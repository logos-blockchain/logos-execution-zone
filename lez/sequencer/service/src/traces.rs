//! Exports spans as OpenTelemetry traces over OTLP/HTTP, to the collector
//! `OTEL_EXPORTER_OTLP_TRACES_ENDPOINT` or `OTEL_EXPORTER_OTLP_ENDPOINT` names.
//! With neither set, nothing is exported. The other `OTEL_*` variables apply,
//! e.g. `OTEL_RESOURCE_ATTRIBUTES` or `OTEL_TRACES_SAMPLER`.
//!
//! Every message an actor handles is the root of a trace of its own, named
//! after the actor and the message, e.g. `ExecutorActor.ProduceBlock`, and
//! linked to the span the message was sent in. Its attributes name who sent
//! it and the trace it was sent from, so the messages an actor sent, or the
//! ones a trace set off, can be searched for. Spans lasting as long as an
//! actor, a connection or a watcher are left out, so what runs in them starts
//! a trace of its own rather than joining one that never ends.

use std::{
    sync::{
        Arc, OnceLock,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};

use anyhow::{Context as _, Result};
use opentelemetry::{
    KeyValue,
    trace::{TraceContextExt as _, TracerProvider as _},
};
use opentelemetry_sdk::{
    Resource,
    error::OTelSdkResult,
    trace::{BatchSpanProcessor, SdkTracerProvider, SpanData, SpanExporter},
};
use sequencer_core::Ed25519PublicKey;
use sequencer_service_metrics::traces::{ACTOR_ATTRIBUTE, SEQUENCER_ATTRIBUTE};
use tracing::{Dispatch, Metadata, Subscriber, info, span, warn};
use tracing_subscriber::{
    EnvFilter, Layer,
    filter::{FilterExt as _, FilterFn},
    layer::Filter,
    registry::LookupSpan,
};

use crate::actor_metrics::{HANDLE_MESSAGE_SPAN, LIFECYCLE_SPAN};

/// The service name traces carry unless `OTEL_SERVICE_NAME` or
/// `OTEL_RESOURCE_ATTRIBUTES` give another.
pub const SERVICE_NAME: &str = "sequencer";

const ENDPOINT_VARS: [&str; 2] = [
    "OTEL_EXPORTER_OTLP_TRACES_ENDPOINT",
    "OTEL_EXPORTER_OTLP_ENDPOINT",
];

/// Spans as long-lived as an actor, an RPC connection or a cross-zone watcher,
/// by target prefix and name. Exported, each would be one trace taking in all
/// that runs in it until it ends.
const LONG_LIVED_SPANS: [(&str, &str); 3] = [
    ("kameo", LIFECYCLE_SPAN),
    ("jsonrpsee_server", "connection"),
    (
        "sequencer_core",
        sequencer_core::cross_zone_watcher::WATCHER_SPAN,
    ),
];

/// The trace exporter. Dropping it sends the spans still queued.
pub struct Traces {
    provider: SdkTracerProvider,
    sequencer: Arc<OnceLock<String>>,
}

impl Traces {
    /// The exporter the environment sets up, if it names a collector.
    pub fn from_env() -> Result<Option<Self>> {
        let configured = ENDPOINT_VARS
            .iter()
            .any(|var| std::env::var_os(var).is_some_and(|value| !value.is_empty()));
        if !configured {
            return Ok(None);
        }
        let exporter = opentelemetry_otlp::SpanExporter::builder()
            .with_http()
            .build()
            .context("Failed to build the OTLP trace exporter")?;
        Ok(Some(Self::new(exporter, resource())))
    }

    fn new(exporter: impl SpanExporter + 'static, resource: Resource) -> Self {
        let sequencer = Arc::new(OnceLock::new());
        let exporter = Exporter {
            inner: exporter,
            failing: AtomicBool::new(false),
            sequencer: Arc::clone(&sequencer),
        };
        let provider = SdkTracerProvider::builder()
            .with_resource(resource)
            .with_span_processor(BatchSpanProcessor::builder(exporter).build())
            .build();
        Self {
            provider,
            sequencer,
        }
    }

    /// Puts `public_key`, in hex, in [`SEQUENCER_ATTRIBUTE`] of every span
    /// exported from now on. Only the first key set counts.
    pub fn set_sequencer(&self, public_key: &Ed25519PublicKey) {
        self.sequencer
            .get_or_init(|| hex::encode(public_key.as_bytes()));
    }

    /// The layer turning spans into traces: the spans and events `log` lets
    /// through, and every message an actor handles whatever `log` says.
    pub fn layer<S: Subscriber + for<'lookup> LookupSpan<'lookup>>(
        &self,
        log: EnvFilter,
    ) -> impl Layer<S> {
        tracing_opentelemetry::layer()
            .with_tracer(self.provider.tracer(env!("CARGO_PKG_NAME")))
            // An actor's handler moves between threads at every await.
            .with_threads(false)
            .with_filter(filter(log))
    }
}

impl Drop for Traces {
    fn drop(&mut self) {
        if let Err(err) = self.provider.shutdown() {
            warn!(error = %err, "Failed to send the last traces");
        }
    }
}

/// Names actor spans, puts the sequencer on every span, and says once that
/// exports fail and once that they work again, where the batch processor would
/// log every failed batch.
#[derive(Debug)]
struct Exporter<E> {
    inner: E,
    failing: AtomicBool,
    sequencer: Arc<OnceLock<String>>,
}

impl<E: SpanExporter> SpanExporter for Exporter<E> {
    async fn export(&self, mut batch: Vec<SpanData>) -> OTelSdkResult {
        batch.iter_mut().for_each(name_actor_span);
        if let Some(sequencer) = self.sequencer.get() {
            let attribute = KeyValue::new(SEQUENCER_ATTRIBUTE, sequencer.clone());
            for span in &mut batch {
                span.attributes.push(attribute.clone());
            }
        }
        match self.inner.export(batch).await {
            Ok(()) => {
                if self.failing.swap(false, Ordering::Relaxed) {
                    info!("Exporting traces again");
                }
            }
            Err(err) => {
                if !self.failing.swap(true, Ordering::Relaxed) {
                    warn!(error = %err, "Failed to export traces, dropping them until it succeeds");
                }
            }
        }
        Ok(())
    }

    fn shutdown_with_timeout(&self, timeout: Duration) -> OTelSdkResult {
        self.inner.shutdown_with_timeout(timeout)
    }

    fn force_flush(&self) -> OTelSdkResult {
        self.inner.force_flush()
    }

    fn set_resource(&mut self, resource: &Resource) {
        self.inner.set_resource(resource);
    }
}

fn resource() -> Resource {
    let named = std::env::var_os("OTEL_SERVICE_NAME").is_some()
        || std::env::var("OTEL_RESOURCE_ATTRIBUTES")
            .is_ok_and(|attributes| attributes.contains("service.name="));
    let resource = Resource::builder();
    if named {
        resource.build()
    } else {
        resource.with_service_name(SERVICE_NAME).build()
    }
}

/// `log`'s spans and events, and kameo's handler spans, without the
/// [`LONG_LIVED_SPANS`] or the exporter's own events.
fn filter<S: Subscriber + for<'lookup> LookupSpan<'lookup>>(log: EnvFilter) -> impl Filter<S> {
    let handler = FilterFn::new(|metadata| {
        metadata.is_span()
            && metadata.name() == HANDLE_MESSAGE_SPAN
            && metadata.target().starts_with("kameo")
    });
    let exported = FilterFn::new(|metadata| {
        !is_long_lived(metadata) && !metadata.target().starts_with("opentelemetry")
    });
    log.or(handler).and(exported)
}

/// Whether `metadata` is of one of the [`LONG_LIVED_SPANS`], left out of
/// traces.
pub fn is_long_lived(metadata: &Metadata<'_>) -> bool {
    LONG_LIVED_SPANS.iter().any(|&(target, name)| {
        metadata.is_span() && metadata.name() == name && metadata.target().starts_with(target)
    })
}

/// The name of the trace a handled message roots: `actor` and `message` by
/// type name, e.g. `ExecutorActor.ProduceBlock`.
pub fn handler_name(actor: &str, message: &str) -> String {
    format!("{}.{}", type_name(actor), type_name(message))
}

/// Puts `attributes` on the trace span of `id`, if `dispatch` exports traces.
pub fn set_attributes(
    dispatch: &Dispatch,
    id: &span::Id,
    attributes: impl IntoIterator<Item = KeyValue>,
) {
    if let Some(context) = tracing_opentelemetry::get_otel_context(id, dispatch) {
        let span = context.span();
        for attribute in attributes {
            span.set_attribute(attribute);
        }
    }
}

/// Names a span kameo opened for a handled message after the actor and the
/// message, e.g. `ExecutorActor.ProduceBlock`, and puts the actor in
/// [`ACTOR_ATTRIBUTE`].
fn name_actor_span(span: &mut SpanData) {
    if span.name != HANDLE_MESSAGE_SPAN {
        return;
    }
    let value_of = |key: &str| {
        span.attributes
            .iter()
            .find(|attribute| attribute.key.as_str() == key)
            .map(|attribute| attribute.value.as_str().into_owned())
    };
    let (Some(actor), Some(message)) = (value_of("actor.name"), value_of("message")) else {
        return;
    };
    span.name = handler_name(&actor, &message).into();
    span.attributes
        .push(KeyValue::new(ACTOR_ATTRIBUTE, type_name(&actor).to_owned()));
}

/// `module::Type<Arguments>` without its module path and arguments: `Type`.
pub fn type_name(full: &str) -> &str {
    let path = full.split('<').next().unwrap_or(full);
    path.rsplit("::").next().unwrap_or(path)
}

#[cfg(test)]
mod tests {
    use kameo::{
        actor::{ActorRef, Spawn as _},
        message::{Context, Message},
    };
    use opentelemetry::trace::SpanId;
    use opentelemetry_sdk::trace::InMemorySpanExporter;
    use sequencer_bedrock_actor::protocol::Ed25519Key;
    use sequencer_service_metrics::{
        instances,
        names::NO_SENDER,
        traces::{
            CAUSE_ATTRIBUTE, INSTANCE_ATTRIBUTE, SENDER_ATTRIBUTE, SENDER_INSTANCE_ATTRIBUTE,
        },
    };
    use tracing::Instrument as _;
    use tracing_subscriber::layer::SubscriberExt as _;

    use super::*;

    #[derive(kameo::Actor)]
    struct Worker;

    struct Work;

    impl Message<Work> for Worker {
        type Reply = ();

        async fn handle(&mut self, Work: Work, _: &mut Context<Self, Self::Reply>) {}
    }

    #[derive(kameo::Actor)]
    struct Relay(ActorRef<Worker>);

    struct Forward;

    impl Message<Forward> for Relay {
        type Reply = ();

        async fn handle(&mut self, Forward: Forward, _: &mut Context<Self, Self::Reply>) {
            self.0
                .ask(Work)
                .into_future()
                .instrument(tracing::info_span!("nested"))
                .await
                .unwrap();
        }
    }

    /// One of several, its instance named.
    #[derive(kameo::Actor)]
    struct Pinged;

    struct Ping;

    impl Message<Ping> for Pinged {
        type Reply = ();

        async fn handle(&mut self, Ping: Ping, _: &mut Context<Self, Self::Reply>) {}
    }

    /// One of several, its instance named, pinging another.
    #[derive(kameo::Actor)]
    struct Pinger(ActorRef<Pinged>);

    struct Start;

    impl Message<Start> for Pinger {
        type Reply = ();

        async fn handle(&mut self, Start: Start, _: &mut Context<Self, Self::Reply>) {
            self.0.ask(Ping).await.unwrap();
        }
    }

    /// Opens a span while starting, in kameo's span for its whole run.
    struct Starter;

    impl kameo::Actor for Starter {
        type Args = Self;
        type Error = kameo::error::Infallible;

        async fn on_start(args: Self, _: ActorRef<Self>) -> Result<Self, Self::Error> {
            tracing::info_span!("startup").in_scope(|| {});
            Ok(args)
        }
    }

    fn exported(spans: &[SpanData], name: &str) -> SpanData {
        spans
            .iter()
            .find(|span| span.name == name)
            .unwrap_or_else(|| panic!("no {name} span in {:?}", names(spans)))
            .clone()
    }

    fn names(spans: &[SpanData]) -> Vec<&str> {
        spans.iter().map(|span| span.name.as_ref()).collect()
    }

    fn attribute(span: &SpanData, key: &str) -> Option<String> {
        span.attributes
            .iter()
            .find(|attribute| attribute.key.as_str() == key)
            .map(|attribute| attribute.value.to_string())
    }

    fn links_to(span: &SpanData, cause: &SpanData) -> bool {
        span.links
            .iter()
            .any(|link| link.span_context.span_id() == cause.span_context.span_id())
    }

    #[tokio::test]
    async fn each_handled_message_roots_a_trace_linked_to_its_sender() {
        let exporter = InMemorySpanExporter::default();
        let traces = Traces::new(exporter.clone(), resource());
        let subscriber = tracing_subscriber::registry()
            .with(crate::actor_metrics::layer())
            .with(traces.layer(EnvFilter::new("info")));
        let _subscriber = tracing::subscriber::set_default(subscriber);

        let public_key = Ed25519Key::from_bytes(&[7; 32]).public_key();
        traces.set_sequencer(&public_key);
        let worker = Worker::spawn(Worker);
        let relay = Relay::spawn(Relay(worker.clone()));
        relay
            .ask(Forward)
            .into_future()
            .instrument(tracing::info_span!("rpc"))
            .await
            .unwrap();
        worker.ask(Work).await.unwrap();
        let starter = Starter::spawn(Starter);
        starter.wait_for_startup().await;
        relay.stop_gracefully().await.unwrap();
        relay.wait_for_shutdown().await;
        traces.provider.force_flush().unwrap();

        let spans = exporter.get_finished_spans().unwrap();
        let rpc = exported(&spans, "rpc");
        let forward = exported(&spans, "Relay.Forward");
        let nested = exported(&spans, "nested");
        let (work, unsent): (Vec<_>, Vec<_>) = spans
            .iter()
            .filter(|span| span.name == "Worker.Work")
            .partition(|span| !span.links.is_empty());
        let work = work.first().expect("a Worker.Work the relay sent");
        let unsent = unsent.first().expect("a Worker.Work sent outside any span");
        for (span, cause) in [(&forward, &rpc), (work, &nested)] {
            assert_eq!(
                span.parent_span_id,
                SpanId::INVALID,
                "{} has a parent",
                span.name
            );
            assert!(
                links_to(span, cause),
                "{} is not linked to {}",
                span.name,
                cause.name
            );
        }
        assert!(
            work.attributes
                .contains(&KeyValue::new(ACTOR_ATTRIBUTE, "Worker")),
            "{:?}",
            work.attributes
        );
        for (span, sender, cause) in [(&forward, "rpc", "rpc"), (work, "Relay", "Relay.Forward")] {
            assert_eq!(attribute(span, SENDER_ATTRIBUTE).as_deref(), Some(sender));
            assert_eq!(attribute(span, CAUSE_ATTRIBUTE).as_deref(), Some(cause));
        }
        for key in [SENDER_ATTRIBUTE, CAUSE_ATTRIBUTE] {
            assert_eq!(attribute(unsent, key).as_deref(), Some(NO_SENDER));
        }
        assert!(
            spans.iter().all(|span| attribute(span, SEQUENCER_ATTRIBUTE)
                == Some(hex::encode(public_key.as_bytes()))),
            "a span without the sequencer"
        );
        assert_eq!(exported(&spans, "startup").parent_span_id, SpanId::INVALID);
        assert!(
            !names(&spans).contains(&LIFECYCLE_SPAN),
            "{:?}",
            names(&spans)
        );
    }

    #[tokio::test]
    async fn a_message_carries_the_instances_of_its_handler_and_sender() {
        let exporter = InMemorySpanExporter::default();
        let traces = Traces::new(exporter.clone(), resource());
        let subscriber = tracing_subscriber::registry()
            .with(crate::actor_metrics::layer())
            .with(traces.layer(EnvFilter::new("info")));
        let _subscriber = tracing::subscriber::set_default(subscriber);

        let pinged_instances = instances::expect(<Pinged as kameo::Actor>::name());
        let pinger_instances = instances::expect(<Pinger as kameo::Actor>::name());
        let pinged = Pinged::spawn(Pinged);
        pinged_instances.name(pinged.id(), "pinged-1");
        let pinger = Pinger::spawn(Pinger(pinged));
        pinger_instances.name(pinger.id(), "pinger-1");
        pinger.ask(Start).await.unwrap();
        traces.provider.force_flush().unwrap();

        let spans = exporter.get_finished_spans().unwrap();
        let ping = exported(&spans, "Pinged.Ping");
        assert_eq!(
            attribute(&ping, INSTANCE_ATTRIBUTE).as_deref(),
            Some("pinged-1")
        );
        assert_eq!(
            attribute(&ping, SENDER_INSTANCE_ATTRIBUTE).as_deref(),
            Some("pinger-1")
        );
        let start = exported(&spans, "Pinger.Start");
        assert_eq!(
            attribute(&start, INSTANCE_ATTRIBUTE).as_deref(),
            Some("pinger-1")
        );
        assert_eq!(attribute(&start, SENDER_INSTANCE_ATTRIBUTE), None);
    }

    #[test]
    fn type_names_drop_the_module_path_and_arguments() {
        for (full, short) in [
            (
                "sequencer_storage_actor::actor::StorageActor",
                "StorageActor",
            ),
            ("kameo_actors::broker::Broker<a::ChannelEvent>", "Broker"),
            (
                "kameo_actors::broker::Publish<a::b::ChannelEvent>",
                "Publish",
            ),
            ("Worker", "Worker"),
        ] {
            assert_eq!(type_name(full), short);
        }
    }
}
