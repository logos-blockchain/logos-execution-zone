//! Actor metrics drawn from kameo's traces: every message an actor handles
//! runs in an `actor.handle_message` span following from the span it was sent
//! in, and every start and stop of an actor, supervised restarts included,
//! emits an event.

use std::{fmt, sync::OnceLock, time::Instant};

use opentelemetry::KeyValue;
use sequencer_service_metrics::{
    instances::{self, Lifecycle},
    names::{ActorState, NO_SENDER},
    traces::{CAUSE_ATTRIBUTE, INSTANCE_ATTRIBUTE, SENDER_ATTRIBUTE, SENDER_INSTANCE_ATTRIBUTE},
};
use tracing::{
    Dispatch, Event, Level, Subscriber,
    dispatcher::WeakDispatch,
    field::{Field, Visit},
    span,
};
use tracing_subscriber::{
    Layer,
    filter::{FilterExt as _, FilterFn, Targets},
    layer::Context,
    registry::{LookupSpan, SpanRef},
};

use crate::traces;

/// Kameo's span around one message's handler.
pub const HANDLE_MESSAGE_SPAN: &str = "actor.handle_message";

/// Kameo's span around an actor's whole run, its `next` included.
pub const LIFECYCLE_SPAN: &str = "actor.lifecycle";

const KAMEO_TARGET: &str = "kameo";

/// Where kameo emits the events marking an actor's start and stop.
const LIFECYCLE_TARGET: &str = "kameo::actor::spawn";

const STARTED: &str = "actor started";
const STOPPED: &str = "actor stopped";

/// Records how long actors take to handle messages and who sent them, and
/// when actors start and stop. While traces are exported, it also puts who
/// sent each message and the trace it was sent from on the message's span.
#[derive(Default)]
pub struct ActorMetrics {
    dispatch: OnceLock<WeakDispatch>,
}

/// The actor a kameo span runs in, kept on the span.
struct ActorSpan {
    name: String,
    id: String,
}

/// What sent the messages a span of ours sends, when it does not run in an
/// actor: what it follows from, e.g. the handler that set it off.
struct FollowsFrom(Sender);

/// What sent a message.
#[derive(Clone)]
struct Sender {
    /// The actor's name, or a span's.
    name: String,
    /// The instance of the actor, if it is named.
    instance: Option<String>,
}

/// The `otel.name` a span of ours names its trace with.
struct OtelName(String);

/// A message being handled, kept on its span until the span closes.
struct Handling {
    message_name: String,
    /// The instance of the actor handling it, if it is named.
    instance: Option<String>,
    /// Set by the first span the handler's span follows from.
    sender: Option<Sender>,
    since: Instant,
    /// When the handler last stopped running. The span can close much later:
    /// each message the handler sent holds it until handled.
    until: Option<Instant>,
}

/// The fields kameo puts on its spans and events that the metrics need.
#[derive(Default)]
struct Fields {
    actor_name: Option<String>,
    actor_id: Option<String>,
    /// The handled message's name on a span; the text on an event.
    message: Option<String>,
    reason: Option<String>,
    otel_name: Option<String>,
}

impl<S: Subscriber + for<'lookup> LookupSpan<'lookup>> Layer<S> for ActorMetrics {
    fn on_register_dispatch(&self, subscriber: &Dispatch) {
        self.dispatch.get_or_init(|| subscriber.downgrade());
    }

    fn on_new_span(&self, attrs: &span::Attributes<'_>, id: &span::Id, ctx: Context<'_, S>) {
        let metadata = attrs.metadata();
        let handles_message = metadata.name() == HANDLE_MESSAGE_SPAN;
        let kameo = metadata.target().starts_with(KAMEO_TARGET);
        if kameo && !(handles_message || metadata.name() == LIFECYCLE_SPAN) {
            return;
        }
        let mut fields = Fields::default();
        attrs.record(&mut fields);
        let Some(span) = ctx.span(id) else {
            return;
        };
        let mut extensions = span.extensions_mut();
        if !kameo {
            if let Some(name) = fields.otel_name {
                extensions.insert(OtelName(name));
            }
            return;
        }
        let (Some(name), Some(actor_id)) = (fields.actor_name, fields.actor_id) else {
            return;
        };
        if handles_message && let Some(message_name) = fields.message {
            extensions.insert(Handling {
                message_name,
                instance: instances::of(&actor_id),
                sender: None,
                since: Instant::now(),
                until: None,
            });
        }
        extensions.insert(ActorSpan { name, id: actor_id });
    }

    /// Kameo has a handler's span follow from the span the message was sent
    /// in, if there was one, and then from the actor's own lifecycle span.
    /// A span of ours follows from what set off its work.
    fn on_follows_from(&self, id: &span::Id, follows: &span::Id, ctx: Context<'_, S>) {
        let (Some(span), Some(cause)) = (ctx.span(id), ctx.span(follows)) else {
            return;
        };
        let lifecycle_of = (cause.name() == LIFECYCLE_SPAN)
            .then(|| {
                cause
                    .extensions()
                    .get::<ActorSpan>()
                    .map(|actor| actor.id.clone())
            })
            .flatten();
        let sender = sender(&cause);

        let (own_lifecycle, unattributed) = {
            let extensions = span.extensions();
            let actor = extensions.get::<ActorSpan>();
            (
                actor.is_some_and(|actor| lifecycle_of.as_ref() == Some(&actor.id)),
                actor.is_none() && extensions.get::<FollowsFrom>().is_none(),
            )
        };
        let mut extensions = span.extensions_mut();
        if let Some(handling) = extensions.get_mut::<Handling>() {
            if handling.sender.is_none() {
                let (sender, trace) = if own_lifecycle {
                    (Sender::none(), None)
                } else {
                    (sender, trace_name(&cause))
                };
                handling.sender = Some(sender.clone());
                let instance = handling.instance.clone();
                drop(extensions);
                self.tag(id, sender, trace, instance);
            }
            return;
        }
        if unattributed {
            extensions.insert(FollowsFrom(sender));
        }
    }

    fn on_exit(&self, id: &span::Id, ctx: Context<'_, S>) {
        if let Some(span) = ctx.span(id)
            && let Some(handling) = span.extensions_mut().get_mut::<Handling>()
        {
            handling.until = Some(Instant::now());
        }
    }

    fn on_close(&self, id: span::Id, ctx: Context<'_, S>) {
        let Some(span) = ctx.span(&id) else {
            return;
        };
        let mut extensions = span.extensions_mut();
        let Some(Handling {
            message_name,
            instance,
            sender,
            since,
            until,
        }) = extensions.remove()
        else {
            return;
        };
        if let Some(actor) = extensions.get_mut::<ActorSpan>() {
            let sender = sender.unwrap_or_else(Sender::none);
            sequencer_service_metrics::record_message_handling_time(
                actor.name.clone(),
                instance,
                message_name,
                sender.name,
                sender.instance,
                until.unwrap_or_else(Instant::now).duration_since(since),
            );
        }
    }

    fn on_event(&self, event: &Event<'_>, _ctx: Context<'_, S>) {
        if event.metadata().target() != LIFECYCLE_TARGET {
            return;
        }
        let mut fields = Fields::default();
        event.record(&mut fields);
        let Some(actor_name) = fields.actor_name else {
            return;
        };
        let lifecycle = match fields.message.as_deref() {
            Some(STARTED) => Lifecycle::Started(std::time::SystemTime::now()),
            Some(STOPPED) => {
                Lifecycle::Stopped(state_after(fields.reason.as_deref().unwrap_or_default()))
            }
            _ => return,
        };
        instances::record_lifecycle(actor_name, fields.actor_id, lifecycle);
    }
}

impl Sender {
    /// The sender of a message sent in no span.
    fn none() -> Self {
        Self {
            name: NO_SENDER.to_owned(),
            instance: None,
        }
    }
}

impl ActorMetrics {
    /// Puts `sender`, the trace the message was sent from and the instance of
    /// the actor handling it on the trace span of the message handled in `id`.
    fn tag(&self, id: &span::Id, sender: Sender, trace: Option<String>, instance: Option<String>) {
        let Some(dispatch) = self.dispatch.get().and_then(WeakDispatch::upgrade) else {
            return;
        };
        let sender_name = traces::type_name(&sender.name).to_owned();
        let cause = trace.unwrap_or_else(|| sender_name.clone());
        let instances = [
            instance.map(|handler| KeyValue::new(INSTANCE_ATTRIBUTE, handler)),
            sender
                .instance
                .map(|sender| KeyValue::new(SENDER_INSTANCE_ATTRIBUTE, sender)),
        ];
        traces::set_attributes(
            &dispatch,
            id,
            [
                KeyValue::new(SENDER_ATTRIBUTE, sender_name),
                KeyValue::new(CAUSE_ATTRIBUTE, cause),
            ]
            .into_iter()
            .chain(instances.into_iter().flatten()),
        );
    }
}

impl Fields {
    /// Where the value of `field` goes, if it is one of these.
    fn slot(&mut self, field: &Field) -> Option<&mut Option<String>> {
        match field.name() {
            "actor.name" | "name" => Some(&mut self.actor_name),
            // `id` on kameo's start and stop events.
            "actor.id" | "id" => Some(&mut self.actor_id),
            "message" => Some(&mut self.message),
            "reason" => Some(&mut self.reason),
            "otel.name" => Some(&mut self.otel_name),
            _ => None,
        }
    }
}

impl Visit for Fields {
    fn record_str(&mut self, field: &Field, value: &str) {
        if let Some(slot) = self.slot(field) {
            *slot = Some(value.to_owned());
        }
    }

    fn record_debug(&mut self, field: &Field, value: &dyn fmt::Debug) {
        if let Some(slot) = self.slot(field) {
            *slot = Some(format!("{value:?}"));
        }
    }
}

/// What sent a message from within `cause`: the actor running it, or the
/// sender of what it follows from; failing both, the outermost span it is in.
fn sender<S: for<'lookup> LookupSpan<'lookup>>(cause: &SpanRef<'_, S>) -> Sender {
    let mut outermost = cause.name();
    for span in cause.scope() {
        let extensions = span.extensions();
        if let Some(actor) = extensions.get::<ActorSpan>() {
            return Sender {
                name: actor.name.clone(),
                instance: instances::of(&actor.id),
            };
        }
        if let Some(FollowsFrom(sender)) = extensions.get() {
            return sender.clone();
        }
        outermost = span.name();
    }
    Sender {
        name: outermost.to_owned(),
        instance: None,
    }
}

/// The name of the trace a message sent from within `cause` comes from, as
/// [`traces`] exports it: the handled message `cause` is in, e.g.
/// `ExecutorActor.ProduceBlock`, or else its outermost span short of a
/// long-lived one, by `otel.name` if it has one. None when sent from
/// directly within a long-lived span, e.g. an actor's own loop.
fn trace_name<S: for<'lookup> LookupSpan<'lookup>>(cause: &SpanRef<'_, S>) -> Option<String> {
    let mut outermost = None;
    for span in cause.scope() {
        let extensions = span.extensions();
        if let (Some(actor), Some(handling)) =
            (extensions.get::<ActorSpan>(), extensions.get::<Handling>())
        {
            return Some(traces::handler_name(&actor.name, &handling.message_name));
        }
        if traces::is_long_lived(span.metadata()) {
            break;
        }
        outermost = Some(
            extensions
                .get::<OtelName>()
                .map_or_else(|| span.name().to_owned(), |OtelName(name)| name.clone()),
        );
    }
    outermost
}

/// [`ActorMetrics`], taking every kameo span and event, and every other span
/// at `info` or above, to tell which one sent a message. Whatever `RUST_LOG`
/// says, so the senders it finds do not change with the log level.
pub fn layer<S: Subscriber + for<'lookup> LookupSpan<'lookup>>() -> impl Layer<S> {
    let kameo = Targets::new().with_target(KAMEO_TARGET, Level::TRACE);
    let spans = FilterFn::new(|metadata| metadata.is_span() && *metadata.level() <= Level::INFO);
    ActorMetrics::default().with_filter(kameo.or(spans))
}

/// The state an actor stopped for `reason`, kameo's `ActorStopReason` in its
/// `Debug` form, leaves it in.
fn state_after(reason: &str) -> ActorState {
    let variant = reason
        .split(|char: char| !char.is_alphanumeric())
        .next()
        .unwrap_or_default();
    match variant {
        "SupervisorRestart" => ActorState::Restarting,
        "Panicked" | "LinkDied" => ActorState::Failed,
        _ => ActorState::Stopped,
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use kameo::{
        actor::{ActorRef, Spawn as _},
        message::{Context, Message},
        supervision::RestartPolicy,
    };
    use metrics_exporter_prometheus::PrometheusRecorder;
    use sequencer_service_metrics::names::{
        ACTOR_INSTANCE_LABEL, ACTOR_MESSAGE_HANDLING_TIME, ACTOR_NAME_LABEL, ACTOR_START_TIME,
        ACTOR_STATE, MESSAGE_NAME_LABEL, SENDER_INSTANCE_LABEL, SENDER_LABEL,
    };
    use sharding_pool_actor::{RestartConfig, ShardingKey, ShardingPoolActor};
    use tracing::Instrument as _;
    use tracing_subscriber::layer::SubscriberExt as _;

    use super::*;

    #[derive(kameo::Actor, Clone)]
    struct Worker;

    /// Keeps the worker busy for the given time.
    struct Work(Duration);

    impl Message<Work> for Worker {
        type Reply = ();

        async fn handle(&mut self, Work(duration): Work, _: &mut Context<Self, Self::Reply>) {
            tokio::time::sleep(duration).await;
        }
    }

    struct Crash;

    impl Message<Crash> for Worker {
        type Reply = ();

        async fn handle(&mut self, _: Crash, _: &mut Context<Self, Self::Reply>) {
            panic!("crash requested");
        }
    }

    #[derive(kameo::Actor)]
    struct Supervisor;

    /// Hands work on to a worker.
    #[derive(kameo::Actor)]
    struct Relay(ActorRef<Worker>);

    struct Forward;

    impl Message<Forward> for Relay {
        type Reply = ();

        async fn handle(&mut self, _: Forward, _: &mut Context<Self, Self::Reply>) {
            self.0.ask(Work(Duration::ZERO)).await.unwrap();
        }
    }

    /// Hands work on to a worker without waiting for it.
    struct Pass(Duration);

    impl Message<Pass> for Relay {
        type Reply = ();

        async fn handle(&mut self, Pass(duration): Pass, _: &mut Context<Self, Self::Reply>) {
            self.0.tell(Work(duration)).await.unwrap();
        }
    }

    /// One of several, its instance named, handing work on to a worker.
    #[derive(kameo::Actor)]
    struct Named(ActorRef<Worker>);

    struct Delegate;

    impl Message<Delegate> for Named {
        type Reply = ();

        async fn handle(&mut self, _: Delegate, _: &mut Context<Self, Self::Reply>) {
            self.0.ask(Work(Duration::ZERO)).await.unwrap();
        }
    }

    /// Run by a pool, which labels it with its instance.
    #[derive(kameo::Actor)]
    struct Pooled;

    /// For the pooled actor of the given key.
    #[derive(Clone)]
    struct Ping(u32);

    impl ShardingKey for Ping {
        type Key = u32;

        fn sharding_key(&self) -> Self::Key {
            self.0
        }
    }

    impl Message<Ping> for Pooled {
        type Reply = ();

        async fn handle(&mut self, _: Ping, _: &mut Context<Self, Self::Reply>) {}
    }

    fn subscriber() -> impl Subscriber + Send + Sync {
        tracing_subscriber::registry().with(layer())
    }

    fn recorder() -> PrometheusRecorder {
        crate::prometheus_builder("test".to_owned())
            .unwrap()
            .build_recorder()
    }

    /// The instances of the pooled actor's `metric` series, as `recorder` renders
    /// them, sorted; `None` for a series with no instance.
    fn pooled_instances(recorder: &PrometheusRecorder, metric: &str) -> Vec<Option<String>> {
        let series = format!("{metric}{{");
        let actor_name = format!(
            r#"{ACTOR_NAME_LABEL}="{}""#,
            <Pooled as kameo::Actor>::name()
        );
        let instance = format!(r#"{ACTOR_INSTANCE_LABEL}=""#);
        let mut instances: Vec<_> = recorder
            .handle()
            .render()
            .lines()
            .filter(|line| line.starts_with(&series) && line.contains(&actor_name))
            .map(|line| {
                let (_, rest) = line.split_once(&instance)?;
                Some(rest.split('"').next()?.to_owned())
            })
            .collect();
        instances.sort();
        instances
    }

    /// The worker's `metric` value, as `recorder` renders it.
    fn worker_value(recorder: &PrometheusRecorder, metric: &str) -> Option<f64> {
        let series = format!("{metric}{{");
        let actor_name = format!(
            r#"{ACTOR_NAME_LABEL}="{}""#,
            <Worker as kameo::Actor>::name()
        );
        recorder
            .handle()
            .render()
            .lines()
            .find(|line| line.starts_with(&series) && line.contains(&actor_name))
            .and_then(|line| line.rsplit(' ').next()?.parse().ok())
    }

    /// The seconds `A` took to handle all its `M` messages, whoever sent them,
    /// as `recorder` renders them.
    fn handling_time<A: Message<M>, M: Send + 'static>(recorder: &PrometheusRecorder) -> f64 {
        let sum = format!("{ACTOR_MESSAGE_HANDLING_TIME}_sum{{");
        let actor_name = format!(r#"{ACTOR_NAME_LABEL}="{}""#, <A as kameo::Actor>::name());
        let message_name = format!(r#"{MESSAGE_NAME_LABEL}="{}""#, <A as Message<M>>::name());
        recorder
            .handle()
            .render()
            .lines()
            .filter(|line| {
                line.starts_with(&sum) && line.contains(&actor_name) && line.contains(&message_name)
            })
            .filter_map(|line| line.rsplit(' ').next()?.parse::<f64>().ok())
            .sum()
    }

    fn state(recorder: &PrometheusRecorder) -> Option<f64> {
        worker_value(recorder, ACTOR_STATE)
    }

    fn value_of(state: ActorState) -> f64 {
        f64::from(u8::from(state))
    }

    #[tokio::test]
    async fn times_handlers_and_follows_a_graceful_stop() {
        let recorder = recorder();
        let _recorder = metrics::set_default_local_recorder(&recorder);
        let _subscriber = tracing::subscriber::set_default(subscriber());

        let worker = Worker::spawn(Worker);
        worker.ask(Work(Duration::from_millis(20))).await.unwrap();

        assert_eq!(state(&recorder), Some(value_of(ActorState::Running)));
        let handling_time = format!("{ACTOR_MESSAGE_HANDLING_TIME}_");
        assert_eq!(
            worker_value(&recorder, &format!("{handling_time}count")),
            Some(1.0)
        );
        let handled_for = worker_value(&recorder, &format!("{handling_time}sum")).unwrap();
        assert!(handled_for >= 0.02, "handled for {handled_for}s");
        let rendered = recorder.handle().render();
        let message_name = format!(
            r#"{MESSAGE_NAME_LABEL}="{}""#,
            <Worker as Message<Work>>::name()
        );
        assert!(
            rendered
                .lines()
                .any(|line| line.starts_with(&handling_time) && line.contains(&message_name)),
            "no {message_name} in\n{rendered}"
        );

        worker.stop_gracefully().await.unwrap();
        worker.wait_for_shutdown().await;
        assert_eq!(state(&recorder), Some(value_of(ActorState::Stopped)));
    }

    #[tokio::test]
    async fn a_panic_leaves_the_actor_failed() {
        let recorder = recorder();
        let _recorder = metrics::set_default_local_recorder(&recorder);
        let _subscriber = tracing::subscriber::set_default(subscriber());

        let worker = Worker::spawn(Worker);
        worker.tell(Crash).await.unwrap();
        worker.wait_for_shutdown().await;

        assert_eq!(state(&recorder), Some(value_of(ActorState::Failed)));
    }

    #[tokio::test]
    async fn a_supervised_restart_runs_again_with_a_later_start_time() {
        let recorder = recorder();
        let _recorder = metrics::set_default_local_recorder(&recorder);
        let _subscriber = tracing::subscriber::set_default(subscriber());

        let supervisor = Supervisor::spawn(Supervisor);
        let worker = Worker::supervise(&supervisor, Worker).spawn().await;
        worker.ask(Work(Duration::ZERO)).await.unwrap();
        let first_start = worker_value(&recorder, ACTOR_START_TIME).unwrap();

        tokio::time::sleep(Duration::from_millis(10)).await;
        worker.tell(Crash).await.unwrap();
        // Answered only once the restarted worker runs.
        worker.ask(Work(Duration::ZERO)).await.unwrap();

        assert_eq!(state(&recorder), Some(value_of(ActorState::Running)));
        let restart = worker_value(&recorder, ACTOR_START_TIME).unwrap();
        assert!(
            restart > first_start,
            "restarted at {restart}, first started at {first_start}"
        );
    }

    #[tokio::test]
    async fn times_a_handler_without_the_handlers_of_what_it_told() {
        let recorder = recorder();
        let _recorder = metrics::set_default_local_recorder(&recorder);
        let _subscriber = tracing::subscriber::set_default(subscriber());

        let worker = Worker::spawn(Worker);
        let relay = Relay::spawn(Relay(worker.clone()));
        relay.ask(Pass(Duration::from_millis(100))).await.unwrap();
        // Answered only once the work passed on is done.
        worker.ask(Work(Duration::ZERO)).await.unwrap();

        let relayed_for = handling_time::<Relay, Pass>(&recorder);
        assert!(relayed_for < 0.05, "relayed for {relayed_for}s");
        let worked_for = handling_time::<Worker, Work>(&recorder);
        assert!(worked_for >= 0.1, "worked for {worked_for}s");
    }

    #[tokio::test]
    async fn labels_a_pools_actors_with_their_instance() {
        let recorder = recorder();
        let _recorder = metrics::set_default_local_recorder(&recorder);
        let _subscriber = tracing::subscriber::set_default(subscriber());

        let expected = instances::expect(<Pooled as kameo::Actor>::name());
        let pool = ShardingPoolActor::spawn(
            ShardingPoolActor::<Pooled, u32>::new(
                RestartConfig {
                    policy: RestartPolicy::Never,
                    limit: 0,
                    within: Duration::ZERO,
                },
                |_key| Pooled,
            )
            .with_on_worker_spawned(move |key, worker| expected.name(worker.id(), key)),
        );
        pool.ask(Ping(1)).await.unwrap();
        pool.ask(Ping(2)).await.unwrap();

        let both = [Some("1".to_owned()), Some("2".to_owned())];
        for metric in [
            format!("{ACTOR_MESSAGE_HANDLING_TIME}_count"),
            ACTOR_STATE.to_owned(),
            ACTOR_START_TIME.to_owned(),
        ] {
            assert_eq!(pooled_instances(&recorder, &metric), both, "{metric}");
        }
    }

    #[tokio::test]
    async fn labels_a_message_with_the_instance_of_its_sender() {
        let recorder = recorder();
        let _recorder = metrics::set_default_local_recorder(&recorder);
        let _subscriber = tracing::subscriber::set_default(subscriber());

        let expected = instances::expect(<Named as kameo::Actor>::name());
        let named = Named::spawn(Named(Worker::spawn(Worker)));
        expected.name(named.id(), "named-1");
        named.ask(Delegate).await.unwrap();

        let count = format!("{ACTOR_MESSAGE_HANDLING_TIME}_count{{");
        let sender = format!(r#"{SENDER_INSTANCE_LABEL}="named-1""#);
        let rendered = recorder.handle().render();
        assert!(
            rendered.lines().any(|line| line.starts_with(&count)
                && line.contains("Worker\"")
                && line.contains(&sender)),
            "no Worker message from `named-1` in\n{rendered}"
        );
    }

    #[tokio::test]
    async fn labels_each_message_with_its_sender() {
        let recorder = recorder();
        let _recorder = metrics::set_default_local_recorder(&recorder);
        let _subscriber = tracing::subscriber::set_default(subscriber());

        let worker = Worker::spawn(Worker);
        let relay = Relay::spawn(Relay(worker.clone()));
        relay.ask(Forward).await.unwrap();
        worker
            .ask(Work(Duration::ZERO))
            .into_future()
            .instrument(tracing::info_span!("rpc"))
            .await
            .unwrap();
        worker
            .ask(Work(Duration::ZERO))
            .into_future()
            .instrument(tracing::debug_span!("detail"))
            .await
            .unwrap();
        worker.ask(Work(Duration::ZERO)).await.unwrap();

        let count = format!("{ACTOR_MESSAGE_HANDLING_TIME}_count{{");
        let rendered = recorder.handle().render();
        let senders: Vec<_> = rendered
            .lines()
            .filter(|line| line.starts_with(&count) && line.contains("Worker\""))
            .filter_map(|line| {
                let (_, rest) = line.split_once(&format!(r#"{SENDER_LABEL}=""#))?;
                rest.split('"').next()
            })
            .collect();
        let relay_name = <Relay as kameo::Actor>::name();
        for sender in [relay_name, "rpc", NO_SENDER] {
            assert!(senders.contains(&sender), "no {sender} in {senders:?}");
        }
        assert!(!senders.contains(&"detail"), "a debug span in {senders:?}");
    }

    #[test]
    fn stop_reasons_map_to_states() {
        for (reason, state) in [
            ("Normal", ActorState::Stopped),
            ("Killed", ActorState::Stopped),
            ("SupervisorRestart", ActorState::Restarting),
            (r#"Panicked { err: "boom" }"#, ActorState::Failed),
            (
                "LinkDied { id: ActorId(3), reason: Normal }",
                ActorState::Failed,
            ),
        ] {
            assert_eq!(state_after(reason), state, "{reason}");
        }
    }
}
