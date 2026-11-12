//! Actor metrics drawn from kameo's traces: every message an actor handles
//! runs in an `actor.handle_message` span, and every start and stop of an
//! actor, supervised restarts included, emits an event.

use std::{fmt, time::Instant};

use anyhow::{Context as _, Result};
use sequencer_service_metrics::names::ActorState;
use tracing::{
    Event, Level, Subscriber,
    field::{Field, Visit},
    span,
};
use tracing_subscriber::{
    Layer,
    filter::Targets,
    layer::{Context, SubscriberExt as _},
    registry::LookupSpan,
};

use crate::log_forwarder::LogForwarder;

/// Kameo's span around one message's handler.
const HANDLE_MESSAGE_SPAN: &str = "actor.handle_message";

/// Where kameo emits the events marking an actor's start and stop.
const LIFECYCLE_TARGET: &str = "kameo::actor::spawn";

const STARTED: &str = "actor started";
const STOPPED: &str = "actor stopped";

/// Records how long actors take to handle messages, and when they start and
/// stop.
pub struct ActorMetrics;

/// A message being handled, kept on its span until the span closes.
struct Handling {
    actor_name: String,
    message_name: String,
    since: Instant,
}

/// The fields kameo puts on its spans and events that the metrics need.
#[derive(Default)]
struct Fields {
    actor_name: Option<String>,
    /// The handled message's name on a span; the text on an event.
    message: Option<String>,
    reason: Option<String>,
}

impl<S: Subscriber + for<'lookup> LookupSpan<'lookup>> Layer<S> for ActorMetrics {
    fn on_new_span(&self, attrs: &span::Attributes<'_>, id: &span::Id, ctx: Context<'_, S>) {
        if attrs.metadata().name() != HANDLE_MESSAGE_SPAN {
            return;
        }
        let mut fields = Fields::default();
        attrs.record(&mut fields);
        if let (Some(span), Some(actor_name), Some(message_name)) =
            (ctx.span(id), fields.actor_name, fields.message)
        {
            span.extensions_mut().insert(Handling {
                actor_name,
                message_name,
                since: Instant::now(),
            });
        }
    }

    fn on_close(&self, id: span::Id, ctx: Context<'_, S>) {
        let Some(span) = ctx.span(&id) else {
            return;
        };
        let handling = span.extensions_mut().remove();
        if let Some(Handling {
            actor_name,
            message_name,
            since,
        }) = handling
        {
            sequencer_service_metrics::record_message_handling_time(
                actor_name,
                message_name,
                since.elapsed(),
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
        match fields.message.as_deref() {
            Some(STARTED) => {
                sequencer_service_metrics::record_actor_start_time(
                    actor_name.clone(),
                    std::time::SystemTime::now(),
                );
                sequencer_service_metrics::record_actor_state(actor_name, ActorState::Running);
            }
            Some(STOPPED) => sequencer_service_metrics::record_actor_state(
                actor_name,
                state_after(fields.reason.as_deref().unwrap_or_default()),
            ),
            _ => {}
        }
    }
}

impl Fields {
    fn set(&mut self, field: &Field, value: String) {
        match field.name() {
            "actor.name" | "name" => self.actor_name = Some(value),
            "message" => self.message = Some(value),
            "reason" => self.reason = Some(value),
            _ => {}
        }
    }
}

impl Visit for Fields {
    fn record_str(&mut self, field: &Field, value: &str) {
        self.set(field, value.to_owned());
    }

    fn record_debug(&mut self, field: &Field, value: &dyn fmt::Debug) {
        self.set(field, format!("{value:?}"));
    }
}

/// Installs [`ActorMetrics`] as the global tracing subscriber, next to a
/// [`LogForwarder`] that keeps tracing events in the logs.
///
/// Call it once the `log` logger is set: the forwarder asks it which events to
/// take.
pub fn install() -> Result<()> {
    tracing::subscriber::set_global_default(subscriber())
        .context("Failed to install the actor metrics tracing subscriber")
}

fn subscriber() -> impl Subscriber + Send + Sync {
    tracing_subscriber::registry()
        .with(ActorMetrics.with_filter(Targets::new().with_target("kameo", Level::TRACE)))
        .with(LogForwarder::filtered())
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
    use std::{sync::Mutex, time::Duration};

    use kameo::{
        actor::Spawn as _,
        message::{Context, Message},
    };
    use metrics_exporter_prometheus::PrometheusRecorder;
    use sequencer_service_metrics::names::{
        ACTOR_MESSAGE_HANDLING_TIME, ACTOR_NAME_LABEL, ACTOR_START_TIME, ACTOR_STATE,
        MESSAGE_NAME_LABEL,
    };

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

    fn recorder() -> PrometheusRecorder {
        crate::prometheus_builder("test".to_owned())
            .unwrap()
            .build_recorder()
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

    /// The installed subscriber must not swallow the log lines `tracing`
    /// hands the `log` logger while none is installed, nor change them.
    #[test]
    fn tracing_events_still_reach_the_log_logger() {
        static LOGGED: Mutex<Vec<String>> = Mutex::new(Vec::new());

        struct Capture;

        impl log::Log for Capture {
            fn enabled(&self, metadata: &log::Metadata<'_>) -> bool {
                metadata.level() <= log::Level::Info
            }

            fn log(&self, record: &log::Record<'_>) {
                LOGGED
                    .lock()
                    .unwrap()
                    .push(format!("{} {}", record.target(), record.args()));
            }

            fn flush(&self) {}
        }

        log::set_logger(&Capture).unwrap();
        log::set_max_level(log::LevelFilter::Trace);
        tracing::subscriber::with_default(subscriber(), || {
            tracing::info!(target: "libp2p_swarm", peer = 3, addr = "/ip4/10.0.0.1", "dialing");
            tracing::debug!(target: "libp2p_swarm", "below the logger's level");
        });

        assert_eq!(
            *LOGGED.lock().unwrap(),
            [r#"libp2p_swarm dialing peer=3 addr="/ip4/10.0.0.1""#]
        );
    }
}
