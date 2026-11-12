//! The instance of every actor that runs as one of several of its type.
//!
//! Whatever spawns such an actor names its instance once it has spawned it, by
//! which time the actor may have started. So the starts and stops of these
//! actors wait for their instance, and are recorded once it is named.
//!
//! [`ACTOR_INSTANCE_LABEL`]: crate::names::ACTOR_INSTANCE_LABEL

use std::{
    collections::{HashMap, HashSet},
    fmt::Display,
    sync::{LazyLock, Mutex, MutexGuard, PoisonError},
    time::SystemTime,
};

use crate::{names::ActorState, record_actor_start_time, record_actor_state};

static INSTANCES: LazyLock<Mutex<Instances>> = LazyLock::new(Mutex::default);

#[derive(Default)]
struct Instances {
    /// Names of the actors whose instances are named.
    expected: HashSet<String>,
    /// The instance of each of their actors, by actor id. Kept after the actor
    /// stops, as a supervisor may start it again under the same id.
    by_actor: HashMap<String, String>,
    /// The starts and stops of their actors whose instance is not named yet,
    /// by actor id.
    waiting: HashMap<String, Vec<Lifecycle>>,
}

/// The actors of one type, whose instances it names. From [`expect`].
#[must_use = "Only it names the instances these actors' starts and stops wait for"]
pub struct ExpectedInstances {
    actor_name: String,
}

/// A start or a stop of an actor.
#[derive(Clone, Copy, Debug)]
pub enum Lifecycle {
    Started(SystemTime),
    /// Stopped, leaving it in this state.
    Stopped(ActorState),
}

impl ExpectedInstances {
    /// Names the instance of the actor `actor_id`, e.g. by the key a pool runs
    /// it for, and records the starts and stops it had before.
    pub fn name(&self, actor_id: impl Display, instance: impl Display) {
        let actor_id = actor_id.to_string();
        let instance = instance.to_string();
        let waiting = {
            let mut instances = instances();
            let waiting = instances.waiting.remove(&actor_id).unwrap_or_default();
            instances.by_actor.insert(actor_id, instance.clone());
            waiting
        };
        for lifecycle in waiting {
            record(self.actor_name.clone(), Some(instance.clone()), lifecycle);
        }
    }
}

/// Says each actor named `actor_name` will have its instance named, by what
/// it returns. Call it before any of them starts.
pub fn expect(actor_name: &str) -> ExpectedInstances {
    instances().expected.insert(actor_name.to_owned());
    ExpectedInstances {
        actor_name: actor_name.to_owned(),
    }
}

/// The instance of the actor `actor_id`, if it is named.
#[must_use]
pub fn of(actor_id: &str) -> Option<String> {
    instances().by_actor.get(actor_id).cloned()
}

/// Records a start or stop of the actor `actor_name`, under its instance if it
/// has one. One whose instance is expected but not named yet waits for it.
pub fn record_lifecycle(actor_name: String, actor_id: Option<String>, lifecycle: Lifecycle) {
    let instance = {
        let mut instances = instances();
        match actor_id {
            Some(actor_id) if instances.expected.contains(&actor_name) => {
                if let Some(instance) = instances.by_actor.get(&actor_id) {
                    Some(instance.clone())
                } else {
                    instances
                        .waiting
                        .entry(actor_id)
                        .or_default()
                        .push(lifecycle);
                    return;
                }
            }
            _ => None,
        }
    };
    record(actor_name, instance, lifecycle);
}

fn record(actor_name: String, instance: Option<String>, lifecycle: Lifecycle) {
    match lifecycle {
        Lifecycle::Started(at) => {
            record_actor_start_time(actor_name.clone(), instance.clone(), at);
            record_actor_state(actor_name, instance, ActorState::Running);
        }
        Lifecycle::Stopped(state) => record_actor_state(actor_name, instance, state),
    }
}

fn instances() -> MutexGuard<'static, Instances> {
    INSTANCES.lock().unwrap_or_else(PoisonError::into_inner)
}

#[cfg(test)]
mod tests {
    use metrics_exporter_prometheus::PrometheusBuilder;

    use super::*;
    use crate::names::{ACTOR_NAME_LABEL, ACTOR_STATE};

    /// The `ACTOR_STATE` line of `actor_name` in `rendered`.
    fn state_line<'rendered>(rendered: &'rendered str, actor_name: &str) -> Option<&'rendered str> {
        let actor = format!(r#"{ACTOR_NAME_LABEL}="{actor_name}""#);
        rendered
            .lines()
            .find(|line| line.starts_with(ACTOR_STATE) && line.contains(&actor))
    }

    #[test]
    fn an_expected_actor_waits_for_its_instance() {
        let recorder = PrometheusBuilder::new().build_recorder();
        metrics::with_local_recorder(&recorder, || {
            let expected = expect("Expected");
            record_lifecycle(
                "Expected".to_owned(),
                Some("expected-1".to_owned()),
                Lifecycle::Started(SystemTime::now()),
            );
            let before = recorder.handle().render();
            assert_eq!(state_line(&before, "Expected"), None, "{before}");

            expected.name("expected-1", "a");
            let after = recorder.handle().render();
            let state = state_line(&after, "Expected").expect("Recorded once named");
            assert!(state.contains(r#"actor_instance="a""#), "{state}");
        });
    }

    #[test]
    fn an_actor_not_expected_goes_without_an_instance() {
        let recorder = PrometheusBuilder::new().build_recorder();
        metrics::with_local_recorder(&recorder, || {
            record_lifecycle(
                "Alone".to_owned(),
                Some("alone-1".to_owned()),
                Lifecycle::Stopped(ActorState::Stopped),
            );
            let rendered = recorder.handle().render();
            let state = state_line(&rendered, "Alone").expect("Recorded at once");
            assert!(!state.contains("actor_instance"), "{state}");
        });
    }
}
