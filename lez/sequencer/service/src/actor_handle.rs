use anyhow::{Result, anyhow};
use futures::never::Never;
use kameo::actor::ActorRef;
use tracing::{error, info};

/// A handle to an actor encapsulating some common operations like graceful shutdown and health
/// check. Creating one exports the actor's mailbox capacity.
pub struct ActorHandle<T: kameo::Actor> {
    actor_ref: ActorRef<T>,
    full_name: String,
}

impl<T: kameo::Actor> ActorHandle<T> {
    pub fn new(actor_ref: ActorRef<T>) -> Self {
        record_mailbox_capacity(&actor_ref);
        Self {
            full_name: format!("{}{}", T::name(), actor_ref.id()),
            actor_ref,
        }
    }

    pub fn full_name(&self) -> &str {
        &self.full_name
    }

    pub const fn actor_ref(&self) -> &ActorRef<T> {
        &self.actor_ref
    }

    pub async fn shutdown(self) {
        let full_name = self.full_name();
        info!(actor = full_name, "Stopping actor");

        if let Err(err) = self.actor_ref.stop_gracefully().await {
            error!(actor = full_name, error = %err, "Failed to gracefully stop actor");
        }
        self.actor_ref.wait_for_shutdown_with_result(|_| ()).await;

        info!(actor = full_name, "Actor stopped");
    }

    pub async fn failed(&self) -> Result<Never>
    where
        T::Error: std::fmt::Display,
    {
        let err = self
            .actor_ref
            .wait_for_shutdown_with_result(|res| self.stop_res_into_anyhow(res))
            .await;
        Err(err)
    }

    pub fn is_healthy(&self) -> bool {
        self.actor_ref.is_alive()
    }

    fn stop_res_into_anyhow<E: std::fmt::Display>(
        &self,
        res: Result<&kameo::error::ActorStopReason, kameo::error::HookError<&E>>,
    ) -> anyhow::Error {
        let full_name = self.full_name();

        match res {
            Ok(reason) => {
                let causes = std::iter::successors(Some(reason), |reason| {
                    if let kameo::error::ActorStopReason::LinkDied { reason, .. } = reason {
                        Some(reason.as_ref())
                    } else {
                        None
                    }
                })
                .map(ToString::to_string)
                .collect::<Vec<_>>()
                .join(": ");
                anyhow!("{full_name} actor has been stopped: {causes}")
            }
            Err(kameo::error::HookError::Panicked(err)) => {
                anyhow!(err).context(format!("{full_name} actor has been stopped due to panic"))
            }
            Err(kameo::error::HookError::Error(err)) => {
                // Can't use `anyhow!(err)` here because `err` is a reference to the error, not
                // the error itself. Also can't require `E: Clone` as a lot
                // of error types don't implement `Clone`
                // (e.g. `std::io::Error` and `anyhow::Error`).
                anyhow!(format!("{err:#}"))
                    .context(format!("{full_name} actor has been stopped due to error"))
            }
        }
    }
}

impl<T: kameo::Actor> Drop for ActorHandle<T> {
    fn drop(&mut self) {
        info!(actor = self.full_name(), "Killing actor");
        self.actor_ref.kill();
    }
}

/// Exports the capacity of `actor_ref`'s mailbox, as read off the mailbox itself.
pub fn record_mailbox_capacity<T: kameo::Actor>(actor_ref: &ActorRef<T>) {
    sequencer_service_metrics::record_mailbox_capacity(
        T::name(),
        actor_ref.mailbox_sender().max_capacity(),
    );
}

#[cfg(test)]
mod tests {
    use kameo::{actor::Spawn as _, mailbox};
    use metrics_exporter_prometheus::PrometheusBuilder;
    use sequencer_service_metrics::names::{ACTOR_MAILBOX_CAPACITY, ACTOR_NAME_LABEL};

    use super::*;

    #[derive(kameo::Actor)]
    struct Bounded;

    #[derive(kameo::Actor)]
    struct Unbounded;

    #[tokio::test]
    async fn handles_export_their_actors_mailbox_capacity() {
        let recorder = PrometheusBuilder::new().build_recorder();
        let _handles = metrics::with_local_recorder(&recorder, || {
            (
                ActorHandle::new(Bounded::spawn_with_mailbox(Bounded, mailbox::bounded(8))),
                ActorHandle::new(Unbounded::spawn_with_mailbox(
                    Unbounded,
                    mailbox::unbounded(),
                )),
            )
        });

        let rendered = recorder.handle().render();
        // The exporter writes infinity as Rust does, `inf`, which Prometheus reads as `+Inf`.
        for (actor, capacity) in [
            (<Bounded as kameo::Actor>::name(), "8"),
            (<Unbounded as kameo::Actor>::name(), "inf"),
        ] {
            let series =
                format!(r#"{ACTOR_MAILBOX_CAPACITY}{{{ACTOR_NAME_LABEL}="{actor}"}} {capacity}"#);
            assert!(rendered.contains(&series), "no `{series}` in:\n{rendered}");
        }
    }
}
