use anyhow::{Result, anyhow};
use futures::never::Never;
use kameo::actor::ActorRef;
use log::{error, info};

/// A handle to an actor encapsulating some common operations like graceful shutdown and health
/// check.
pub struct ActorHandle<T: kameo::Actor> {
    actor_ref: ActorRef<T>,
    full_name: String,
}

impl<T: kameo::Actor> ActorHandle<T> {
    pub fn new(actor_ref: ActorRef<T>) -> Self {
        Self {
            full_name: format!("{}{}", T::name(), actor_ref.id()),
            actor_ref,
        }
    }

    pub fn full_name(&self) -> &str {
        &self.full_name
    }

    pub async fn shutdown(self) {
        let full_name = self.full_name();
        info!("Stopping {full_name} actor...");

        if let Err(err) = self.actor_ref.stop_gracefully().await {
            error!("Failed to gracefully stop actor {full_name}: {err}",);
        }
        self.actor_ref.wait_for_shutdown_with_result(|_| ()).await;

        info!("{full_name} actor stopped");
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
            Ok(reason) => anyhow!("{full_name} actor has been stopped: {reason}"),
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
        info!("Killing {} actor", self.full_name());
        self.actor_ref.kill();
    }
}
