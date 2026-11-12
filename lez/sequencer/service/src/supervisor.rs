use kameo::{Actor, actor::ActorRef, error::Infallible, supervision::SupervisionStrategy};

/// Supervises the top actors of the sequencer. A failed one restarts them
/// all, and once one spends its restarts the supervisor stops, failing the sequencer.
pub struct SequencerSupervisor;

impl Actor for SequencerSupervisor {
    type Args = Self;
    type Error = Infallible;

    fn supervision_strategy() -> SupervisionStrategy {
        SupervisionStrategy::OneForAll
    }

    async fn on_start(args: Self::Args, _actor_ref: ActorRef<Self>) -> Result<Self, Self::Error> {
        Ok(args)
    }
}
