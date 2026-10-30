use std::{
    collections::{HashMap, hash_map::Entry},
    fmt::Display,
    hash::Hash,
    ops::ControlFlow,
    sync::Arc,
    time::Duration,
};

use kameo::{
    Actor, Reply,
    actor::{ActorId, ActorRef, Spawn as _, WeakActorRef},
    error::{ActorStopReason, Infallible, SendError},
    mailbox::{MailboxReceiver, Signal},
    message::{Context, Message},
    reply::DelegatedReply,
    supervision::RestartPolicy,
};
use log::{info, warn};

use crate::{ShardingKey, protocol::Spawn};

#[cfg(test)]
mod tests;

pub struct RestartConfig {
    pub policy: RestartPolicy,
    pub limit: u32,
    pub within: Duration,
}

/// Trait representing a valid key for the sharding pool.
///
/// Implemented for all types that satisfy the trait bounds.
pub trait Key: Hash + Eq + Clone + Display + Send + Sync + 'static {}

impl<K: Hash + Eq + Clone + Display + Send + Sync + 'static> Key for K {}

#[derive(Clone, Copy)]
enum RestartState {
    /// Initial state before any restarts. Set once the actor is created and never resent.
    Initial,
    /// Actor was restarted.
    Restarted,
    /// Final state, given up actor will never be restarted.
    GivenUp,
}

struct WorkerMeta<K> {
    key: K,
    restart_sender: tokio::sync::watch::Sender<RestartState>,
}

/// See [`crate`] docs for information.
pub struct ShardingPoolActor<A: Actor<Error: Display>, K: Key> {
    workers: HashMap<K, ActorRef<A>>,
    workers_meta: HashMap<ActorId, WorkerMeta<K>>,
    /// Worker whose death is being handled by the supervisor. Its watchers are notified once the
    /// handling is done.
    died_worker: Option<ActorId>,

    restart_config: RestartConfig,
    ctr: Arc<dyn Fn(K) -> A::Args + Send + Sync + 'static>,
}

impl<A, K> ShardingPoolActor<A, K>
where
    A: Actor,
    K: Key,
    A::Error: Display,
{
    /// Create new sharding pool with the given restart config and actor constructor function.
    ///
    /// Note that constructor function must be infallible. If your actor initialization can fail,
    /// consider using [`Actor::on_start`] for that.
    pub fn new<F>(restart_config: RestartConfig, ctr: F) -> Self
    where
        F: Fn(K) -> A::Args + Send + Sync + 'static,
    {
        Self {
            workers: HashMap::new(),
            workers_meta: HashMap::new(),
            died_worker: None,
            restart_config,
            ctr: Arc::new(ctr),
        }
    }

    async fn get_or_spawn_worker(
        &mut self,
        self_ref: &ActorRef<Self>,
        key: K,
    ) -> (bool, &ActorRef<A>) {
        let entry = self.workers.entry(key.clone());
        #[expect(
            clippy::ref_patterns,
            reason = "Handy here to pass value by reference and by value to different branches"
        )]
        match entry {
            Entry::Occupied(ref _occupied) => (
                false,
                // Can't use `occupied.get()` because of lifetime issues
                entry.or_insert_with(|| unreachable!("Checked that it's occupied")),
            ),
            Entry::Vacant(vacant) => {
                let ctr = Arc::clone(&self.ctr);

                let key_clone = key.clone();
                let actor = A::supervise_with(self_ref, move || (ctr)(key_clone.clone()))
                    .restart_policy(self.restart_config.policy)
                    .restart_limit(self.restart_config.limit, self.restart_config.within)
                    .spawn()
                    .await;
                let actor = vacant.insert(actor);

                self.workers_meta.insert(
                    actor.id(),
                    WorkerMeta {
                        key,
                        restart_sender: tokio::sync::watch::channel(RestartState::Initial).0,
                    },
                );

                (true, actor)
            }
        }
    }

    fn give_up_worker(&self, id: ActorId) -> &K {
        let meta = self.workers_meta.get(&id).expect("Key must exist");
        meta.restart_sender
            .send_modify(|state| *state = RestartState::GivenUp);
        &meta.key
    }

    fn notify_restart_watchers(&self, id: ActorId) {
        let meta = self.workers_meta.get(&id).expect("Meta must exist");
        meta.restart_sender.send_if_modified(|state| match state {
            RestartState::Initial | RestartState::Restarted => {
                // Updating the value to indicate that the actor has been restarted once again.
                *state = RestartState::Restarted;
                true
            }
            // Doing nothing as the actor has been given up.
            RestartState::GivenUp => false,
        });
    }
}

impl<A, K> Actor for ShardingPoolActor<A, K>
where
    A: Actor,
    K: Key,
    A::Error: Display,
{
    type Args = Self;
    type Error = Infallible;

    async fn on_start(args: Self::Args, _actor_ref: ActorRef<Self>) -> Result<Self, Self::Error> {
        Ok(args)
    }

    async fn next(
        &mut self,
        _actor_ref: WeakActorRef<Self>,
        mailbox_rx: &mut MailboxReceiver<Self>,
    ) -> Result<Option<Signal<Self>>, Self::Error> {
        // Previous `LinkDied` signal has been handled by now, so the worker is either restarted or
        // given up.
        if let Some(id) = self.died_worker.take() {
            self.notify_restart_watchers(id);
        }

        let Some(signal) = mailbox_rx.recv().await else {
            return Ok(None);
        };
        if let Signal::LinkDied { id, .. } = signal {
            self.died_worker = Some(id);
        }

        Ok(Some(signal))
    }

    async fn on_link_died(
        &mut self,
        _actor_ref: WeakActorRef<Self>,
        id: ActorId,
        reason: ActorStopReason,
    ) -> Result<ControlFlow<ActorStopReason>, Self::Error> {
        match &reason {
            ActorStopReason::Normal => {
                let key = self.give_up_worker(id);
                info!("Sharded actor with key {key} and id {id} stopped normally");
            }
            ActorStopReason::SupervisorRestart => {
                warn!("Sharded actor with id {id} is being restarted");
            }
            ActorStopReason::Killed => {
                let key = self.give_up_worker(id);
                warn!("Sharded actor with key {key} and id {id} was killed");
            }
            ActorStopReason::Panicked(err) => {
                let key = self.give_up_worker(id);
                let panic_reason = err.reason();
                let downcasted = err
                    .with_downcast_ref(|err: &A::Error| {
                        warn!(
                            "Sharded actor with key {key} and id {id} panicked with reason \"{panic_reason}\" and error \"{err:#}\""
                        );
                    })
                    .is_some();

                if !downcasted {
                    warn!(
                        "Sharded actor with key {key} and id {id} panicked with reason \"{panic_reason}\""
                    );
                }
            }
            ActorStopReason::LinkDied {
                id: died_link_id,
                reason,
            } => {
                let key = self.give_up_worker(id);
                warn!(
                    "Sharded actor with key {key} and id {id} died because its link with id {died_link_id} died with reason \"{reason}\""
                );
            }
        }

        Ok(ControlFlow::Continue(()))
    }
}

impl<A, K> Message<Spawn<K>> for ShardingPoolActor<A, K>
where
    A: Actor,
    K: Key,
    A::Error: Display,
{
    type Reply = bool;

    async fn handle(&mut self, msg: Spawn<K>, ctx: &mut Context<Self, Self::Reply>) -> Self::Reply {
        self.get_or_spawn_worker(ctx.actor_ref(), msg.key).await.0
    }
}

impl<A, K, M> Message<M> for ShardingPoolActor<A, K>
where
    A: Actor + Message<M>,
    A::Error: std::fmt::Display,
    K: Key,
    M: ShardingKey<Key = K> + Clone + Send + 'static,
{
    type Reply =
        DelegatedReply<Result<<A::Reply as Reply>::Ok, SendError<M, <A::Reply as Reply>::Error>>>;

    async fn handle(&mut self, msg: M, ctx: &mut Context<Self, Self::Reply>) -> Self::Reply {
        let self_ref = ctx.actor_ref().clone();
        let key = msg.sharding_key();
        let actor = self
            .get_or_spawn_worker(&self_ref, key.clone())
            .await
            .1
            .clone();
        let mut receiver = self
            .workers_meta
            .get(&actor.id())
            .expect("Worker meta must exist")
            .restart_sender
            .subscribe();

        ctx.spawn(async move {
            loop {
                match actor.ask(msg.clone()).await {
                    Ok(resp) => return Ok(resp),
                    Err(
                        SendError::ActorStopped
                        | SendError::ActorRestarting(_)
                        | SendError::ActorNotRunning(_),
                    ) => {
                        let cur_state = *receiver.borrow();
                        if matches!(cur_state, RestartState::GivenUp) {
                            return Err(SendError::ActorStopped);
                        }

                        receiver
                            .changed()
                            .await
                            .map_err(|_err| SendError::ActorStopped)?;
                        let value = *receiver.borrow_and_update();
                        match value {
                            RestartState::Initial => {
                                unreachable!("Initial state cannot happen twice")
                            }
                            RestartState::Restarted => {}
                            RestartState::GivenUp => return Err(SendError::ActorStopped),
                        }
                    }
                    Err(
                        err @ (SendError::MailboxFull(_)
                        | SendError::HandlerError(_)
                        | SendError::Timeout(_)),
                    ) => return Err(err),
                }
            }
        })
    }
}
