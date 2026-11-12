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

use crate::{
    ShardingKey,
    protocol::{Link, Reset, Spawn, Unlink},
};

#[cfg(test)]
mod tests;

#[derive(Clone, Copy)]
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
    /// Whether the pool restarts the worker, so giving up on it means its restart budget is spent.
    restarted: bool,
}

/// See [`crate`] docs for information.
pub struct ShardingPoolActor<A: Actor<Error: Display>, K: Key> {
    workers: HashMap<K, ActorRef<A>>,
    workers_meta: HashMap<ActorId, WorkerMeta<K>>,
    /// Worker whose death is being handled by the supervisor. Its watchers are notified once the
    /// handling is done.
    died_worker: Option<ActorId>,

    restart_config: RestartConfig,
    /// Keys restarted differently from [`Self::restart_config`].
    key_restart_configs: HashMap<K, RestartConfig>,
    ctr: Arc<dyn Fn(K) -> A::Args + Send + Sync + 'static>,
    on_worker_spawned: Option<WorkerHook<A>>,
}

/// Called with a worker, see [`ShardingPoolActor::with_on_worker_spawned`].
type WorkerHook<A> = Box<dyn Fn(&ActorRef<A>) + Send + Sync + 'static>;

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
            key_restart_configs: HashMap::new(),
            ctr: Arc::new(ctr),
            on_worker_spawned: None,
        }
    }

    /// Restarts the worker of `key` according to `restart_config` instead of the pool's one.
    #[must_use]
    pub fn with_restart_config(mut self, key: K, restart_config: RestartConfig) -> Self {
        self.key_restart_configs.insert(key, restart_config);
        self
    }

    /// Calls `hook` with every worker the pool spawns, once: a restarted worker keeps its
    /// [`ActorRef`] and mailbox, while a reset key gets a new worker.
    #[must_use]
    pub fn with_on_worker_spawned<F>(mut self, hook: F) -> Self
    where
        F: Fn(&ActorRef<A>) + Send + Sync + 'static,
    {
        self.on_worker_spawned = Some(Box::new(hook));
        self
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
                let restart_config = self
                    .key_restart_configs
                    .get(&key)
                    .copied()
                    .unwrap_or(self.restart_config);

                let key_clone = key.clone();
                let actor = A::supervise_with(self_ref, move || (ctr)(key_clone.clone()))
                    .restart_policy(restart_config.policy)
                    .restart_limit(restart_config.limit, restart_config.within)
                    .spawn()
                    .await;
                if let Some(on_worker_spawned) = &self.on_worker_spawned {
                    on_worker_spawned(&actor);
                }
                let actor = vacant.insert(actor);

                self.workers_meta.insert(
                    actor.id(),
                    WorkerMeta {
                        key,
                        restart_sender: tokio::sync::watch::channel(RestartState::Initial).0,
                        restarted: restart_config.policy != RestartPolicy::Never,
                    },
                );

                (true, actor)
            }
        }
    }

    /// Returns the key of the worker and whether the pool was restarting it. A worker still in
    /// place stays there, failing its messages, until reset.
    fn give_up_worker(&mut self, id: ActorId) -> (K, bool) {
        let meta = self.workers_meta.get(&id).expect("Key must exist");
        meta.restart_sender
            .send_modify(|state| *state = RestartState::GivenUp);
        let (key, restarted) = (meta.key.clone(), meta.restarted);
        if self
            .workers
            .get(&key)
            .is_none_or(|worker| worker.id() != id)
        {
            self.workers_meta.remove(&id);
        }
        (key, restarted)
    }

    fn notify_restart_watchers(&self, id: ActorId) {
        // A reset worker is forgotten.
        let Some(meta) = self.workers_meta.get(&id) else {
            return;
        };
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
        if matches!(reason, ActorStopReason::SupervisorRestart) {
            warn!("Sharded actor with id {id} is being restarted");
            return Ok(ControlFlow::Continue(()));
        }

        let (key, restarted) = self.give_up_worker(id);
        match &reason {
            ActorStopReason::Normal => {
                info!("Sharded actor with key {key} and id {id} stopped normally");
            }
            ActorStopReason::SupervisorRestart => unreachable!("Handled above"),
            ActorStopReason::Killed => {
                warn!("Sharded actor with key {key} and id {id} was killed");
            }
            ActorStopReason::Panicked(err) => {
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
                warn!(
                    "Sharded actor with key {key} and id {id} died because its link with id {died_link_id} died with reason \"{reason}\""
                );
            }
        }

        // Given up on a worker it was restarting, the pool fails with it. A worker the pool does
        // not restart is left to the actors linked to it.
        if restarted && !reason.is_normal() {
            return Ok(ControlFlow::Break(ActorStopReason::LinkDied {
                id,
                reason: Box::new(reason),
            }));
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

impl<A, K, B> Message<Link<K, B>> for ShardingPoolActor<A, K>
where
    A: Actor,
    K: Key,
    A::Error: Display,
    B: Actor,
{
    type Reply = DelegatedReply<bool>;

    async fn handle(
        &mut self,
        Link { key, sibling }: Link<K, B>,
        ctx: &mut Context<Self, Self::Reply>,
    ) -> Self::Reply {
        let self_ref = ctx.actor_ref().clone();
        let worker = self.get_or_spawn_worker(&self_ref, key).await.1.clone();
        worker.link(&sibling).await;
        // Linked first, so a worker found running once it has started tells of its death.
        ctx.spawn(async move {
            worker.wait_for_startup_with_result(|res| res.is_ok()).await && worker.is_alive()
        })
    }
}

impl<A, K, B> Message<Unlink<K, B>> for ShardingPoolActor<A, K>
where
    A: Actor,
    K: Key,
    A::Error: Display,
    B: Actor,
{
    type Reply = ();

    async fn handle(
        &mut self,
        Unlink { key, sibling }: Unlink<K, B>,
        _ctx: &mut Context<Self, Self::Reply>,
    ) -> Self::Reply {
        if let Some(worker) = self.workers.get(&key) {
            worker.unlink(&sibling).await;
        }
    }
}

impl<A, K> Message<Reset<K>> for ShardingPoolActor<A, K>
where
    A: Actor,
    K: Key,
    A::Error: Display,
{
    type Reply = DelegatedReply<()>;

    async fn handle(&mut self, msg: Reset<K>, ctx: &mut Context<Self, Self::Reply>) -> Self::Reply {
        let worker = self.workers.remove(&msg.key);
        if let Some(worker) = &worker
            && self
                .workers_meta
                .get(&worker.id())
                .is_some_and(|meta| matches!(*meta.restart_sender.borrow(), RestartState::GivenUp))
        {
            // Its death is handled already, so nothing else forgets it.
            self.workers_meta.remove(&worker.id());
        }

        // Waiting in the handler would deadlock: the worker's mailbox closes once this pool
        // handles its death.
        ctx.spawn(async move {
            if let Some(worker) = worker {
                worker.kill();
                worker.wait_for_shutdown().await;
            }
        })
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
