#![expect(
    clippy::arithmetic_side_effects,
    reason = "We don't care about these in tests"
)]

use std::{
    fmt::Display,
    sync::{Arc, Mutex},
    time::Duration,
};

use kameo::{
    Actor, Reply,
    actor::{ActorRef, Spawn as _},
    error::{ActorStopReason, SendError},
    message::{Context, Message},
    supervision::RestartPolicy,
};
use sequencer_actors_common::SendErrorExt;
use tracing::{
    Subscriber,
    field::{Field, Visit},
    info, span,
};
use tracing_subscriber::{Layer, layer::SubscriberExt as _, registry::LookupSpan};

use super::FORWARD_SPAN;
use crate::{
    RestartConfig, ShardingKey, ShardingPoolActor,
    protocol::{Link, Reset, Spawn, Unlink},
};

/// Stops once an actor linked to it dies, as kameo does by default.
#[derive(Actor)]
struct Watcher;

/// Counts received increments and remembers the key it was constructed for.
#[derive(Actor)]
struct Counter {
    key: u32,
    count: u64,
}

#[derive(Debug, Clone, Copy)]
struct Increment {
    key: u32,
}

#[derive(Reply, Debug, PartialEq, Eq)]
struct Observed {
    key: u32,
    count: u64,
}

impl Counter {
    const fn fresh(key: u32) -> Self {
        Self { key, count: 0 }
    }
}

impl ShardingKey for Increment {
    type Key = u32;

    fn sharding_key(&self) -> Self::Key {
        self.key
    }
}

impl Message<Increment> for Counter {
    type Reply = Observed;

    async fn handle(
        &mut self,
        _msg: Increment,
        _ctx: &mut Context<Self, Self::Reply>,
    ) -> Self::Reply {
        self.count = self.count.saturating_add(1);
        Observed {
            key: self.key,
            count: self.count,
        }
    }
}

struct TickingBomb {
    ticks: u32,
}

impl Actor for TickingBomb {
    type Args = u32;
    type Error = String;

    async fn on_start(args: Self::Args, _actor_ref: ActorRef<Self>) -> Result<Self, Self::Error> {
        let ticks = args;
        info!(?ticks, "Starting TickingBombActor");

        if ticks == 0 {
            return Err("Ticks must be greater than zero".to_owned());
        }

        Ok(Self { ticks })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct Tick;

impl Message<Tick> for TickingBomb {
    type Reply = ();

    async fn handle(&mut self, _msg: Tick, _ctx: &mut Context<Self, Self::Reply>) -> Self::Reply {
        self.ticks = self.ticks.saturating_sub(1);
        assert_ne!(self.ticks, 0, "Boom!");
    }
}

/// Like `()` but implements needed traits for being used as a sharding key.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct TickShardingKey;

impl Display for TickShardingKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "TickShardingKey")
    }
}

impl ShardingKey for Tick {
    type Key = TickShardingKey;

    fn sharding_key(&self) -> TickShardingKey {
        TickShardingKey
    }
}

/// Like [`Tick`] but routed to the bomb with the given key and applied only once `trigger` fires.
#[derive(Debug, Clone)]
struct TriggeredTick {
    key: u32,
    trigger: tokio::sync::watch::Receiver<bool>,
}

impl ShardingKey for TriggeredTick {
    type Key = u32;

    fn sharding_key(&self) -> Self::Key {
        self.key
    }
}

impl Message<TriggeredTick> for TickingBomb {
    type Reply = ();

    async fn handle(
        &mut self,
        mut msg: TriggeredTick,
        ctx: &mut Context<Self, Self::Reply>,
    ) -> Self::Reply {
        msg.trigger
            .wait_for(|fired| *fired)
            .await
            .expect("Trigger must not be dropped before firing");
        <Self as Message<Tick>>::handle(self, Tick, ctx).await;
    }
}

/// Records which span follows from which, each by the actor it runs in, or
/// else by its name.
#[derive(Clone, Default)]
struct FollowsFrom(Arc<Mutex<Vec<(String, String)>>>);

/// A span's name as [`FollowsFrom`] records it.
struct SpanName(String);

/// The `actor.name` field kameo puts on its spans.
#[derive(Default)]
struct ActorName(Option<String>);

impl Visit for ActorName {
    fn record_str(&mut self, field: &Field, value: &str) {
        if field.name() == "actor.name" {
            self.0 = Some(value.to_owned());
        }
    }

    fn record_debug(&mut self, field: &Field, value: &dyn std::fmt::Debug) {
        if field.name() == "actor.name" {
            self.0 = Some(format!("{value:?}"));
        }
    }
}

impl<S: Subscriber + for<'lookup> LookupSpan<'lookup>> Layer<S> for FollowsFrom {
    fn on_new_span(
        &self,
        attrs: &span::Attributes<'_>,
        id: &span::Id,
        ctx: tracing_subscriber::layer::Context<'_, S>,
    ) {
        let mut actor = ActorName::default();
        attrs.record(&mut actor);
        let name = actor
            .0
            .unwrap_or_else(|| attrs.metadata().name().to_owned());
        if let Some(span) = ctx.span(id) {
            span.extensions_mut().insert(SpanName(name));
        }
    }

    fn on_follows_from(
        &self,
        id: &span::Id,
        follows: &span::Id,
        ctx: tracing_subscriber::layer::Context<'_, S>,
    ) {
        let name = |span_id| {
            let span = ctx.span(span_id)?;
            let extensions = span.extensions();
            extensions
                .get::<SpanName>()
                .map(|SpanName(name)| name.clone())
        };
        if let (Some(span), Some(cause)) = (name(id), name(follows)) {
            self.0
                .lock()
                .expect("Follows-from lock poisoned")
                .push((span, cause));
        }
    }
}

fn spawn_pool() -> ActorRef<ShardingPoolActor<Counter, u32>> {
    ShardingPoolActor::spawn(ShardingPoolActor::new(
        RestartConfig {
            policy: RestartPolicy::Never,
            limit: 0,
            within: Duration::ZERO,
        },
        Counter::fresh,
    ))
}

async fn increment(pool: &ActorRef<ShardingPoolActor<Counter, u32>>, key: u32) -> Observed {
    pool.ask(Increment { key })
        .await
        .expect("Failed to increment the counter")
}

#[tokio::test]
async fn messages_with_the_same_key_reach_the_same_actor() {
    let pool = spawn_pool();

    assert_eq!(increment(&pool, 1).await, Observed { key: 1, count: 1 });
    assert_eq!(increment(&pool, 1).await, Observed { key: 1, count: 2 });
}

#[tokio::test]
async fn messages_with_different_keys_reach_separate_actors() {
    let pool = spawn_pool();

    increment(&pool, 1).await;
    increment(&pool, 1).await;

    assert_eq!(
        increment(&pool, 2).await,
        Observed { key: 2, count: 1 },
        "A new key must get its own actor constructed for that key"
    );
    assert_eq!(increment(&pool, 1).await, Observed { key: 1, count: 3 });
}

#[tokio::test]
async fn spawn_creates_an_actor_only_for_a_new_key() {
    let pool = spawn_pool();

    assert!(pool.ask(Spawn { key: 1 }).await.expect("Failed to spawn"));
    assert_eq!(increment(&pool, 1).await, Observed { key: 1, count: 1 });

    assert!(
        !pool.ask(Spawn { key: 1 }).await.expect("Failed to spawn"),
        "Spawning an existing key must be rejected"
    );
    assert_eq!(
        increment(&pool, 1).await,
        Observed { key: 1, count: 2 },
        "A rejected spawn must keep the existing actor"
    );
}

#[tokio::test]
async fn spawn_is_rejected_for_a_key_already_routed_to() {
    let pool = spawn_pool();

    increment(&pool, 1).await;

    assert!(!pool.ask(Spawn { key: 1 }).await.expect("Failed to spawn"));
    assert_eq!(increment(&pool, 1).await, Observed { key: 1, count: 2 });
}

#[tokio::test]
async fn the_spawn_hook_sees_a_worker_per_key() {
    let spawned = Arc::new(Mutex::new(Vec::new()));
    let spawned_clone = Arc::clone(&spawned);
    let pool = ShardingPoolActor::spawn(
        ShardingPoolActor::new(
            RestartConfig {
                policy: RestartPolicy::Never,
                limit: 0,
                within: Duration::ZERO,
            },
            Counter::fresh,
        )
        .with_on_worker_spawned(move |key, worker| {
            spawned_clone.lock().unwrap().push((*key, worker.id()));
        }),
    );

    increment(&pool, 1).await;
    increment(&pool, 1).await;
    increment(&pool, 2).await;

    let spawned = spawned.lock().unwrap();
    let keys: Vec<_> = spawned.iter().map(|(key, _)| *key).collect();
    assert_eq!(keys, [1, 2]);
    assert_ne!(spawned[0].1, spawned[1].1);
}

#[tokio::test]
async fn the_spawn_hook_skips_a_restarted_worker() {
    let _err = logging::try_init();

    let spawned = Arc::new(Mutex::new(0_u32));
    let spawned_clone = Arc::clone(&spawned);
    let pool = ShardingPoolActor::spawn(
        ShardingPoolActor::<TickingBomb, TickShardingKey>::new(
            RestartConfig {
                policy: RestartPolicy::Permanent,
                limit: 1,
                within: Duration::from_mins(1),
            },
            |TickShardingKey| 2,
        )
        .with_on_worker_spawned(move |_key, _worker| *spawned_clone.lock().unwrap() += 1),
    );

    assert_eq!(pool.ask(Tick).await, Ok(()));
    // Explodes, and is restarted.
    assert_eq!(pool.ask(Tick).await, Ok(()));

    assert_eq!(*spawned.lock().unwrap(), 1);
}

#[tokio::test]
async fn sending_message_to_actor_which_failed_to_start_results_in_error() {
    let _err = logging::try_init();

    let pool = ShardingPoolActor::<TickingBomb, TickShardingKey>::new(
        RestartConfig {
            policy: RestartPolicy::Never,
            limit: 0,
            within: Duration::ZERO,
        },
        |TickShardingKey| 0,
    );
    let pool = ShardingPoolActor::spawn(pool);

    assert_eq!(
        pool.ask(Tick).await.map_err(SendErrorExt::flatten),
        Err(SendError::ActorStopped)
    );
}

#[tokio::test]
async fn actor_panicked_when_handling_message_is_restarted() {
    let _err = logging::try_init();

    let pool = ShardingPoolActor::<TickingBomb, TickShardingKey>::new(
        RestartConfig {
            policy: RestartPolicy::Permanent,
            limit: 1,
            within: Duration::from_mins(1),
        },
        |TickShardingKey| 2,
    );
    let pool = ShardingPoolActor::spawn(pool);

    assert_eq!(pool.ask(Tick).await, Ok(()));
    // This Tick causes TickingBomb to explode (panic) and should trigger a restart.
    assert_eq!(pool.ask(Tick).await, Ok(()));

    // After the restart limit is reached (this test is faster than 1 min), the bomb should not be
    // restarted.
    assert_eq!(
        pool.ask(Tick).await.map_err(SendErrorExt::flatten),
        Err(SendError::ActorStopped)
    );
}

#[tokio::test]
async fn a_given_up_actor_stays_stopped_until_reset() {
    let _err = logging::try_init();

    let pool = ShardingPoolActor::<TickingBomb, TickShardingKey>::new(
        RestartConfig {
            policy: RestartPolicy::Never,
            limit: 0,
            within: Duration::ZERO,
        },
        |TickShardingKey| 2,
    );
    let pool = ShardingPoolActor::spawn(pool);

    // First tick normal.
    assert_eq!(pool.ask(Tick).await, Ok(()));
    // Second tick causes boom.
    assert_eq!(
        pool.ask(Tick).await.map_err(SendErrorExt::flatten),
        Err(SendError::ActorStopped)
    );
    assert_eq!(
        pool.ask(Tick).await.map_err(SendErrorExt::flatten),
        Err(SendError::ActorStopped),
        "The given up bomb must not be restarted"
    );
    assert!(
        pool.is_alive(),
        "Pool must outlive an actor it does not restart"
    );

    pool.ask(Reset {
        key: TickShardingKey,
    })
    .await
    .expect("Failed to reset");
    assert_eq!(
        pool.ask(Tick).await,
        Ok(()),
        "A fresh bomb must take the tick"
    );
}

#[tokio::test]
async fn spending_the_restart_budget_stops_the_pool() {
    let _err = logging::try_init();

    let pool = ShardingPoolActor::<TickingBomb, TickShardingKey>::new(
        RestartConfig {
            policy: RestartPolicy::Permanent,
            limit: 0,
            within: Duration::from_mins(1),
        },
        |TickShardingKey| 2,
    );
    let pool = ShardingPoolActor::spawn(pool);

    assert_eq!(pool.ask(Tick).await, Ok(()));
    assert_eq!(
        pool.ask(Tick).await.map_err(SendErrorExt::flatten),
        Err(SendError::ActorStopped)
    );

    let stopped_for_the_bomb = tokio::time::timeout(
        Duration::from_secs(5),
        pool.wait_for_shutdown_with_result(|res| {
            matches!(
                res,
                Ok(ActorStopReason::LinkDied { reason, .. })
                    if matches!(**reason, ActorStopReason::Panicked(_))
            )
        }),
    )
    .await
    .expect("Pool must stop once the bomb spends its restart budget");
    assert!(stopped_for_the_bomb, "Pool must stop for the bomb's panic");
}

#[tokio::test]
async fn a_key_is_restarted_by_its_own_restart_config() {
    const RESTARTED_KEY: u32 = 0;
    const NEVER_RESTARTED_KEY: u32 = 1;

    let _err = logging::try_init();

    let pool = ShardingPoolActor::<TickingBomb, u32>::new(
        RestartConfig {
            policy: RestartPolicy::Never,
            limit: 0,
            within: Duration::ZERO,
        },
        |_key| 2,
    )
    .with_restart_config(
        RESTARTED_KEY,
        RestartConfig {
            policy: RestartPolicy::Permanent,
            limit: 1,
            within: Duration::from_mins(1),
        },
    );
    let pool = ShardingPoolActor::spawn(pool);
    let (fire, trigger) = tokio::sync::watch::channel(true);
    drop(fire);
    let tick = |key| TriggeredTick {
        key,
        trigger: trigger.clone(),
    };

    for key in [RESTARTED_KEY, NEVER_RESTARTED_KEY] {
        assert!(pool.ask(tick(key)).await.is_ok());
    }
    assert!(
        pool.ask(tick(RESTARTED_KEY)).await.is_ok(),
        "The exploded tick must be retried by the restarted bomb"
    );
    assert!(matches!(
        pool.ask(tick(NEVER_RESTARTED_KEY))
            .await
            .map_err(SendErrorExt::flatten),
        Err(SendError::ActorStopped)
    ));
}

#[tokio::test]
async fn a_linked_actor_learns_of_its_worker_dying() {
    let pool = spawn_pool();
    let watcher = Watcher::spawn(Watcher);

    let started = pool
        .ask(Link {
            key: 1,
            sibling: watcher.clone(),
        })
        .await
        .expect("Failed to link");
    assert!(started, "The linked worker must have started");
    pool.ask(Reset { key: 1 }).await.expect("Failed to reset");

    tokio::time::timeout(Duration::from_secs(5), watcher.wait_for_shutdown())
        .await
        .expect("Watcher must stop along with its worker");
}

#[tokio::test]
async fn an_unlinked_actor_outlives_its_worker() {
    let pool = spawn_pool();
    let watcher = Watcher::spawn(Watcher);

    pool.ask(Link {
        key: 1,
        sibling: watcher.clone(),
    })
    .await
    .expect("Failed to link");
    pool.ask(Unlink {
        key: 1,
        sibling: watcher.clone(),
    })
    .await
    .expect("Failed to unlink");
    pool.ask(Reset { key: 1 }).await.expect("Failed to reset");

    // Room for a link death notice to arrive, had one been sent.
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert!(
        watcher.is_alive(),
        "Watcher must outlive the unlinked worker"
    );
}

#[tokio::test]
async fn linking_a_worker_that_failed_to_start_replies_so() {
    let _err = logging::try_init();

    let pool = ShardingPoolActor::spawn(ShardingPoolActor::<TickingBomb, TickShardingKey>::new(
        RestartConfig {
            policy: RestartPolicy::Never,
            limit: 0,
            within: Duration::ZERO,
        },
        |TickShardingKey| 0,
    ));

    let started = pool
        .ask(Link {
            key: TickShardingKey,
            sibling: Watcher::spawn(Watcher),
        })
        .await
        .expect("Failed to link");
    assert!(!started);
}

#[tokio::test]
async fn a_reset_worker_is_replaced_by_a_fresh_one() {
    let pool = spawn_pool();

    increment(&pool, 1).await;
    pool.ask(Reset { key: 1 }).await.expect("Failed to reset");

    assert_eq!(increment(&pool, 1).await, Observed { key: 1, count: 1 });
}

/// Multi-threaded so that the bomb can explode while the pool is blocked.
#[tokio::test(flavor = "multi_thread")]
async fn pool_with_full_mailbox_will_still_restart_failed_actor() {
    const BOMB_KEY: u32 = 0;
    const SLOW_KEY: u32 = 1;
    const FILLER_KEY: u32 = 2;
    const MAILBOX_CAPACITY: usize = 4;
    const STEP_DURATION: Duration = Duration::from_millis(100);
    const BLOCK_DURATION: Duration = Duration::from_millis(500);

    let _err = logging::try_init();

    let pool = ShardingPoolActor::<TickingBomb, u32>::new(
        RestartConfig {
            policy: RestartPolicy::Permanent,
            limit: 1,
            within: Duration::from_mins(1),
        },
        |key| {
            if key == SLOW_KEY {
                info!(duration = ?BLOCK_DURATION, "Blocking the pool");
                // Constructor is called by the pool itself, so this blocks the pool.
                std::thread::sleep(BLOCK_DURATION);
            }
            2
        },
    );
    let pool =
        ShardingPoolActor::spawn_with_mailbox(pool, kameo::mailbox::bounded(MAILBOX_CAPACITY));

    // The second of these ticks explodes the bomb.
    let (fire, trigger) = tokio::sync::watch::channel(false);
    let tick = TriggeredTick {
        key: BOMB_KEY,
        trigger,
    };
    let first_tick = pool
        .ask(tick.clone())
        .enqueue()
        .await
        .expect("Failed to enqueue the first tick");
    let second_tick = pool
        .ask(tick)
        .enqueue()
        .await
        .expect("Failed to enqueue the second tick");

    // Letting the pool route the ticks to the bomb before blocking it.
    tokio::time::sleep(STEP_DURATION).await;
    pool.tell(Spawn { key: SLOW_KEY })
        .send()
        .await
        .expect("Failed to send slow spawn");
    tokio::time::sleep(STEP_DURATION).await;

    // The pool is blocked now, so the bomb's `LinkDied` is left waiting in the pool's mailbox.
    fire.send(true).expect("Bomb must wait for the trigger");
    tokio::time::sleep(STEP_DURATION).await;

    // `LinkDied` already takes one slot.
    for _ in 1..MAILBOX_CAPACITY {
        pool.tell(Spawn { key: FILLER_KEY })
            .try_send()
            .expect("Failed to fill the mailbox");
    }
    assert!(matches!(
        pool.tell(Spawn { key: FILLER_KEY }).try_send(),
        Err(SendError::MailboxFull(_))
    ));

    // Takes the slot freed by the pool receiving `LinkDied`, so the mailbox stays full while the
    // pool reacts to the bomb death.
    let waiting_sender = tokio::spawn({
        let pool = pool.clone();
        async move { pool.tell(Spawn { key: FILLER_KEY }).send().await.is_ok() }
    });

    let (first_tick, second_tick) = tokio::time::timeout(BLOCK_DURATION * 4, async {
        (first_tick.await, second_tick.await)
    })
    .await
    .expect("Pool got stuck handling the bomb death with a full mailbox");
    assert!(
        first_tick.is_ok() && second_tick.is_ok(),
        "Exploded tick must be retried by the restarted bomb: {first_tick:?}, {second_tick:?}"
    );
    assert!(
        waiting_sender.await.expect("Waiting sender panicked"),
        "Waiting sender must eventually be served"
    );
}

#[tokio::test]
async fn a_message_passed_on_follows_from_the_pool_handling_it() {
    let follows = FollowsFrom::default();
    let _subscriber =
        tracing::subscriber::set_default(tracing_subscriber::registry().with(follows.clone()));

    let pool = spawn_pool();
    increment(&pool, 1).await;

    let follows = follows
        .0
        .lock()
        .expect("Follows-from lock poisoned")
        .clone();
    let pool_name = <ShardingPoolActor<Counter, u32> as Actor>::name();
    let worker_name = <Counter as Actor>::name();
    for (span, cause) in [(worker_name, FORWARD_SPAN), (FORWARD_SPAN, pool_name)] {
        assert!(
            follows.contains(&(span.to_owned(), cause.to_owned())),
            "{span} does not follow from {cause}: {follows:?}"
        );
    }
}
