use kameo::{
    Actor, Reply,
    actor::{ActorRef, Spawn as _},
    message::{Context, Message},
};

use crate::{ShardingKey, ShardingPoolActor, protocol::Spawn};

/// Counts received increments and remembers the key it was constructed for.
#[derive(Actor)]
struct Counter {
    key: u32,
    count: u64,
}

#[derive(Debug)]
struct Increment {
    key: u32,
}

#[derive(Reply, Debug, PartialEq, Eq)]
struct Observed {
    key: u32,
    count: u64,
}

#[expect(
    clippy::trivially_copy_pass_by_ref,
    reason = "Constructors must match the `fn(&K)` signature"
)]
impl Counter {
    const fn fresh(key: &u32) -> Self {
        Self {
            key: *key,
            count: 0,
        }
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

fn spawn_pool() -> ActorRef<ShardingPoolActor<Counter, u32>> {
    ShardingPoolActor::spawn(ShardingPoolActor::new(Counter::fresh))
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
