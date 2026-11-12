use kameo::{Actor, actor::ActorRef};

/// Spawn sub-actors based on a sharding key using constructor provided at
/// `ShardingPoolActor::new()`.
///
/// If no actor exists for the given sharding key, a new one will be spawned and `true` will be
/// returned. Otherwise, `false` is returned.
pub struct Spawn<K> {
    pub key: K,
}

/// Link `sibling` to the sub-actor of a sharding key, spawning it if there is none, so each learns
/// of the other dying (see [`ActorRef::link()`]).
///
/// Replies whether the sub-actor started.
pub struct Link<K, B: Actor> {
    pub key: K,
    pub sibling: ActorRef<B>,
}

/// Unlink `sibling` from the sub-actor of a sharding key, if there is one.
pub struct Unlink<K, B: Actor> {
    pub key: K,
    pub sibling: ActorRef<B>,
}

/// Reset a sharding key: stop its sub-actor, if any, wait until it has stopped and forget it, so
/// the next message for the key spawns a fresh one. The only way a sub-actor leaves the pool.
pub struct Reset<K> {
    pub key: K,
}
