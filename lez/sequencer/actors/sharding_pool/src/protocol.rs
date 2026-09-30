/// Spawn sub-actors based on a sharding key using constructor provided at
/// `ShardingPoolActor::new()`.
///
/// If no actor exists for the given sharding key, a new one will be spawned and `true` will be
/// returned. Otherwise, `false` is returned.
pub struct Spawn<K> {
    pub key: K,
}
