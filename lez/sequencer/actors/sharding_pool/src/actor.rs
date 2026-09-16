use std::{
    collections::{HashMap, hash_map::Entry},
    hash::Hash,
};

use kameo::{
    Actor,
    actor::{ActorRef, Spawn as _},
    message::{Context, Message},
    reply::ForwardedReply,
};

use crate::{ShardingKey, protocol::Spawn};

#[cfg(test)]
mod tests;

#[derive(Actor)]
pub struct ShardingPoolActor<A: Actor, K: Send + 'static> {
    actors: HashMap<K, ActorRef<A>>,

    #[expect(
        clippy::type_complexity,
        reason = "More readable than using a type alias"
    )]
    ctr: Box<dyn Fn(&K) -> A::Args + Send + 'static>,
}

impl<A: Actor, K: Send + 'static> ShardingPoolActor<A, K> {
    pub fn new<F>(ctr: F) -> Self
    where
        F: Fn(&K) -> A::Args + Send + 'static,
    {
        Self {
            actors: HashMap::new(),
            ctr: Box::new(ctr),
        }
    }
}

impl<A, K> Message<Spawn<K>> for ShardingPoolActor<A, K>
where
    A: Actor,
    K: Hash + Eq + Send + 'static,
{
    type Reply = bool;

    async fn handle(
        &mut self,
        msg: Spawn<K>,
        _ctx: &mut Context<Self, Self::Reply>,
    ) -> Self::Reply {
        let entry = self.actors.entry(msg.key);
        match entry {
            Entry::Occupied(_) => false,
            Entry::Vacant(vacant) => {
                let actor = A::spawn((self.ctr)(vacant.key()));
                vacant.insert(actor);
                true
            }
        }
    }
}

impl<A, K, M> Message<M> for ShardingPoolActor<A, K>
where
    A: Actor + Message<M>,
    K: Hash + Eq + Send + 'static,
    M: ShardingKey<Key = K> + Send + 'static,
{
    type Reply = ForwardedReply<M, A::Reply>;

    async fn handle(&mut self, msg: M, ctx: &mut Context<Self, Self::Reply>) -> Self::Reply {
        let actor = self
            .actors
            .entry(msg.sharding_key())
            .or_insert_with_key(|key| A::spawn((self.ctr)(key)));

        ctx.forward(actor, msg).await
    }
}
