use kameo::{Actor, message::Message};
use trait_set::trait_set;

use crate::{
    Result, Storable,
    error::Error,
    protocol::{
        Count, DbDump, Delete, DumpDb, Get, GetFirst, GetLast, GetRange, Store, WriteBatch,
    },
};

pub trait StorageActorTrait:
    Actor<Args = Self, Error = Error>
    + Message<DumpDb, Reply = Result<DbDump>>
    + Message<WriteBatch, Reply = Result<()>>
{
}

trait_set! {
    /// A storage actor keeping values of type `T`.
    ///
    /// A client lists one bound per type it stores, e.g. `S: Stores<A> + Stores<B>`.
    pub trait Stores<T: Storable> = StorageActorTrait
        + Message<Store<T>, Reply = Result<()>>
        + Message<Get<T>, Reply = Result<Option<T>>>
        + Message<Delete<T>, Reply = Result<()>>
        + Message<GetRange<T>, Reply = Result<Vec<(T::Key, T)>>>
        + Message<GetFirst<T>, Reply = Result<Option<(T::Key, T)>>>
        + Message<GetLast<T>, Reply = Result<Option<(T::Key, T)>>>
        + Message<Count<T>, Reply = Result<usize>>;
}
