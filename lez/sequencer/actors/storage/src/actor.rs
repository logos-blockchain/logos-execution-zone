use std::path::Path;

use kameo::{
    Actor,
    actor::{ActorRef, WeakActorRef},
    error::ActorStopReason,
    message::{Context, Message},
};

use crate::{
    Result, Storable, StorageActorTrait,
    error::Error,
    protocol::{
        Count, DbDump, Delete, DumpDb, Get, GetFirst, GetLast, GetRange, Store, WriteBatch,
    },
    writes::Writes,
};

pub mod db;
#[cfg(test)]
mod tests;

pub struct StorageActor {
    /// `None` after [`Actor::on_stop`] closed the database.
    db: Option<db::Database>,
}

impl StorageActor {
    /// Creates a new `StorageActor` with a database at `location`.
    /// If the database does not exist, it will be created.
    pub fn new(location: &Path) -> Result<Self> {
        Ok(Self::new_inner(db::Database::new(location)?))
    }

    /// Creates a fresh database at `location` from `dump`.
    pub fn restore_from_dump(location: &Path, dump: &DbDump) -> Result<Self> {
        let dump = db::Dump::from_bytes(&dump.bytes)?;
        Ok(Self::new_inner(db::Database::restore(location, &dump)?))
    }

    const fn new_inner(db: db::Database) -> Self {
        Self { db: Some(db) }
    }

    /// The open database.
    ///
    /// # Panics
    ///
    /// If called after the actor has stopped, which can't happen for message handlers as kameo
    /// stops delivering messages before [`Actor::on_stop`].
    const fn db(&self) -> &db::Database {
        self.db
            .as_ref()
            .expect("Database is closed, the actor has already stopped")
    }
}

impl StorageActorTrait for StorageActor {}

impl Actor for StorageActor {
    type Args = Self;
    type Error = Error;

    async fn on_start(args: Self::Args, _actor_ref: ActorRef<Self>) -> Result<Self> {
        Ok(args)
    }

    /// Closes the database, releasing the rocksdb lock on its directory.
    async fn on_stop(
        &mut self,
        _actor_ref: WeakActorRef<Self>,
        _reason: ActorStopReason,
    ) -> Result<()> {
        let Self { db } = self;

        drop(db.take());

        Ok(())
    }
}

impl<T: Storable> Message<Store<T>> for StorageActor {
    type Reply = Result<()>;

    async fn handle(
        &mut self,
        Store { key, value }: Store<T>,
        _ctx: &mut Context<Self, Self::Reply>,
    ) -> Self::Reply {
        self.db().put(&key, &value)
    }
}

impl<T: Storable> Message<Get<T>> for StorageActor {
    type Reply = Result<Option<T>>;

    async fn handle(
        &mut self,
        Get { key }: Get<T>,
        _ctx: &mut Context<Self, Self::Reply>,
    ) -> Self::Reply {
        self.db().get(&key)
    }
}

impl<T: Storable> Message<Delete<T>> for StorageActor {
    type Reply = Result<()>;

    async fn handle(
        &mut self,
        Delete { key }: Delete<T>,
        _ctx: &mut Context<Self, Self::Reply>,
    ) -> Self::Reply {
        self.db().delete::<T>(&key)
    }
}

impl<T: Storable> Message<GetRange<T>> for StorageActor {
    type Reply = Result<Vec<(T::Key, T)>>;

    async fn handle(
        &mut self,
        GetRange { start, end, limit }: GetRange<T>,
        _ctx: &mut Context<Self, Self::Reply>,
    ) -> Self::Reply {
        self.db()
            .iter_range::<T>(&start, end.as_ref())
            .take(limit)
            .collect()
    }
}

impl<T: Storable> Message<GetFirst<T>> for StorageActor {
    type Reply = Result<Option<(T::Key, T)>>;

    async fn handle(
        &mut self,
        _msg: GetFirst<T>,
        _ctx: &mut Context<Self, Self::Reply>,
    ) -> Self::Reply {
        self.db().iter::<T>().next().transpose()
    }
}

impl<T: Storable> Message<GetLast<T>> for StorageActor {
    type Reply = Result<Option<(T::Key, T)>>;

    async fn handle(
        &mut self,
        _msg: GetLast<T>,
        _ctx: &mut Context<Self, Self::Reply>,
    ) -> Self::Reply {
        self.db().iter::<T>().next_back().transpose()
    }
}

impl<T: Storable> Message<Count<T>> for StorageActor {
    type Reply = Result<usize>;

    async fn handle(
        &mut self,
        _msg: Count<T>,
        _ctx: &mut Context<Self, Self::Reply>,
    ) -> Self::Reply {
        Ok(self.db().count::<T>())
    }
}

impl<W: Writes> Message<WriteBatch<W>> for StorageActor {
    type Reply = Result<()>;

    async fn handle(
        &mut self,
        WriteBatch(writes): WriteBatch<W>,
        _ctx: &mut Context<Self, Self::Reply>,
    ) -> Self::Reply {
        self.db().write(&writes)
    }
}

impl Message<DumpDb> for StorageActor {
    type Reply = Result<DbDump>;

    async fn handle(
        &mut self,
        DumpDb: DumpDb,
        _ctx: &mut Context<Self, Self::Reply>,
    ) -> Self::Reply {
        Ok(DbDump {
            bytes: self.db().dump()?.to_bytes()?,
        })
    }
}
