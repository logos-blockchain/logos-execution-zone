use std::{
    any::Any,
    ops::{Deref, DerefMut},
};

use kameo::{
    Actor, Reply,
    actor::ActorRef,
    message::{Context, Message},
};
pub use sequencer_actors_common::mock::{Checkpoint, Replace, ReplaceReply};

pub use self::{
    canned_store::{CannedStore, SharedStore},
    stored_values::StoredValues,
};
use crate::{
    Result, Storable, StorageActorTrait,
    error::Error,
    protocol::{
        Count, DbDump, Delete, DumpDb, Get, GetFirst, GetLast, GetRange, RangeStart, Store,
        WriteBatch,
    },
    storable::start_key,
    writes::Writes,
};

mod canned_store;
mod stored_values;

mockall::mock! {
    pub StorageActorExpectations {
        pub fn handle_dump_db(
            &mut self,
            msg: DumpDb,
            ctx: &mut Context<MockStorageActor, Result<DbDump>>
        ) -> Result<DbDump>;

        pub fn handle_checkpoint(
            &mut self,
            msg: Checkpoint,
            ctx: &mut Context<MockStorageActor, Result<()>>,
        ) -> Result<()>;
    }
}

/// A storage actor whose fixed messages are mocked, while the values of
/// generic messages, like [`Store`] and [`Get`], are kept in memory.
///
/// Expectations are set on [`MockStorageActorExpectations`], which the mock
/// dereferences to.
#[derive(Default)]
pub struct MockStorageActor {
    expectations: MockStorageActorExpectations,
    values: StoredValues,
    stalled_reads: Option<StalledReads>,
}

/// Whether a read of a key stalls, by the key bytes.
type StallsKey = Box<dyn Fn(&[u8]) -> bool + Send>;

/// [`Get`] and [`GetRange`] messages the mock takes but never answers.
struct StalledReads {
    type_name: &'static str,
    stalls: StallsKey,
    on_stall: Box<dyn Fn() + Send>,
    /// Reply senders of the stalled reads, kept so their callers wait instead of failing.
    held: Vec<Box<dyn Any + Send>>,
}

impl MockStorageActor {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// A mock keeping the values of generic messages in `values`, seen by
    /// every holder of a clone of it.
    #[must_use]
    pub fn with_values(values: StoredValues) -> Self {
        Self {
            expectations: MockStorageActorExpectations::new(),
            values,
            stalled_reads: None,
        }
    }

    /// Makes every later [`Get`] of a `T` whose key `stalls`, and every [`GetRange`] of a `T`
    /// starting at a key that does, call `on_stall` and never get an answer, while the mock keeps
    /// handling other messages.
    pub fn stall_reads<T: Storable>(
        &mut self,
        stalls: impl Fn(&[u8]) -> bool + Send + 'static,
        on_stall: impl Fn() + Send + 'static,
    ) {
        self.stalled_reads = Some(StalledReads {
            type_name: T::TYPE_NAME,
            stalls: Box::new(stalls),
            on_stall: Box::new(on_stall),
            held: Vec::new(),
        });
    }

    #[must_use]
    pub const fn values(&self) -> &StoredValues {
        &self.values
    }

    /// Whether a read of a `T` from `key` stalls; a stalled read keeps its reply sender, so the
    /// reply the handler returns is never sent.
    fn stall<T: Storable, R: Reply>(
        &mut self,
        key: Option<&[u8]>,
        ctx: &mut Context<Self, R>,
    ) -> bool {
        let Some(stalled) = &mut self.stalled_reads else {
            return false;
        };
        if stalled.type_name != T::TYPE_NAME || !key.is_some_and(|key| (stalled.stalls)(key)) {
            return false;
        }
        (stalled.on_stall)();
        let (_delegated, reply_sender) = ctx.reply_sender();
        if let Some(sender) = reply_sender {
            stalled.held.push(Box::new(sender));
        }
        true
    }
}

impl Deref for MockStorageActor {
    type Target = MockStorageActorExpectations;

    fn deref(&self) -> &Self::Target {
        &self.expectations
    }
}

impl DerefMut for MockStorageActor {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.expectations
    }
}

impl StorageActorTrait for MockStorageActor {}

impl Actor for MockStorageActor {
    type Args = Self;
    type Error = Error;

    async fn on_start(args: Self::Args, _actor_ref: ActorRef<Self>) -> Result<Self> {
        Ok(args)
    }
}

impl<T: Storable> Message<Store<T>> for MockStorageActor {
    type Reply = Result<()>;

    async fn handle(
        &mut self,
        Store { key, value }: Store<T>,
        _ctx: &mut Context<Self, Self::Reply>,
    ) -> Self::Reply {
        self.values.store(&key, &value)
    }
}

impl<T: Storable> Message<Get<T>> for MockStorageActor {
    type Reply = Result<Option<T>>;

    async fn handle(
        &mut self,
        Get { key }: Get<T>,
        ctx: &mut Context<Self, Self::Reply>,
    ) -> Self::Reply {
        if self.stall::<T, _>(Some(key.as_ref()), ctx) {
            return Ok(None);
        }
        self.values.get(&key)
    }
}

impl<T: Storable> Message<Delete<T>> for MockStorageActor {
    type Reply = Result<()>;

    async fn handle(
        &mut self,
        Delete { key }: Delete<T>,
        _ctx: &mut Context<Self, Self::Reply>,
    ) -> Self::Reply {
        self.values.delete::<T>(&key);
        Ok(())
    }
}

impl<T: Storable> Message<GetRange<T>> for MockStorageActor {
    type Reply = Result<Vec<(T::Key, T)>>;

    async fn handle(
        &mut self,
        GetRange { start, end, limit }: GetRange<T>,
        ctx: &mut Context<Self, Self::Reply>,
    ) -> Self::Reply {
        let stall_key = match &start {
            RangeStart::At(key) => Some(key.as_ref()),
            RangeStart::First | RangeStart::After(_) => None,
        };
        if self.stall::<T, _>(stall_key, ctx) {
            return Ok(Vec::new());
        }
        self.values
            .read_range(start_key(&start), end.as_ref(), limit)
    }
}

impl<T: Storable> Message<GetFirst<T>> for MockStorageActor {
    type Reply = Result<Option<(T::Key, T)>>;

    async fn handle(
        &mut self,
        _msg: GetFirst<T>,
        _ctx: &mut Context<Self, Self::Reply>,
    ) -> Self::Reply {
        Ok(self.values.read_range(None, None, 1)?.pop())
    }
}

impl<T: Storable> Message<GetLast<T>> for MockStorageActor {
    type Reply = Result<Option<(T::Key, T)>>;

    async fn handle(
        &mut self,
        _msg: GetLast<T>,
        _ctx: &mut Context<Self, Self::Reply>,
    ) -> Self::Reply {
        self.values.last()
    }
}

impl<T: Storable> Message<Count<T>> for MockStorageActor {
    type Reply = Result<usize>;

    async fn handle(
        &mut self,
        _msg: Count<T>,
        _ctx: &mut Context<Self, Self::Reply>,
    ) -> Self::Reply {
        Ok(self.values.count::<T>())
    }
}

impl<W: Writes> Message<WriteBatch<W>> for MockStorageActor {
    type Reply = Result<()>;

    async fn handle(
        &mut self,
        WriteBatch(writes): WriteBatch<W>,
        _ctx: &mut Context<Self, Self::Reply>,
    ) -> Self::Reply {
        self.values.write(&writes)
    }
}

impl Message<Replace<Self>> for MockStorageActor {
    type Reply = ReplaceReply<Self>;

    async fn handle(
        &mut self,
        Replace { mock }: Replace<Self>,
        _ctx: &mut Context<Self, Self::Reply>,
    ) -> Self::Reply {
        let old_mock = std::mem::replace(self, mock);
        ReplaceReply { old_mock }
    }
}

impl Message<DumpDb> for MockStorageActor {
    type Reply = Result<DbDump>;

    async fn handle(&mut self, msg: DumpDb, ctx: &mut Context<Self, Self::Reply>) -> Self::Reply {
        self.handle_dump_db(msg, ctx)
    }
}

impl Message<Checkpoint> for MockStorageActor {
    type Reply = ();

    async fn handle(
        &mut self,
        Checkpoint: Checkpoint,
        _ctx: &mut Context<Self, Self::Reply>,
    ) -> Self::Reply {
        self.checkpoint();
    }
}
