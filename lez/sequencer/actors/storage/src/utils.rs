//! Helpers over the storage protocol.

use kameo::{actor::ActorRef, error::SendError, message::Message};

use crate::{
    Result, Storable,
    error::Error,
    protocol::{GetRange, RangeStart},
};

/// The values of `T` with their keys, from a start key to an end key, in key order, read a page at
/// a time.
pub struct Pages<'storage, A: Message<GetRange<T>>, T: Storable> {
    storage_ref: &'storage ActorRef<A>,
    /// Where the next page starts. `None` past the last page.
    next_start: Option<RangeStart<T>>,
    end: Option<T::Key>,
    page_size: usize,
}

impl<'storage, A, T> Pages<'storage, A, T>
where
    A: Message<GetRange<T>, Reply = Result<Vec<(T::Key, T)>>>,
    T: Storable<Key: Clone>,
{
    /// From `start` to `end`, both included if stored, `page_size` values a page. `None` starts
    /// from the first key, or stops at the last one.
    pub fn new(
        storage_ref: &'storage ActorRef<A>,
        start: Option<T::Key>,
        end: Option<T::Key>,
        page_size: usize,
    ) -> Self {
        Self {
            storage_ref,
            next_start: Some(start.map_or(RangeStart::First, RangeStart::At)),
            end,
            page_size,
        }
    }

    /// The next page, `None` past the last one.
    pub async fn next(
        &mut self,
    ) -> std::result::Result<Option<Vec<(T::Key, T)>>, SendError<GetRange<T>, Error>> {
        let Some(start) = self.next_start.take() else {
            return Ok(None);
        };
        let entries = self
            .storage_ref
            .ask(GetRange {
                start,
                end: self.end.clone(),
                limit: self.page_size,
            })
            .await?;
        // A page short of full holds the last values.
        if entries.len() == self.page_size {
            self.next_start = entries
                .last()
                .map(|(key, _value)| RangeStart::After(key.clone()));
        }
        Ok((!entries.is_empty()).then_some(entries))
    }
}
