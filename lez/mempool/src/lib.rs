use std::{
    cmp::Reverse,
    collections::{BinaryHeap, HashMap, VecDeque},
    hash::Hash,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
};

use tokio::sync::mpsc::{Receiver, Sender};

/// A held item and the lanes it sits in.
struct Entry<T, G> {
    item: T,
    lanes: Vec<G>,
    /// Whether `ready` currently holds it, so it is never enqueued twice.
    queued: bool,
}

/// A bounded pool that pops the highest `priority` first, without ever
/// reordering a lane.
///
/// - `priority`: the bid of an item; higher pops first, ties go to the earlier arrival.
/// - `lanes_of`: the lanes an item belongs to (one per signer `nonce` sequence). Items sharing a
///   lane keep their arrival order: an item is ready only once it heads every lane it is in. An
///   item in no lane is always ready.
///
/// This is Kahn's algorithm with a priority heap, kept across pops:
/// - items are the nodes of a DAG
/// - lanes are its edges.
///
/// `lanes_of` runs once per item, and so does `priority` unless a `push_front` overtakes the
/// item while it is ready.
///
/// A pop costs O(k·(k + log n)), `k` being the lanes of the popped item and `n` the ready items.
pub struct MemPool<T, K = (), G = ()> {
    receiver: Receiver<T>,
    priority: fn(&T) -> K,
    lanes_of: fn(&T) -> Vec<G>,
    /// Arrival numbers: received items count up from 0, `push_front` counts
    /// down from -1, so every lane stays sorted by arrival.
    next_back: i64,
    next_front: i64,
    items: HashMap<i64, Entry<T, G>>,
    /// Per lane, arrivals in order; only the front is eligible.
    lanes: HashMap<G, VecDeque<i64>>,
    /// Ready items: highest bid first, earlier arrival breaks ties.
    ready: BinaryHeap<(K, Reverse<i64>)>,
    /// Every item the pool holds, in the channel or not.
    ///
    /// [`MemPoolHandle`] reserves a slot here before sending, so admission is one atomic op.
    len: Arc<AtomicUsize>,
}

impl<T> MemPool<T> {
    /// A pool with no priorities nor lanes, simple arrival order (FIFO).
    #[must_use]
    pub fn new_fifo(max_size: usize) -> (Self, MemPoolHandle<T>) {
        Self::new(max_size, |_| (), |_| Vec::new())
    }
}

impl<T, K: Ord, G: Hash + Eq + Clone> MemPool<T, K, G> {
    #[must_use]
    pub fn new(
        max_size: usize,
        priority: fn(&T) -> K,
        lanes_of: fn(&T) -> Vec<G>,
    ) -> (Self, MemPoolHandle<T>) {
        let (sender, receiver) = tokio::sync::mpsc::channel(max_size);

        let len = Arc::new(AtomicUsize::new(0));
        let mem_pool = Self {
            receiver,
            priority,
            lanes_of,
            next_back: 0,
            next_front: 0,
            items: HashMap::new(),
            lanes: HashMap::new(),
            ready: BinaryHeap::new(),
            len: Arc::clone(&len),
        };
        let sender = MemPoolHandle { sender, len };
        (mem_pool, sender)
    }

    /// Returns the total number of items in the mempool, received or still in the channel.
    #[must_use]
    pub fn len(&self) -> usize {
        self.items.len().saturating_add(self.receiver.len())
    }

    /// Returns true if the mempool is empty, false otherwise.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.items.is_empty() && self.receiver.is_empty()
    }

    /// Pop the ready item with the highest priority.
    pub fn pop(&mut self) -> Option<T> {
        self.ingest();

        let entry = loop {
            let (_, Reverse(arrival)) = self.ready.pop()?;
            if self.is_ready(arrival)
                && let Some(entry) = self.items.remove(&arrival)
            {
                break entry;
            }
            // a `push_front` overtook it; it is enqueued again once that item pops
            if let Some(entry) = self.items.get_mut(&arrival) {
                entry.queued = false;
            }
        };

        for lane in &entry.lanes {
            if let Some(queue) = self.lanes.get_mut(lane) {
                queue.pop_front();
                if queue.is_empty() {
                    self.lanes.remove(lane);
                }
            }
        }

        // whatever now heads those lanes may have become ready
        for lane in &entry.lanes {
            if let Some(head) = self
                .lanes
                .get(lane)
                .and_then(|queue| queue.front().copied())
            {
                self.enqueue_if_ready(head);
            }
        }

        self.len.fetch_sub(1, Ordering::Relaxed);
        Some(entry.item)
    }

    /// Put a popped item back at the front of its lanes; it also wins ties.
    pub fn push_front(&mut self, item: T) {
        self.next_front = self.next_front.saturating_sub(1);
        self.insert(self.next_front, item, true);
        self.len.fetch_add(1, Ordering::Relaxed);
    }

    /// Moves everything out of the channel.
    ///
    /// Note that `len` already counts these.
    fn ingest(&mut self) {
        while let Some(item) = self.try_recv() {
            let arrival = self.next_back;
            self.next_back = arrival.saturating_add(1);
            self.insert(arrival, item, false);
        }
    }

    fn insert(&mut self, arrival: i64, item: T, front: bool) {
        let lanes = (self.lanes_of)(&item);
        for lane in &lanes {
            let queue = self.lanes.entry(lane.clone()).or_default();
            if front {
                queue.push_front(arrival);
            } else {
                queue.push_back(arrival);
            }
        }
        let entry = Entry {
            item,
            lanes,
            queued: false,
        };
        self.items.insert(arrival, entry);
        self.enqueue_if_ready(arrival);
    }

    /// Whether the item heads every lane it is in.
    fn is_ready(&self, arrival: i64) -> bool {
        self.items.get(&arrival).is_some_and(|entry| {
            entry
                .lanes
                .iter()
                .all(|lane| self.lanes.get(lane).and_then(VecDeque::front) == Some(&arrival))
        })
    }

    fn enqueue_if_ready(&mut self, arrival: i64) {
        if !self.is_ready(arrival) {
            return;
        }
        if let Some(entry) = self.items.get_mut(&arrival)
            && !std::mem::replace(&mut entry.queued, true)
        {
            self.ready
                .push(((self.priority)(&entry.item), Reverse(arrival)));
        }
    }

    fn try_recv(&mut self) -> Option<T> {
        use tokio::sync::mpsc::error::TryRecvError;

        match self.receiver.try_recv() {
            Ok(item) => Some(item),
            Err(TryRecvError::Empty) => None,
            Err(TryRecvError::Disconnected) => {
                panic!("Mempool senders disconnected, cannot receive items, this is a bug")
            }
        }
    }
}

pub struct MemPoolHandle<T> {
    sender: Sender<T>,
    len: Arc<AtomicUsize>,
}

impl<T> Clone for MemPoolHandle<T> {
    fn clone(&self) -> Self {
        Self {
            sender: self.sender.clone(),
            len: Arc::clone(&self.len),
        }
    }
}

impl<T> MemPoolHandle<T> {
    /// Send an item to the mempool blocking if the channel is full. Bounded by
    /// the channel alone, unlike [`Self::try_push`].
    pub async fn push(&self, item: T) -> Result<(), tokio::sync::mpsc::error::SendError<T>> {
        // `reserve` the slot so that counting and sending happen together,
        // and the entire thing is cancel-safe
        let Ok(permit) = self.sender.reserve().await else {
            return Err(tokio::sync::mpsc::error::SendError(item));
        };
        self.len.fetch_add(1, Ordering::Relaxed);
        permit.send(item);
        Ok(())
    }

    /// Send an item to the mempool, failing _immediately_ if it is full: the
    /// bound counts what the pool already holds, not just the channel.
    pub fn try_push(&self, item: T) -> Result<(), tokio::sync::mpsc::error::TrySendError<T>> {
        // reserve the slot first: the pool can never exceed `max_size` this way
        if self.len.fetch_add(1, Ordering::Relaxed) >= self.sender.max_capacity() {
            self.len.fetch_sub(1, Ordering::Relaxed);
            return Err(tokio::sync::mpsc::error::TrySendError::Full(item));
        }
        // every channel item is counted, so this fails only when closed or when
        // the channel-bounded `push` is also in use; either way undo the slot
        self.sender.try_send(item).inspect_err(|_| {
            self.len.fetch_sub(1, Ordering::Relaxed);
        })
    }
}

#[cfg(test)]
mod tests {
    use futures::FutureExt as _;
    use tokio::test;

    use super::*;

    /// An item as `(priority, lanes, tag)`.
    type Laned = (u32, Vec<char>, &'static str);

    fn laned_pool() -> (MemPool<Laned, u32, char>, MemPoolHandle<Laned>) {
        MemPool::new(
            10,
            |&(priority, _, _)| priority,
            |(_, lanes, _)| lanes.clone(),
        )
    }

    fn drain(pool: &mut MemPool<Laned, u32, char>) -> Vec<&'static str> {
        std::iter::from_fn(|| pool.pop())
            .map(|(_, _, tag)| tag)
            .collect()
    }

    #[test]
    async fn mempool_new() {
        let (mut pool, _handle): (MemPool<u64>, _) = MemPool::new_fifo(10);
        assert_eq!(pool.pop(), None);
        assert_eq!(pool.len(), 0);
    }

    #[test]
    async fn push_and_pop() {
        let (mut pool, handle) = MemPool::new_fifo(10);

        handle.push(1).await.unwrap();
        assert_eq!(pool.len(), 1);

        let item = pool.pop();
        assert_eq!(item, Some(1));
        assert_eq!(pool.pop(), None);
        assert_eq!(pool.len(), 0);
    }

    #[test]
    async fn multiple_push_pop() {
        let (mut pool, handle) = MemPool::new_fifo(10);

        handle.push(1).await.unwrap();
        handle.push(2).await.unwrap();
        handle.push(3).await.unwrap();

        assert_eq!(pool.len(), 3);
        assert_eq!(pool.pop(), Some(1));
        assert_eq!(pool.pop(), Some(2));
        assert_eq!(pool.pop(), Some(3));
        assert_eq!(pool.pop(), None);
        assert_eq!(pool.len(), 0);
    }

    #[test]
    async fn pops_highest_first_then_arrival_order() {
        let (mut pool, handle) = laned_pool();

        // every item in its own lane
        handle.push((1, vec!['b'], "b")).await.unwrap();
        handle.push((5, vec!['c'], "c")).await.unwrap();
        handle.push((1, vec!['d'], "d")).await.unwrap();
        pool.push_front((1, vec!['a'], "a"));

        assert_eq!(drain(&mut pool), vec!["c", "a", "b", "d"]);
    }

    #[test]
    async fn never_reorders_a_lane_and_waits_on_every_lane() {
        let (mut pool, handle) = laned_pool();

        // `p` is in no lane; alice's tipped `a1` waits behind `a0`; the
        // sponsored `s` is in both lanes and waits behind `a0` even though
        // bob's lane is free; `b0` waits behind `s`.
        handle.push((0, vec![], "p")).await.unwrap();
        handle.push((0, vec!['A'], "a0")).await.unwrap();
        handle.push((5, vec!['A'], "a1")).await.unwrap();
        handle.push((9, vec!['A', 'B'], "s")).await.unwrap();
        handle.push((3, vec!['B'], "b0")).await.unwrap();

        assert_eq!(drain(&mut pool), vec!["p", "a0", "a1", "s", "b0"]);
    }

    #[test]
    async fn enqueues_an_item_once_however_many_lanes_report_it() {
        let (mut pool, handle) = laned_pool();

        // `y` becomes the head of both lanes at once when `x` is picked;
        // `z` names the same lane twice.
        handle.push((1, vec!['A', 'B'], "x")).await.unwrap();
        handle.push((2, vec!['A', 'B'], "y")).await.unwrap();
        handle.push((3, vec!['A', 'A'], "z")).await.unwrap();

        assert_eq!(drain(&mut pool), vec!["x", "y", "z"]);
    }

    #[test]
    async fn push_front_goes_back_ahead_of_its_lane() {
        let (mut pool, handle) = laned_pool();

        handle.push((0, vec!['A'], "a0")).await.unwrap();
        handle.push((5, vec!['A'], "a1")).await.unwrap();

        // popping `a0` made the better-paying `a1` ready; putting `a0` back
        // must make it wait again
        let a0 = pool.pop().unwrap();
        assert_eq!(a0.2, "a0");
        pool.push_front(a0);

        assert_eq!(drain(&mut pool), vec!["a0", "a1"]);
        assert!(pool.lanes.is_empty(), "drained lanes are dropped");
    }

    #[test]
    async fn orders_what_arrives_between_pops() {
        let (mut pool, handle) = laned_pool();

        handle.push((1, vec![], "low")).await.unwrap();
        handle.push((2, vec![], "mid")).await.unwrap();
        assert_eq!(pool.pop().unwrap().2, "mid");

        handle.push((9, vec![], "late")).await.unwrap();
        assert_eq!(drain(&mut pool), vec!["late", "low"]);
    }

    #[test]
    async fn try_push_counts_what_pop_moved_out_of_the_channel() {
        let (mut pool, handle) = MemPool::new(2, |&item: &u32| item, |_| Vec::<()>::new());

        handle.try_push(1).unwrap();
        handle.try_push(2).unwrap();
        assert_eq!(pool.pop(), Some(2));

        // The channel is empty again, but the pool still holds one.
        handle.try_push(3).unwrap();
        assert!(handle.try_push(4).is_err());
        assert_eq!(pool.len(), 2);
    }

    #[test]
    async fn a_cancelled_push_does_not_leak_a_slot() {
        let (mut pool, handle) = MemPool::new_fifo(1);
        handle.push(1).await.unwrap();

        // the channel is full, so this push parks; drop it mid-wait
        assert!(handle.push(2).now_or_never().is_none());

        assert_eq!(pool.pop(), Some(1));
        handle.try_push(3).unwrap();
    }

    #[test]
    async fn max_size() {
        let (_pool, handle) = MemPool::new_fifo(2);

        handle.push(1).await.unwrap();
        handle.push(2).await.unwrap();

        // This should block if buffer is full
        assert_eq!(handle.push(3).now_or_never(), None);
    }

    #[test]
    async fn try_push_fails_when_full_without_blocking() {
        let (mut pool, handle) = MemPool::new_fifo(1);

        handle.try_push(1).unwrap();
        assert!(handle.try_push(2).is_err(), "full mempool must not accept");

        // Popping frees capacity again.
        assert_eq!(pool.pop(), Some(1));
        handle.try_push(2).unwrap();
        assert_eq!(pool.pop(), Some(2));
    }

    #[test]
    async fn push_front() {
        let (mut pool, handle) = MemPool::new_fifo(10);

        handle.push(1).await.unwrap();
        handle.push(2).await.unwrap();

        // Push items to the front - these should be popped first
        pool.push_front(10);
        pool.push_front(20);

        // Items pushed to front are popped in LIFO order
        assert_eq!(pool.pop(), Some(20));
        assert_eq!(pool.pop(), Some(10));
        // Original items are then popped in FIFO order
        assert_eq!(pool.pop(), Some(1));
        assert_eq!(pool.pop(), Some(2));
        assert_eq!(pool.pop(), None);
    }
}
