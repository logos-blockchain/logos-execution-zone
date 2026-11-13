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
/// `lanes_of` and `priority` run once per item.
///
/// A pop costs O(k·(k + log n)), `k` being the lanes of the popped item and `n` the ready items.
pub struct MemPool<T, K = (), G = ()> {
    receiver: Receiver<T>,
    handle: MemPoolHandle<T>,
    priority: fn(&T) -> K,
    lanes_of: fn(&T) -> Vec<G>,
    /// Items given back with [`Self::push_front`]; popped before anything else, last in first out.
    front: Vec<T>,
    /// Arrival numbers, counting up; every lane is sorted by them.
    next_arrival: u64,
    items: HashMap<u64, Entry<T, G>>,
    /// Per lane, arrivals in order; only the front is eligible.
    lanes: HashMap<G, VecDeque<u64>>,
    /// Ready items: highest bid first, earlier arrival breaks ties.
    ready: BinaryHeap<(K, Reverse<u64>)>,
    /// Every item the pool holds, in the channel or not.
    ///
    /// [`MemPoolHandle`] reserves a slot here before sending, so admission is one atomic op.
    len: Arc<AtomicUsize>,
}

impl<T> MemPool<T> {
    /// A pool with no priorities nor lanes, simple arrival order (FIFO).
    #[must_use]
    pub fn new_fifo(max_size: usize) -> Self {
        Self::new(max_size, |_| (), |_| Vec::new())
    }
}

impl<T, K: Ord, G: Hash + Eq + Clone> MemPool<T, K, G> {
    #[must_use]
    pub fn new(max_size: usize, priority: fn(&T) -> K, lanes_of: fn(&T) -> Vec<G>) -> Self {
        let (sender, receiver) = tokio::sync::mpsc::channel(max_size);

        let len = Arc::new(AtomicUsize::new(0));
        Self {
            receiver,
            handle: MemPoolHandle {
                sender,
                len: Arc::clone(&len),
            },
            priority,
            lanes_of,
            front: Vec::new(),
            next_arrival: 0,
            items: HashMap::new(),
            lanes: HashMap::new(),
            ready: BinaryHeap::new(),
            len,
        }
    }

    #[must_use]
    pub const fn handle(&self) -> &MemPoolHandle<T> {
        &self.handle
    }

    /// Returns the total number of items in the mempool, received, pushed to front, or still in the
    /// channel: the same count admission checks.
    #[must_use]
    pub fn len(&self) -> usize {
        self.len.load(Ordering::Relaxed)
    }

    /// Returns true if the mempool is empty, false otherwise.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Pop what was given back first, then the ready item with the highest priority.
    pub fn pop(&mut self) -> Option<T> {
        // pop the front, if any
        if let Some(item) = self.front.pop() {
            self.len.fetch_sub(1, Ordering::Relaxed);
            return Some(item);
        }

        // ingest from channel to `self.items`
        self.ingest();

        // pop w.r.t priority
        let (_, Reverse(arrival)) = self.ready.pop()?;
        let entry = self.items.remove(&arrival).expect("ready items are held");
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

    /// Give a popped item back; it pops before anything else, whatever its priority.
    ///
    /// Only for items that were popped from this pool: they were ahead of everything in their
    /// lanes then, so lane order holds as long as they go first. Several given back pop last in
    /// first out, so hand a batch back in reverse.
    pub fn push_front(&mut self, item: T) {
        self.front.push(item);
        self.len.fetch_add(1, Ordering::Relaxed);
    }

    /// Moves everything out of the channel.
    ///
    /// Note that `len` already counts these.
    fn ingest(&mut self) {
        while let Some(item) = self.try_recv() {
            let arrival = self.next_arrival;
            self.next_arrival = arrival.saturating_add(1);
            self.insert(arrival, item);
        }
    }

    fn insert(&mut self, arrival: u64, item: T) {
        let lanes = (self.lanes_of)(&item);
        for lane in &lanes {
            self.lanes
                .entry(lane.clone())
                .or_default()
                .push_back(arrival);
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
    fn is_ready(&self, arrival: u64) -> bool {
        self.items.get(&arrival).is_some_and(|entry| {
            entry
                .lanes
                .iter()
                .all(|lane| self.lanes.get(lane).and_then(VecDeque::front) == Some(&arrival))
        })
    }

    fn enqueue_if_ready(&mut self, arrival: u64) {
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
    /// Send an item to the mempool, failing _immediately_ if it is full: the
    /// bound counts what the pool already holds, not just the channel.
    pub fn try_push(&self, item: T) -> Result<(), tokio::sync::mpsc::error::TrySendError<T>> {
        // reserve the slot first: the pool can never exceed `max_size` this way
        if self.len.fetch_add(1, Ordering::Relaxed) >= self.sender.max_capacity() {
            self.len.fetch_sub(1, Ordering::Relaxed);
            return Err(tokio::sync::mpsc::error::TrySendError::Full(item));
        }
        // every channel item is counted, so this fails only when closed; undo
        // the slot
        self.sender.try_send(item).inspect_err(|_| {
            self.len.fetch_sub(1, Ordering::Relaxed);
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// An item as `(priority, lanes, tag)`.
    type Laned = (u32, Vec<char>, &'static str);

    fn laned_pool() -> MemPool<Laned, u32, char> {
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
    fn mempool_new() {
        let mut pool = MemPool::<u64>::new_fifo(10);
        assert_eq!(pool.pop(), None);
        assert_eq!(pool.len(), 0);
    }

    #[test]
    fn push_and_pop() {
        let mut pool = MemPool::new_fifo(10);
        let handle = pool.handle().clone();

        handle.try_push(1).unwrap();
        assert_eq!(pool.len(), 1);

        let item = pool.pop();
        assert_eq!(item, Some(1));
        assert_eq!(pool.pop(), None);
        assert_eq!(pool.len(), 0);
    }

    #[test]
    fn multiple_push_pop() {
        let mut pool = MemPool::new_fifo(10);
        let handle = pool.handle().clone();

        handle.try_push(1).unwrap();
        handle.try_push(2).unwrap();
        handle.try_push(3).unwrap();

        assert_eq!(pool.len(), 3);
        assert_eq!(pool.pop(), Some(1));
        assert_eq!(pool.pop(), Some(2));
        assert_eq!(pool.pop(), Some(3));
        assert_eq!(pool.pop(), None);
        assert_eq!(pool.len(), 0);
    }

    #[test]
    fn pops_highest_first_then_arrival_order() {
        let mut pool = laned_pool();
        let handle = pool.handle().clone();

        // every item in its own lane
        handle.try_push((1, vec!['b'], "b")).unwrap();
        handle.try_push((5, vec!['c'], "c")).unwrap();
        handle.try_push((1, vec!['d'], "d")).unwrap();

        assert_eq!(drain(&mut pool), vec!["c", "b", "d"]);
    }

    #[test]
    fn never_reorders_a_lane_and_waits_on_every_lane() {
        let mut pool = laned_pool();
        let handle = pool.handle().clone();

        // `p` is in no lane; alice's tipped `a1` waits behind `a0`; the
        // sponsored `s` is in both lanes and waits behind `a0` even though
        // bob's lane is free; `b0` waits behind `s`.
        handle.try_push((0, vec![], "p")).unwrap();
        handle.try_push((0, vec!['A'], "a0")).unwrap();
        handle.try_push((5, vec!['A'], "a1")).unwrap();
        handle.try_push((9, vec!['A', 'B'], "s")).unwrap();
        handle.try_push((3, vec!['B'], "b0")).unwrap();

        assert_eq!(drain(&mut pool), vec!["p", "a0", "a1", "s", "b0"]);
    }

    #[test]
    fn enqueues_an_item_once_however_many_lanes_report_it() {
        let mut pool = laned_pool();
        let handle = pool.handle().clone();

        // `y` becomes the head of both lanes at once when `x` is picked;
        // `z` names the same lane twice.
        handle.try_push((1, vec!['A', 'B'], "x")).unwrap();
        handle.try_push((2, vec!['A', 'B'], "y")).unwrap();
        handle.try_push((3, vec!['A', 'A'], "z")).unwrap();

        assert_eq!(drain(&mut pool), vec!["x", "y", "z"]);
    }

    #[test]
    fn push_front_pops_before_any_tip_and_ahead_of_its_lane() {
        let mut pool = laned_pool();
        let handle = pool.handle().clone();

        handle.try_push((0, vec!['A'], "a0")).unwrap();
        handle.try_push((5, vec!['A'], "a1")).unwrap();
        handle.try_push((9, vec!['H'], "h")).unwrap();

        // popping `h` then `a0` made the better-paying `a1` ready; the two
        // given back (in reverse) must still pop first and in order
        let h = pool.pop().unwrap();
        let a0 = pool.pop().unwrap();
        assert_eq!((h.2, a0.2), ("h", "a0"));
        pool.push_front(a0);
        pool.push_front(h);

        assert_eq!(drain(&mut pool), vec!["h", "a0", "a1"]);
        assert!(pool.lanes.is_empty(), "drained lanes are dropped");
    }

    #[test]
    fn orders_what_arrives_between_pops() {
        let mut pool = laned_pool();
        let handle = pool.handle().clone();

        handle.try_push((1, vec![], "low")).unwrap();
        handle.try_push((2, vec![], "mid")).unwrap();
        assert_eq!(pool.pop().unwrap().2, "mid");

        handle.try_push((9, vec![], "late")).unwrap();
        assert_eq!(drain(&mut pool), vec!["late", "low"]);
    }

    #[test]
    fn try_push_counts_what_pop_moved_out_of_the_channel() {
        let mut pool = MemPool::new(2, |&item: &u32| item, |_| Vec::<()>::new());
        let handle = pool.handle().clone();

        handle.try_push(1).unwrap();
        handle.try_push(2).unwrap();
        assert_eq!(pool.pop(), Some(2));

        // The channel is empty again, but the pool still holds one.
        handle.try_push(3).unwrap();
        assert!(handle.try_push(4).is_err());
        assert_eq!(pool.len(), 2);
    }

    #[test]
    fn try_push_fails_when_full_without_blocking() {
        let mut pool = MemPool::new_fifo(1);
        let handle = pool.handle().clone();

        handle.try_push(1).unwrap();
        assert!(handle.try_push(2).is_err(), "full mempool must not accept");

        // Popping frees capacity again.
        assert_eq!(pool.pop(), Some(1));
        handle.try_push(2).unwrap();
        assert_eq!(pool.pop(), Some(2));
    }

    #[test]
    fn push_front() {
        let mut pool = MemPool::new_fifo(10);
        let handle = pool.handle().clone();

        handle.try_push(1).unwrap();
        handle.try_push(2).unwrap();

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
