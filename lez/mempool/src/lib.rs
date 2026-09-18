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

pub struct MemPool<T> {
    receiver: Receiver<T>,
    front_buffer: Vec<T>,
    /// Every item the pool holds, in the channel or not.
    ///
    /// [`MemPoolHandle`] reserves a slot here before sending, so admission is one atomic op.
    len: Arc<AtomicUsize>,
}

impl<T> MemPool<T> {
    #[must_use]
    pub fn new(max_size: usize) -> (Self, MemPoolHandle<T>) {
        let (sender, receiver) = tokio::sync::mpsc::channel(max_size);

        let len = Arc::new(AtomicUsize::new(0));
        let mem_pool = Self {
            receiver,
            front_buffer: Vec::new(),
            len: Arc::clone(&len),
        };
        let sender = MemPoolHandle { sender, len };
        (mem_pool, sender)
    }

    /// Returns the total number of items in the mempool, including both the front buffer and the
    /// channel.
    #[must_use]
    pub fn len(&self) -> usize {
        self.front_buffer.len().saturating_add(self.receiver.len())
    }

    /// Returns true if the mempool is empty, false otherwise.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.front_buffer.is_empty() && self.receiver.is_empty()
    }

    /// Pop an item from the mempool first checking the front buffer (LIFO) then the channel (FIFO).
    pub fn pop(&mut self) -> Option<T> {
        // First check if there are any items in the front buffer (LIFO),
        // otherwise try to receive from the channel (FIFO)
        let item = self.front_buffer.pop().or_else(|| self.try_recv())?;
        self.len.fetch_sub(1, Ordering::Relaxed);
        Some(item)
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

    /// Push an item to the front of the mempool (will be popped first).
    pub fn push_front(&mut self, item: T) {
        self.front_buffer.push(item);
        self.len.fetch_add(1, Ordering::Relaxed);
    }

    /// Reorders everything held so that `pop` yields the best item first.
    ///
    /// The logic is based on Kahn's algorithm with a priority heap.
    /// We think of lanes as the edges, and items as the nodes in a DAG.
    ///
    /// Time O(n log n + e·k), space O(n + e):
    /// - `n`: number of items, roughly bounded by the mempool's `max_size`
    /// - `e`: total lane memberships (the edges)
    /// - `k`: most lanes any one item has; bounded, as witness count is capped only by tx size
    ///
    /// The ordering is based on:
    /// - `priority`: the bid of an item; higher pops first, ties go to the earlier arrival.
    /// - `lanes_of`: the lanes an item belongs to (one per signer `nonce` sequence). Items sharing
    ///   a lane keep their arrival order: an item is ready only once it heads every lane it is in.
    ///   If it doesn't belong to any lane, it's already ready.
    pub fn prioritize<K: Ord, G: Hash + Eq + Clone>(
        &mut self,
        priority: impl Fn(&T) -> K,
        lanes_of: impl Fn(&T) -> Vec<G>,
    ) {
        let mut items: Vec<Option<(Vec<G>, T)>> = Vec::new();
        // per lane, item indices in arrival order; only the front is eligible
        let mut lanes: HashMap<G, VecDeque<usize>> = HashMap::new();

        // we read & order and fill the pool again, `len` is not touched,
        // so we do not use `pop` here
        let in_buffer = std::mem::take(&mut self.front_buffer).into_iter().rev();
        let in_channel = std::iter::from_fn(|| self.try_recv());
        for (arrival, item) in in_buffer.chain(in_channel).enumerate() {
            let groups = lanes_of(&item);
            for group in &groups {
                lanes.entry(group.clone()).or_default().push_back(arrival);
            }
            items.push(Some((groups, item)));
        }

        // ready items: highest bid first (`K`), earlier arrival breaks ties (`Reverse<usize>`)
        let mut ready: BinaryHeap<(K, Reverse<usize>)> = BinaryHeap::new();
        // an item is enqueued exactly once, however many lanes report it
        let mut queued = vec![false; items.len()];
        // items to check: every item on the first pass, then the new lane heads
        let mut candidates: Vec<usize> = (0..items.len()).collect();
        let mut ordered = Vec::with_capacity(items.len());
        loop {
            for i in candidates {
                let (groups, item) = items[i].as_ref().expect("candidates are unpicked");
                // if its not queued already & its the front of all lanes its part of, its ready
                if !queued[i] && groups.iter().all(|group| lanes[group].front() == Some(&i)) {
                    queued[i] = true;
                    ready.push((priority(item), Reverse(i)));
                }
            }
            let Some((_, Reverse(best))) = ready.pop() else {
                break; // no more candidates
            };

            let (groups, item) = items[best].take().expect("an item is picked once");
            for group in &groups {
                lanes.get_mut(group).expect("registered lane").pop_front();
            }
            // whatever now heads those lanes may have become ready
            candidates = groups
                .iter()
                .filter_map(|group| lanes[group].front().copied())
                .collect();

            ordered.push(item);
        }

        // `pop` takes from the end.
        ordered.reverse();
        self.front_buffer = ordered;
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

    #[test]
    async fn mempool_new() {
        let (mut pool, _handle): (MemPool<u64>, _) = MemPool::new(10);
        assert_eq!(pool.pop(), None);
        assert_eq!(pool.len(), 0);
    }

    #[test]
    async fn push_and_pop() {
        let (mut pool, handle) = MemPool::new(10);

        handle.push(1).await.unwrap();
        assert_eq!(pool.len(), 1);

        let item = pool.pop();
        assert_eq!(item, Some(1));
        assert_eq!(pool.pop(), None);
        assert_eq!(pool.len(), 0);
    }

    #[test]
    async fn multiple_push_pop() {
        let (mut pool, handle) = MemPool::new(10);

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
    async fn prioritize_pops_highest_first_then_arrival_order() {
        let (mut pool, handle) = MemPool::new(10);

        // (priority, tag), every item in its own lane
        handle.push((1, 'b')).await.unwrap();
        handle.push((5, 'c')).await.unwrap();
        handle.push((1, 'd')).await.unwrap();
        pool.push_front((1, 'a'));

        pool.prioritize(|&(priority, _)| priority, |&(_, tag)| vec![tag]);
        let order: Vec<char> = std::iter::from_fn(|| pool.pop())
            .map(|(_, tag)| tag)
            .collect();
        assert_eq!(order, vec!['c', 'a', 'b', 'd']);
    }

    #[test]
    async fn prioritize_never_reorders_a_lane_and_waits_on_every_lane() {
        let (mut pool, handle) = MemPool::new(10);

        // (priority, lanes, tag): `p` is in no lane; alice's tipped `a1` waits
        // behind `a0`; the sponsored `s` is in both lanes and waits behind
        // `a0` even though bob's lane is free; `b0` waits behind `s`.
        handle.push((0, vec![], "p")).await.unwrap();
        handle.push((0, vec!['A'], "a0")).await.unwrap();
        handle.push((5, vec!['A'], "a1")).await.unwrap();
        handle.push((9, vec!['A', 'B'], "s")).await.unwrap();
        handle.push((3, vec!['B'], "b0")).await.unwrap();

        pool.prioritize(|&(priority, _, _)| priority, |(_, lanes, _)| lanes.clone());
        let order: Vec<&str> = std::iter::from_fn(|| pool.pop())
            .map(|(_, _, tag)| tag)
            .collect();
        assert_eq!(order, vec!["p", "a0", "a1", "s", "b0"]);
    }

    #[test]
    async fn prioritize_enqueues_an_item_once_however_many_lanes_report_it() {
        let (mut pool, handle) = MemPool::new(10);

        // `y` becomes the head of both lanes at once when `x` is picked;
        // `z` names the same lane twice.
        handle.push((1, vec!['A', 'B'], "x")).await.unwrap();
        handle.push((2, vec!['A', 'B'], "y")).await.unwrap();
        handle.push((3, vec!['A', 'A'], "z")).await.unwrap();

        pool.prioritize(|&(priority, _, _)| priority, |(_, lanes, _)| lanes.clone());
        let order: Vec<&str> = std::iter::from_fn(|| pool.pop())
            .map(|(_, _, tag)| tag)
            .collect();
        assert_eq!(order, vec!["x", "y", "z"]);
    }

    #[test]
    async fn try_push_counts_what_prioritize_moved_out_of_the_channel() {
        let (mut pool, handle) = MemPool::new(2);

        handle.try_push(1).unwrap();
        handle.try_push(2).unwrap();
        pool.prioritize(|&item| item, |&item| vec![item]);

        // The channel is empty again, but the pool is still full.
        assert!(handle.try_push(3).is_err());
        assert_eq!(pool.pop(), Some(2));
        handle.try_push(3).unwrap();
        assert_eq!(pool.len(), 2);
    }

    #[test]
    async fn a_cancelled_push_does_not_leak_a_slot() {
        let (mut pool, handle) = MemPool::new(1);
        handle.push(1).await.unwrap();

        // the channel is full, so this push parks; drop it mid-wait
        assert!(handle.push(2).now_or_never().is_none());

        assert_eq!(pool.pop(), Some(1));
        handle.try_push(3).unwrap();
    }

    #[test]
    async fn max_size() {
        let (_pool, handle) = MemPool::new(2);

        handle.push(1).await.unwrap();
        handle.push(2).await.unwrap();

        // This should block if buffer is full
        assert_eq!(handle.push(3).now_or_never(), None);
    }

    #[test]
    async fn try_push_fails_when_full_without_blocking() {
        let (mut pool, handle) = MemPool::new(1);

        handle.try_push(1).unwrap();
        assert!(handle.try_push(2).is_err(), "full mempool must not accept");

        // Popping frees capacity again.
        assert_eq!(pool.pop(), Some(1));
        handle.try_push(2).unwrap();
        assert_eq!(pool.pop(), Some(2));
    }

    #[test]
    async fn push_front() {
        let (mut pool, handle) = MemPool::new(10);

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
