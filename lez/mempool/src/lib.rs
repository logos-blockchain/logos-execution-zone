use std::{
    cmp::Reverse,
    collections::{HashMap, VecDeque},
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
    /// `front_buffer.len()`, shared with [`MemPoolHandle`].
    held: Arc<AtomicUsize>,
}

impl<T> MemPool<T> {
    #[must_use]
    pub fn new(max_size: usize) -> (Self, MemPoolHandle<T>) {
        let (sender, receiver) = tokio::sync::mpsc::channel(max_size);

        let held = Arc::new(AtomicUsize::new(0));
        let mem_pool = Self {
            receiver,
            front_buffer: Vec::new(),
            held: Arc::clone(&held),
        };
        let sender = MemPoolHandle { sender, held };
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
        use tokio::sync::mpsc::error::TryRecvError;

        // First check if there are any items in the front buffer (LIFO)
        if let Some(item) = self.front_buffer.pop() {
            self.held.fetch_sub(1, Ordering::Relaxed);
            return Some(item);
        }

        // Otherwise, try to receive from the channel (FIFO)

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
        self.held.fetch_add(1, Ordering::Relaxed);
    }

    /// Reorders everything held so that `pop` yields the best item first.
    ///
    /// - `priority`: the bid of an item; higher pops first, ties go to the earlier arrival.
    /// - `lanes_of`: the lanes an item belongs to (one per signer `nonce` sequence). Items sharing
    ///   a lane keep their arrival order: an item is ready only once it heads every lane it is in.
    ///   No lanes would mean it is always ready.
    pub fn prioritize<K: Ord, G: Hash + Eq + Clone>(
        &mut self,
        priority: impl Fn(&T) -> K,
        lanes_of: impl Fn(&T) -> Vec<G>,
    ) {
        // priority-ordered topological sort: lanes are the edges, `items` are the nodes
        let mut items: Vec<Option<(K, Vec<G>, T)>> = Vec::new();
        // per lane, item indices in arrival order; the front is the only one eligible
        let mut lanes: HashMap<G, VecDeque<usize>> = HashMap::new();
        // loose items are those in no lane: always eligible
        let mut loose: Vec<usize> = Vec::new();
        for (arrival, item) in std::iter::from_fn(|| self.pop()).enumerate() {
            let groups = lanes_of(&item);
            if groups.is_empty() {
                loose.push(arrival);
            }
            for group in &groups {
                lanes.entry(group.clone()).or_default().push_back(arrival);
            }
            items.push(Some((priority(&item), groups, item)));
        }

        // O(n * k) head scan per pick
        let mut ordered = Vec::with_capacity(items.len());
        loop {
            // candidates: every lane front + the loose items
            let heads = lanes.values().filter_map(|lane| lane.front().copied());
            let Some(best) = heads
                .chain(loose.iter().copied())
                // ready if it also fronts every other lane it is in
                .filter(|&i| {
                    let (_, groups, _) = items[i].as_ref().expect("unpicked items are present");
                    groups.iter().all(|group| lanes[group].front() == Some(&i))
                })
                // highest bid wins; earlier arrival breaks ties
                .max_by_key(|&i| {
                    let (bid, _, _) = items[i].as_ref().expect("unpicked items are present");
                    (bid, Reverse(i))
                })
            else {
                // no eligible candidates left
                break;
            };

            let (_, groups, item) = items[best].take().expect("an item is picked once");
            for group in &groups {
                lanes.get_mut(group).expect("registered lane").pop_front();
            }
            if groups.is_empty() {
                loose.retain(|&i| i != best);
            }
            ordered.push(item);
        }

        // `pop` takes from the end.
        ordered.reverse();
        self.held.store(ordered.len(), Ordering::Relaxed);
        self.front_buffer = ordered;
    }
}

pub struct MemPoolHandle<T> {
    sender: Sender<T>,
    held: Arc<AtomicUsize>,
}

impl<T> Clone for MemPoolHandle<T> {
    fn clone(&self) -> Self {
        Self {
            sender: self.sender.clone(),
            held: Arc::clone(&self.held),
        }
    }
}

impl<T> MemPoolHandle<T> {
    /// Send an item to the mempool blocking if the channel is full. Bounded by
    /// the channel alone, unlike [`Self::try_push`].
    pub async fn push(&self, item: T) -> Result<(), tokio::sync::mpsc::error::SendError<T>> {
        self.sender.send(item).await
    }

    /// Send an item to the mempool, failing _immediately_ if it is full: the
    /// bound counts what the pool already holds, not just the channel.
    pub fn try_push(&self, item: T) -> Result<(), tokio::sync::mpsc::error::TrySendError<T>> {
        let max_size = self.sender.max_capacity();
        let in_channel = max_size.saturating_sub(self.sender.capacity());
        if self.held.load(Ordering::Relaxed).saturating_add(in_channel) >= max_size {
            return Err(tokio::sync::mpsc::error::TrySendError::Full(item));
        }
        self.sender.try_send(item)
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
