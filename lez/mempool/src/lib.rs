use std::{
    cmp::Reverse,
    collections::{BinaryHeap, HashMap, VecDeque},
    hash::Hash,
};

/// A held item and the lanes it sits in.
struct Entry<T, G> {
    item: T,
    lanes: Vec<G>,
    /// Whether `ready` currently holds it, so it is never enqueued twice.
    queued: bool,
    /// Given back and not yet unparked: it holds its lanes but does not pop.
    parked: bool,
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
    max_size: usize,
    priority: fn(&T) -> K,
    lanes_of: fn(&T) -> Vec<G>,
    /// Arrival numbers: counting up from 0 for inserted items, down from -1 for given back ones,
    /// so every lane is sorted by them.
    next_arrival: i64,
    next_given_back: i64,
    items: HashMap<i64, Entry<T, G>>,
    /// Per lane, arrivals in order; only the front is eligible.
    lanes: HashMap<G, VecDeque<i64>>,
    /// Ready items: given back ones first, then the highest bid, earlier arrival breaks ties.
    ///
    /// An entry goes stale when an item is given back ahead of it in a lane; [`Self::pop`] skips
    /// those.
    ready: BinaryHeap<(bool, K, Reverse<i64>)>,
    /// Given back items waiting for [`Self::unpark`].
    parked: Vec<i64>,
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
        Self {
            max_size,
            priority,
            lanes_of,
            next_arrival: 0,
            next_given_back: -1,
            items: HashMap::new(),
            lanes: HashMap::new(),
            ready: BinaryHeap::new(),
            parked: Vec::new(),
        }
    }

    /// Returns the number of items the pool holds, parked ones included.
    #[must_use]
    pub fn len(&self) -> usize {
        self.items.len()
    }

    /// Returns true if the mempool is empty, false otherwise.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.items.is_empty()
    }

    /// Adds an item behind everything in its lanes, handing it back if the pool is full.
    pub fn insert(&mut self, item: T) -> Result<(), T> {
        if self.len() >= self.max_size {
            return Err(item);
        }
        let arrival = self.next_arrival;
        self.next_arrival = arrival.saturating_add(1);
        self.add(arrival, item, false);
        Ok(())
    }

    /// Gives an item back ahead of everything in its lanes, past the size bound. It holds its
    /// lanes but does not pop until [`Self::unpark`], then pops before anything inserted.
    ///
    /// Given back items pop among themselves by priority, ties last in first out; within a lane,
    /// the last one given back goes first, so hand a batch back in reverse.
    pub fn give_back(&mut self, item: T) {
        let arrival = self.next_given_back;
        self.next_given_back = arrival.saturating_sub(1);
        self.add(arrival, item, true);
        self.parked.push(arrival);
    }

    /// Lets everything given back pop again.
    pub fn unpark(&mut self) {
        for arrival in std::mem::take(&mut self.parked) {
            if let Some(entry) = self.items.get_mut(&arrival) {
                entry.parked = false;
            }
            self.enqueue_if_ready(arrival);
        }
    }

    /// Pops the ready item that goes first.
    pub fn pop(&mut self) -> Option<T> {
        let arrival = loop {
            let (_, _, Reverse(arrival)) = self.ready.pop()?;
            if self.is_ready(arrival) {
                break arrival;
            }
            if let Some(entry) = self.items.get_mut(&arrival) {
                entry.queued = false;
            }
        };
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

        Some(entry.item)
    }

    fn add(&mut self, arrival: i64, item: T, parked: bool) {
        let lanes = (self.lanes_of)(&item);
        for lane in &lanes {
            let queue = self.lanes.entry(lane.clone()).or_default();
            if parked {
                queue.push_front(arrival);
            } else {
                queue.push_back(arrival);
            }
        }
        let entry = Entry {
            item,
            lanes,
            queued: false,
            parked,
        };
        self.items.insert(arrival, entry);
        self.enqueue_if_ready(arrival);
    }

    /// Whether the item is not parked and heads every lane it is in.
    fn is_ready(&self, arrival: i64) -> bool {
        self.items.get(&arrival).is_some_and(|entry| {
            !entry.parked
                && entry
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
                .push((arrival < 0, (self.priority)(&entry.item), Reverse(arrival)));
        }
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
    fn insert_and_pop_in_arrival_order() {
        let mut pool = MemPool::new_fifo(10);

        pool.insert(1).unwrap();
        pool.insert(2).unwrap();
        pool.insert(3).unwrap();

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

        // every item in its own lane
        pool.insert((1, vec!['b'], "b")).unwrap();
        pool.insert((5, vec!['c'], "c")).unwrap();
        pool.insert((1, vec!['d'], "d")).unwrap();

        assert_eq!(drain(&mut pool), vec!["c", "b", "d"]);
    }

    #[test]
    fn never_reorders_a_lane_and_waits_on_every_lane() {
        let mut pool = laned_pool();

        // `p` is in no lane; alice's tipped `a1` waits behind `a0`; the
        // sponsored `s` is in both lanes and waits behind `a0` even though
        // bob's lane is free; `b0` waits behind `s`.
        pool.insert((0, vec![], "p")).unwrap();
        pool.insert((0, vec!['A'], "a0")).unwrap();
        pool.insert((5, vec!['A'], "a1")).unwrap();
        pool.insert((9, vec!['A', 'B'], "s")).unwrap();
        pool.insert((3, vec!['B'], "b0")).unwrap();

        assert_eq!(drain(&mut pool), vec!["p", "a0", "a1", "s", "b0"]);
    }

    #[test]
    fn enqueues_an_item_once_however_many_lanes_report_it() {
        let mut pool = laned_pool();

        // `y` becomes the head of both lanes at once when `x` is picked;
        // `z` names the same lane twice.
        pool.insert((1, vec!['A', 'B'], "x")).unwrap();
        pool.insert((2, vec!['A', 'B'], "y")).unwrap();
        pool.insert((3, vec!['A', 'A'], "z")).unwrap();

        assert_eq!(drain(&mut pool), vec!["x", "y", "z"]);
    }

    #[test]
    fn orders_what_arrives_between_pops() {
        let mut pool = laned_pool();

        pool.insert((1, vec![], "low")).unwrap();
        pool.insert((2, vec![], "mid")).unwrap();
        assert_eq!(pool.pop().unwrap().2, "mid");

        pool.insert((9, vec![], "late")).unwrap();
        assert_eq!(drain(&mut pool), vec!["late", "low"]);
    }

    #[test]
    fn insert_fails_when_full() {
        let mut pool = MemPool::new_fifo(1);

        pool.insert(1).unwrap();
        assert_eq!(pool.insert(2), Err(2), "full mempool must not accept");

        // Popping frees capacity again.
        assert_eq!(pool.pop(), Some(1));
        pool.insert(2).unwrap();
        assert_eq!(pool.pop(), Some(2));
    }

    #[test]
    fn given_back_items_wait_for_unpark_then_pop_first_in_reverse() {
        let mut pool = MemPool::new_fifo(2);

        pool.insert(1).unwrap();
        pool.insert(2).unwrap();
        // past the bound
        pool.give_back(10);
        pool.give_back(20);
        assert_eq!(pool.len(), 4);

        assert_eq!(pool.pop(), Some(1), "parked items do not pop");
        pool.unpark();
        assert_eq!(pool.pop(), Some(20));
        assert_eq!(pool.pop(), Some(10));
        assert_eq!(pool.pop(), Some(2));
        assert_eq!(pool.pop(), None);
    }

    #[test]
    fn a_parked_item_holds_its_lanes() {
        let mut pool = laned_pool();

        pool.insert((0, vec!['A'], "a0")).unwrap();
        pool.insert((5, vec!['A'], "a1")).unwrap();
        pool.insert((0, vec!['B'], "b0")).unwrap();

        // popping `a0` made `a1` ready; giving `a0` back must block it again
        let a0 = pool.pop().unwrap();
        assert_eq!(a0.2, "a0");
        pool.give_back(a0);
        assert_eq!(drain(&mut pool), vec!["b0"]);

        pool.unpark();
        assert_eq!(drain(&mut pool), vec!["a0", "a1"]);
        assert!(pool.lanes.is_empty(), "drained lanes are dropped");
    }

    #[test]
    fn a_batch_given_back_in_reverse_keeps_its_lane_order() {
        let mut pool = laned_pool();

        pool.insert((0, vec!['A'], "a0")).unwrap();
        pool.insert((5, vec!['A'], "a1")).unwrap();
        pool.insert((9, vec!['H'], "h")).unwrap();
        pool.insert((1, vec!['A'], "a2")).unwrap();

        let taken: Vec<_> = std::iter::from_fn(|| pool.pop()).take(3).collect();
        assert_eq!(
            taken.iter().map(|(_, _, tag)| *tag).collect::<Vec<_>>(),
            vec!["h", "a0", "a1"]
        );
        for item in taken.into_iter().rev() {
            pool.give_back(item);
        }
        pool.unpark();

        assert_eq!(drain(&mut pool), vec!["h", "a0", "a1", "a2"]);
    }
}
