use std::{
    cmp::Reverse,
    collections::{BTreeMap, BinaryHeap, HashMap, HashSet},
    hash::Hash,
    ops::Bound,
};

/// Why [`MemPool::insert`] turned an item away.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Rejected {
    /// The pool already holds `max_size` items.
    Full,
    /// It takes a slot another item holds: the first seen keeps it.
    Occupied,
    /// Its slots would order it both before and after another item, so neither could ever pop.
    Cycle,
}

/// A held item and the lane slots it takes.
struct Entry<T, G, N> {
    item: T,
    slots: Vec<(G, N)>,
    /// Whether `ready` currently holds it, so it is never enqueued twice.
    queued: bool,
    /// Given back and not yet unparked: it holds its slots but does not pop.
    parked: bool,
}

/// A bounded pool that pops the highest `priority` first, without ever
/// reordering a lane.
///
/// - `priority`: the bid of an item; higher pops first, ties go to the earlier arrival.
/// - `slots_of`: the lane slots an item takes (one per signer, at its `nonce`). A lane pops in slot
///   order: an item is ready only once it holds the first slot of every lane it is in. An item in
///   no lane is always ready.
///
/// This is Kahn's algorithm with a priority heap, kept across pops:
/// - items are the nodes of a DAG
/// - lanes are its edges.
///
/// A pop costs O(k·(k + log n)), `k` being the lanes of the popped item and `n` the ready items.
pub struct MemPool<T, K = (), G = (), N = ()> {
    max_size: usize,
    priority: fn(&T) -> K,
    slots_of: fn(&T) -> Vec<(G, N)>,
    /// Arrival numbers: counting up from 0 for inserted items, down from -1 for given back ones.
    next_arrival: i64,
    next_given_back: i64,
    items: HashMap<i64, Entry<T, G, N>>,
    /// Per lane, arrivals by slot; only the first is eligible.
    lanes: HashMap<G, BTreeMap<N, i64>>,
    /// Ready items: given back ones first, then the highest bid, earlier arrival breaks ties.
    ///
    /// An entry goes stale when an item takes a slot ahead of it, or is removed; [`Self::pop`]
    /// skips those.
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

impl<T, K: Ord, G: Hash + Eq + Clone, N: Ord + Clone> MemPool<T, K, G, N> {
    #[must_use]
    pub fn new(max_size: usize, priority: fn(&T) -> K, slots_of: fn(&T) -> Vec<(G, N)>) -> Self {
        Self {
            max_size,
            priority,
            slots_of,
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

    /// The item holding slot `at` of `lane`.
    #[must_use]
    pub fn get(&self, lane: &G, at: &N) -> Option<&T> {
        let arrival = self.lanes.get(lane)?.get(at)?;
        self.items.get(arrival).map(|entry| &entry.item)
    }

    /// The slots of `lane` held from `from` on.
    #[must_use]
    pub fn lane_len(&self, lane: &G, from: &N) -> usize {
        self.lanes
            .get(lane)
            .map_or(0, |queue| queue.range(from..).count())
    }

    /// Adds an item at its slots, if no other item holds any of them.
    pub fn insert(&mut self, item: T) -> Result<(), Rejected> {
        let slots = (self.slots_of)(&item);
        if !self.holders(&slots).is_empty() {
            return Err(Rejected::Occupied);
        }
        if self.len() >= self.max_size {
            return Err(Rejected::Full);
        }
        if self.closes_cycle(&slots, &[]) {
            return Err(Rejected::Cycle);
        }
        let arrival = self.next_arrival;
        self.next_arrival = arrival.saturating_add(1);
        self.add(arrival, item, slots, false);
        Ok(())
    }

    /// Gives an item back past the size bound, replacing whatever holds its slots. It holds them
    /// but does not pop until [`Self::unpark`], then pops before anything inserted. Dropped if it
    /// would close a cycle.
    ///
    /// Given back items pop among themselves by priority, ties last in first out, so hand a batch
    /// back in reverse.
    pub fn give_back(&mut self, item: T) {
        let slots = (self.slots_of)(&item);
        let holders = self.holders(&slots);
        if self.closes_cycle(&slots, &holders) {
            return;
        }
        for arrival in holders {
            self.remove(arrival);
        }
        let arrival = self.next_given_back;
        self.next_given_back = arrival.saturating_sub(1);
        self.add(arrival, item, slots, true);
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
        self.remove(arrival)
    }

    fn add(&mut self, arrival: i64, item: T, slots: Vec<(G, N)>, parked: bool) {
        for (lane, at) in &slots {
            self.lanes
                .entry(lane.clone())
                .or_default()
                .insert(at.clone(), arrival);
        }
        let entry = Entry {
            item,
            slots,
            queued: false,
            parked,
        };
        self.items.insert(arrival, entry);
        self.enqueue_if_ready(arrival);
    }

    fn remove(&mut self, arrival: i64) -> Option<T> {
        let entry = self.items.remove(&arrival)?;
        for (lane, at) in &entry.slots {
            if let Some(queue) = self.lanes.get_mut(lane) {
                queue.remove(at);
                if queue.is_empty() {
                    self.lanes.remove(lane);
                }
            }
        }

        // whatever now heads those lanes may have become ready
        for (lane, _) in &entry.slots {
            if let Some(head) = self.head(lane) {
                self.enqueue_if_ready(head);
            }
        }

        Some(entry.item)
    }

    fn head(&self, lane: &G) -> Option<i64> {
        self.lanes
            .get(lane)
            .and_then(BTreeMap::first_key_value)
            .map(|(_, &arrival)| arrival)
    }

    /// The items holding any of `slots`, each once.
    fn holders(&self, slots: &[(G, N)]) -> Vec<i64> {
        let mut holders: Vec<i64> = slots
            .iter()
            .filter_map(|(lane, at)| self.lanes.get(lane)?.get(at).copied())
            .collect();
        holders.sort_unstable();
        holders.dedup();
        holders
    }

    /// Whether an item at `slots`, once `replaced` are gone, would come after something that
    /// comes after it.
    ///
    /// Walks forward from the items behind it, looking for one ahead of it. An item in one lane
    /// cannot close a cycle, so only one in several lanes pays for the walk.
    fn closes_cycle(&self, slots: &[(G, N)], replaced: &[i64]) -> bool {
        if slots.len() < 2 {
            return false;
        }
        let next = |lane: &G, at: &N| {
            self.lanes
                .get(lane)?
                .range((Bound::Excluded(at), Bound::Unbounded))
                .map(|(_, &arrival)| arrival)
                .find(|arrival| !replaced.contains(arrival))
        };
        let mut behind: Vec<i64> = slots
            .iter()
            .filter_map(|(lane, at)| next(lane, at))
            .collect();
        let mut seen = HashSet::new();
        while let Some(arrival) = behind.pop() {
            if !seen.insert(arrival) {
                continue;
            }
            let Some(entry) = self.items.get(&arrival) else {
                continue;
            };
            let ahead = entry.slots.iter().any(|(lane, at)| {
                slots
                    .iter()
                    .any(|(new_lane, new_at)| lane == new_lane && at < new_at)
            });
            if ahead {
                return true;
            }
            behind.extend(entry.slots.iter().filter_map(|(lane, at)| next(lane, at)));
        }
        false
    }

    /// Whether the item is not parked and heads every lane it is in.
    fn is_ready(&self, arrival: i64) -> bool {
        self.items.get(&arrival).is_some_and(|entry| {
            !entry.parked
                && entry
                    .slots
                    .iter()
                    .all(|(lane, _)| self.head(lane) == Some(arrival))
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

    /// An item as `(priority, slots, tag)`.
    type Laned = (u32, Vec<(char, u32)>, &'static str);

    fn laned_pool(max_size: usize) -> MemPool<Laned, u32, char, u32> {
        MemPool::new(
            max_size,
            |&(priority, _, _)| priority,
            |(_, slots, _)| slots.clone(),
        )
    }

    fn drain(pool: &mut MemPool<Laned, u32, char, u32>) -> Vec<&'static str> {
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
        let mut pool = laned_pool(10);

        // every item in its own lane
        pool.insert((1, vec![('b', 0)], "b")).unwrap();
        pool.insert((5, vec![('c', 0)], "c")).unwrap();
        pool.insert((1, vec![('d', 0)], "d")).unwrap();

        assert_eq!(drain(&mut pool), vec!["c", "b", "d"]);
    }

    #[test]
    fn never_reorders_a_lane_and_waits_on_every_lane() {
        let mut pool = laned_pool(10);

        // `p` is in no lane; alice's tipped `a1` waits behind `a0`; the
        // sponsored `s` is in both lanes and waits behind `a0` even though
        // bob's lane is free; `b1` waits behind `s`.
        pool.insert((0, vec![], "p")).unwrap();
        pool.insert((0, vec![('A', 0)], "a0")).unwrap();
        pool.insert((5, vec![('A', 1)], "a1")).unwrap();
        pool.insert((9, vec![('A', 2), ('B', 0)], "s")).unwrap();
        pool.insert((3, vec![('B', 1)], "b1")).unwrap();

        assert_eq!(drain(&mut pool), vec!["p", "a0", "a1", "s", "b1"]);
    }

    #[test]
    fn orders_a_lane_by_slot_not_arrival() {
        let mut pool = laned_pool(10);

        pool.insert((9, vec![('A', 1)], "a1")).unwrap();
        pool.insert((0, vec![('A', 0)], "a0")).unwrap();

        assert_eq!(drain(&mut pool), vec!["a0", "a1"]);
    }

    #[test]
    fn enqueues_an_item_once_however_many_lanes_report_it() {
        let mut pool = laned_pool(10);

        // `y` becomes the head of both lanes at once when `x` is picked
        pool.insert((1, vec![('A', 0), ('B', 0)], "x")).unwrap();
        pool.insert((2, vec![('A', 1), ('B', 1)], "y")).unwrap();
        pool.insert((3, vec![('A', 2)], "z")).unwrap();

        assert_eq!(drain(&mut pool), vec!["x", "y", "z"]);
    }

    #[test]
    fn orders_what_arrives_between_pops() {
        let mut pool = laned_pool(10);

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
        assert_eq!(pool.insert(2), Err(Rejected::Full));

        // Popping frees capacity again.
        assert_eq!(pool.pop(), Some(1));
        pool.insert(2).unwrap();
        assert_eq!(pool.pop(), Some(2));
    }

    #[test]
    fn the_first_item_seen_keeps_its_slot() {
        let mut pool = laned_pool(10);

        pool.insert((1, vec![('A', 0)], "first")).unwrap();
        assert_eq!(
            pool.insert((9, vec![('A', 0), ('B', 0)], "later")),
            Err(Rejected::Occupied)
        );
        pool.insert((1, vec![('A', 1)], "next")).unwrap();

        assert_eq!(pool.get(&'A', &0).map(|item| item.2), Some("first"));
        assert_eq!(pool.lane_len(&'A', &0), 2);
        assert_eq!(pool.lane_len(&'A', &1), 1);
        assert_eq!(drain(&mut pool), vec!["first", "next"]);
    }

    #[test]
    fn rejects_an_item_that_would_close_a_cycle() {
        let mut pool = laned_pool(10);

        pool.insert((0, vec![('A', 2), ('B', 1)], "y")).unwrap();
        // ahead of `y` in `A`, behind it in `B`
        assert_eq!(
            pool.insert((0, vec![('A', 1), ('B', 2)], "x")),
            Err(Rejected::Cycle)
        );
        // through a third item: behind `y` in `A`, ahead of `z` in `C`, which is ahead of `y`
        pool.insert((0, vec![('B', 0), ('C', 1)], "z")).unwrap();
        assert_eq!(
            pool.insert((0, vec![('A', 3), ('C', 0)], "w")),
            Err(Rejected::Cycle)
        );
        pool.insert((0, vec![('A', 3), ('C', 2)], "v")).unwrap();

        assert_eq!(drain(&mut pool), vec!["z", "y", "v"]);
    }

    #[test]
    fn a_given_back_item_replaces_what_holds_its_slots() {
        let mut pool = laned_pool(10);

        pool.insert((9, vec![('A', 0)], "resubmitted")).unwrap();
        pool.give_back((1, vec![('A', 0)], "orphan"));
        pool.unpark();

        assert_eq!(drain(&mut pool), vec!["orphan"]);
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
        let mut pool = laned_pool(10);

        pool.insert((0, vec![('A', 0)], "a0")).unwrap();
        pool.insert((5, vec![('A', 1)], "a1")).unwrap();
        pool.insert((0, vec![('B', 0)], "b0")).unwrap();

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
    fn a_batch_given_back_in_reverse_keeps_its_order() {
        let mut pool = laned_pool(10);

        pool.insert((0, vec![('A', 0)], "a0")).unwrap();
        pool.insert((5, vec![('A', 1)], "a1")).unwrap();
        pool.insert((9, vec![('H', 0)], "h")).unwrap();
        pool.insert((1, vec![('A', 2)], "a2")).unwrap();

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
