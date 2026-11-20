use std::{
    cmp::Reverse,
    collections::{BTreeMap, BinaryHeap, HashMap, HashSet},
    hash::Hash,
    ops::Bound,
    time::{Duration, Instant},
};

/// Items one lane may hold, so a single signer cannot fill the pool.
pub const MAX_LANE_LENGTH: usize = 64;

/// Why [`MemPool::insert`] turned an item away.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Rejected {
    /// The pool holds `max_size` items and none of them can be evicted.
    Full,
    /// One of its lanes already holds [`MAX_LANE_LENGTH`] items.
    LaneFull,
    /// It does not outbid the item it would replace, or the one it would evict from a full pool.
    Underpriced,
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
    born: Instant,
}

/// A bounded pool that pops the highest `priority` first, without ever
/// reordering a lane.
///
/// - `priority`: the bid of an item; higher pops first, ties go to the earlier arrival.
/// - `slots_of`: the lane slots an item takes (one per signer, at its `nonce`). A lane pops in slot
///   order: an item is ready only once it holds the first slot of every lane it is in. An item in
///   no lane is always ready.
/// - `outbids`: whether a bid may replace the one holding a slot it takes, or evict the lowest lane
///   tail from a full pool.
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
    outbids: fn(&K, &K) -> bool,
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
        Self::new(max_size, |_| (), |_| Vec::new(), |(), ()| false)
    }
}

impl<T, K: Ord, G: Hash + Eq + Clone, N: Ord + Clone> MemPool<T, K, G, N> {
    #[must_use]
    pub fn new(
        max_size: usize,
        priority: fn(&T) -> K,
        slots_of: fn(&T) -> Vec<(G, N)>,
        outbids: fn(&K, &K) -> bool,
    ) -> Self {
        Self {
            max_size,
            priority,
            slots_of,
            outbids,
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

    /// Adds an item at its slots, replacing whatever holds them if it outbids all of those. Into
    /// a full pool, it takes the place of the lowest lane tail it outbids.
    pub fn insert(&mut self, item: T) -> Result<(), Rejected> {
        let slots = (self.slots_of)(&item);
        let mut displaced = self.holders(&slots);
        if slots.iter().any(|(lane, at)| {
            self.lanes
                .get(lane)
                .is_some_and(|queue| queue.len() >= MAX_LANE_LENGTH && !queue.contains_key(at))
        }) {
            return Err(Rejected::LaneFull);
        }
        if displaced.is_empty() && self.len() >= self.max_size {
            displaced.push(self.eviction_candidate(&slots).ok_or(Rejected::Full)?);
        }
        let bid = (self.priority)(&item);
        if !displaced.iter().all(|arrival| {
            self.items
                .get(arrival)
                .is_some_and(|held| (self.outbids)(&bid, &(self.priority)(&held.item)))
        }) {
            return Err(Rejected::Underpriced);
        }
        if self.closes_cycle(&slots, &displaced) {
            return Err(Rejected::Cycle);
        }
        for arrival in displaced {
            self.remove(arrival);
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

    /// Drops every item held for `ttl` or longer, given back ones counting from when they were
    /// given back. O(n) per call.
    pub fn expire(&mut self, ttl: Duration) {
        let expired: Vec<i64> = self
            .items
            .iter()
            .filter(|(_, entry)| entry.born.elapsed() >= ttl)
            .map(|(&arrival, _)| arrival)
            .collect();
        for arrival in expired {
            self.remove(arrival);
        }
    }

    /// Pops the ready item that goes first.
    pub fn pop(&mut self) -> Option<T> {
        self.pop_unless(|_| false)
    }

    /// Pops the ready item that goes first, parking in place, as if given back, those `wait`
    /// holds back. Unlike a pop and a give back, a parked item keeps its age.
    pub fn pop_unless(&mut self, mut wait: impl FnMut(&T) -> bool) -> Option<T> {
        loop {
            let (_, _, Reverse(arrival)) = self.ready.pop()?;
            let ready = self.is_ready(arrival);
            let Some(entry) = self.items.get_mut(&arrival) else {
                continue;
            };
            entry.queued = false;
            if !ready {
                continue;
            }
            if wait(&entry.item) {
                entry.parked = true;
                self.parked.push(arrival);
                continue;
            }
            return self.remove(arrival);
        }
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
            born: Instant::now(),
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

    /// The lowest bid among the inserted, unparked lane tails, latest arrival on ties: removing
    /// it strands nothing. One ahead of `slots` in a lane they share is spared, as evicting it
    /// would only leave a gap before them. O(n) per call.
    fn eviction_candidate(&self, slots: &[(G, N)]) -> Option<i64> {
        self.items
            .iter()
            .filter(|&(&arrival, entry)| {
                arrival >= 0
                    && !entry.parked
                    && !is_ahead(&entry.slots, slots)
                    && entry.slots.iter().all(|(lane, at)| {
                        self.lanes
                            .get(lane)
                            .and_then(BTreeMap::last_key_value)
                            .is_some_and(|(last, _)| last == at)
                    })
            })
            .min_by_key(|&(&arrival, entry)| ((self.priority)(&entry.item), Reverse(arrival)))
            .map(|(&arrival, _)| arrival)
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
            if is_ahead(&entry.slots, slots) {
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

/// Whether `slots` come before `others` in a lane they share.
fn is_ahead<G: Eq, N: Ord>(slots: &[(G, N)], others: &[(G, N)]) -> bool {
    slots.iter().any(|(lane, at)| {
        others
            .iter()
            .any(|(other_lane, other_at)| lane == other_lane && at < other_at)
    })
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
            |new, old| new > old,
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
        // a FIFO bid never outbids, so nothing is evicted
        assert_eq!(pool.insert(2), Err(Rejected::Underpriced));

        // Popping frees capacity again.
        assert_eq!(pool.pop(), Some(1));
        pool.insert(2).unwrap();
        assert_eq!(pool.pop(), Some(2));
    }

    #[test]
    fn replaces_a_slot_only_when_outbid_even_when_full() {
        let mut pool = laned_pool(1);

        pool.insert((1, vec![('A', 0)], "old")).unwrap();
        assert_eq!(
            pool.insert((1, vec![('A', 0)], "same")),
            Err(Rejected::Underpriced)
        );
        assert_eq!(
            pool.insert((9, vec![('A', 1)], "next")),
            Err(Rejected::Full)
        );
        pool.insert((2, vec![('A', 0)], "new")).unwrap();

        assert_eq!(pool.len(), 1);
        assert_eq!(drain(&mut pool), vec!["new"]);
    }

    #[test]
    fn a_full_pool_evicts_the_lowest_lane_tail_it_is_outbid_by() {
        let mut pool = laned_pool(3);

        // `a0` is no tail, so `b0` is the lowest one
        pool.insert((1, vec![('A', 0)], "a0")).unwrap();
        pool.insert((5, vec![('A', 1)], "a1")).unwrap();
        pool.insert((2, vec![('B', 0)], "b0")).unwrap();
        pool.insert((3, vec![('C', 0)], "c")).unwrap();
        // now `c` is the lowest tail, and it is not outbid
        assert_eq!(
            pool.insert((0, vec![('D', 0)], "d")),
            Err(Rejected::Underpriced)
        );

        assert_eq!(drain(&mut pool), vec!["c", "a0", "a1"]);
    }

    #[test]
    fn a_lane_holds_at_most_its_cap() {
        let mut pool = laned_pool(MAX_LANE_LENGTH + 1);

        for at in 0..MAX_LANE_LENGTH {
            let at = u32::try_from(at).unwrap();
            pool.insert((1, vec![('A', at)], "a")).unwrap();
        }
        let next = u32::try_from(MAX_LANE_LENGTH).unwrap();
        assert_eq!(
            pool.insert((1, vec![('A', next)], "over")),
            Err(Rejected::LaneFull)
        );
        // replacing does not lengthen the lane
        pool.insert((2, vec![('A', 3)], "replacement")).unwrap();
        assert_eq!(pool.len(), MAX_LANE_LENGTH);
    }

    #[test]
    fn expires_what_was_held_for_the_ttl() {
        let mut pool = laned_pool(10);

        pool.insert((1, vec![('A', 0)], "a0")).unwrap();
        pool.give_back((1, vec![('B', 0)], "b0"));
        pool.expire(Duration::from_secs(60));
        assert_eq!(pool.len(), 2);

        pool.expire(Duration::ZERO);
        assert!(pool.is_empty());
        assert!(pool.lanes.is_empty());
        pool.unpark();
        assert_eq!(pool.pop(), None);
    }

    #[test]
    fn an_item_held_back_at_pop_parks_in_place_holding_its_lanes() {
        let mut pool = laned_pool(10);

        pool.insert((5, vec![('A', 0)], "wait")).unwrap();
        pool.insert((1, vec![('B', 0)], "go")).unwrap();
        pool.insert((0, vec![('A', 1)], "behind")).unwrap();

        assert_eq!(
            pool.pop_unless(|&(_, _, tag)| tag == "wait")
                .map(|(_, _, tag)| tag),
            Some("go")
        );
        assert_eq!(pool.pop(), None);
        assert_eq!(pool.len(), 2);

        pool.unpark();
        assert_eq!(drain(&mut pool), vec!["wait", "behind"]);
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
