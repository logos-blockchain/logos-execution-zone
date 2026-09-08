use std::collections::VecDeque;

/// A FIFO queue with a fixed capacity: pushing onto a full queue evicts and
/// returns the oldest element, so the bound is an invariant rather than a
/// check every caller must remember.
#[derive(Debug)]
pub struct BoundedVecDeque<T> {
    items: VecDeque<T>,
    capacity: usize,
}

impl<T> BoundedVecDeque<T> {
    /// # Panics
    ///
    /// Panics if `capacity` is zero.
    #[must_use]
    pub fn new(capacity: usize) -> Self {
        assert!(capacity > 0, "BoundedVecDeque capacity must be non-zero");
        Self {
            items: VecDeque::with_capacity(capacity),
            capacity,
        }
    }

    /// Appends `item`, evicting and returning the oldest element if the
    /// queue is full.
    pub fn push_back(&mut self, item: T) -> Option<T> {
        let evicted = if self.items.len() == self.capacity {
            self.items.pop_front()
        } else {
            None
        };
        self.items.push_back(item);
        evicted
    }

    /// Removes and returns all elements, oldest first.
    pub fn drain_all(&mut self) -> VecDeque<T> {
        std::mem::take(&mut self.items)
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.items.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.items.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn push_back_evicts_oldest_at_capacity() {
        let mut queue = BoundedVecDeque::new(2);
        assert_eq!(queue.push_back(1), None);
        assert_eq!(queue.push_back(2), None);
        assert_eq!(queue.push_back(3), Some(1));
        assert_eq!(queue.drain_all(), [2, 3]);
        assert!(queue.is_empty());
    }
}
