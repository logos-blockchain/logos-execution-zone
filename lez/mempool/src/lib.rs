use tokio::sync::mpsc::{Receiver, Sender};

pub struct MemPool<T> {
    receiver: Receiver<T>,
    front_buffer: Vec<T>,
}

impl<T> MemPool<T> {
    #[must_use]
    pub fn new(max_size: usize) -> (Self, MemPoolHandle<T>) {
        let (sender, receiver) = tokio::sync::mpsc::channel(max_size);

        let mem_pool = Self {
            receiver,
            front_buffer: Vec::new(),
        };
        let sender = MemPoolHandle::new(sender);
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
    }
}

pub struct MemPoolHandle<T> {
    sender: Sender<T>,
}

impl<T> Clone for MemPoolHandle<T> {
    fn clone(&self) -> Self {
        Self {
            sender: self.sender.clone(),
        }
    }
}

impl<T> MemPoolHandle<T> {
    const fn new(sender: Sender<T>) -> Self {
        Self { sender }
    }

    /// Send an item to the mempool blocking if max size is reached.
    pub async fn push(&self, item: T) -> Result<(), tokio::sync::mpsc::error::SendError<T>> {
        self.sender.send(item).await
    }

    /// Send an item to the mempool, failing _immediately_ if it is full.
    pub fn try_push(&self, item: T) -> Result<(), tokio::sync::mpsc::error::TrySendError<T>> {
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
