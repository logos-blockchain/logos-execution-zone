//! A set of background tasks that can be stopped and waited on.

use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

use log::warn;
use tokio::task::JoinHandle;

/// Background tasks owned by one component, stoppable on demand and stopped
/// anyway when the last handle goes away.
///
/// `JoinHandle::abort` only *requests* cancellation, and dropping a handle
/// detaches rather than cancels, so neither on its own says when a task has
/// actually stopped. That matters because these tasks hold a store handle:
/// until they are gone the `RocksDB` lock is still held and a restarting
/// sequencer cannot reopen its home directory. [`TaskGroup::shutdown`] is the
/// answer to "have they stopped yet"; the `Drop` below stays as the best-effort
/// path for panics and tests that never call it.
///
/// Cloneable so the owner can keep it (tying task lifetime to its own) while a
/// shutdown path elsewhere holds a clone.
#[derive(Clone, Default)]
pub struct TaskGroup(Arc<TaskGroupInner>);

#[derive(Default)]
struct TaskGroupInner(Mutex<Vec<JoinHandle<()>>>);

impl Drop for TaskGroupInner {
    fn drop(&mut self) {
        for task in Self::take(&self.0) {
            task.abort();
        }
    }
}

impl TaskGroupInner {
    /// Empties the handle list, so a second shutdown (or a drop after one) is a
    /// no-op rather than a second abort.
    fn handles(handles: &Mutex<Vec<JoinHandle<()>>>) -> MutexGuard<'_, Vec<JoinHandle<()>>> {
        handles.lock().unwrap_or_else(PoisonError::into_inner)
    }

    fn take(handles: &Mutex<Vec<JoinHandle<()>>>) -> Vec<JoinHandle<()>> {
        std::mem::take(&mut *Self::handles(handles))
    }
}

impl TaskGroup {
    /// Takes ownership of already-spawned tasks.
    #[must_use]
    pub fn new(handles: Vec<JoinHandle<()>>) -> Self {
        Self(Arc::new(TaskGroupInner(Mutex::new(handles))))
    }

    /// Whether any task has ended on its own.
    ///
    /// These tasks run for the lifetime of the sequencer, so a finished one is a
    /// task that panicked, and whatever it was doing is not happening any more.
    #[must_use]
    pub fn any_finished(&self) -> bool {
        TaskGroupInner::handles(&self.0.0)
            .iter()
            .any(JoinHandle::is_finished)
    }

    /// Stops every task and waits for it to finish.
    ///
    /// Returns only once the runtime has dropped each task's future, so whatever
    /// they held (a store handle, a network client) is released by the time this
    /// returns. Cancellation is the expected outcome, so it is not reported; a
    /// panic is, since it means the task died on its own terms earlier.
    pub async fn shutdown(&self) {
        let handles = TaskGroupInner::take(&self.0.0);
        for handle in handles {
            handle.abort();
            if let Err(err) = handle.await
                && err.is_panic()
            {
                warn!("Background task panicked before shutdown: {err}");
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn a_task_that_ends_on_its_own_is_visible() {
        let group = TaskGroup::new(vec![tokio::spawn(async {})]);
        // A watcher only ends by panicking, so "finished" is the signal that a
        // peer's deliveries have stopped happening.
        tokio::task::yield_now().await;
        assert!(group.any_finished());

        let running = TaskGroup::new(vec![tokio::spawn(std::future::pending())]);
        assert!(!running.any_finished());
    }

    #[tokio::test]
    async fn shutdown_ends_a_task_that_would_never_end_on_its_own() {
        let group = TaskGroup::new(vec![tokio::spawn(std::future::pending())]);

        // The watchers and the drive task are infinite loops, so awaiting one
        // without cancelling it first hangs here for ever.
        tokio::time::timeout(std::time::Duration::from_secs(5), group.shutdown())
            .await
            .expect("shutdown must not hang on a task that never finishes by itself");

        // Shutting down twice is a no-op rather than a second abort.
        tokio::time::timeout(std::time::Duration::from_secs(5), group.shutdown())
            .await
            .expect("a second shutdown must return immediately");
    }
}
