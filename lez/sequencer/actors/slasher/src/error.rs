#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("Storage request failed")]
    StorageRequestFailed(
        #[source] kameo::error::SendError<NoMatter, sequencer_storage_actor::error::Error>,
    ),
}

/// A dummy struct replacing message type in [`kameo::error::SendError`]
/// as we don't want to expose the message type in the public API.
pub struct NoMatter;

impl<M> From<kameo::error::SendError<M, sequencer_storage_actor::error::Error>> for Error {
    fn from(err: kameo::error::SendError<M, sequencer_storage_actor::error::Error>) -> Self {
        Self::StorageRequestFailed(err.map_msg(|_| NoMatter))
    }
}
