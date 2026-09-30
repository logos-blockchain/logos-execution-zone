//! Common utilities for sequencer actors.

#[cfg(feature = "mock")]
pub mod mock;

mod sealed {
    pub trait Sealed {}

    impl<M, E> Sealed for kameo::error::SendError<M, E> {}
}

/// A dummy struct replacing message type in [`kameo::error::SendError`]
/// to not to expose the message type in the public API.
pub struct ErasedMessage;

pub trait EraseMessage: sealed::Sealed {
    type Output;

    fn erase_message(self) -> Self::Output;
}

impl<M, E> EraseMessage for kameo::error::SendError<M, E> {
    type Output = kameo::error::SendError<ErasedMessage, E>;

    fn erase_message(self) -> Self::Output {
        self.map_msg(|_| ErasedMessage)
    }
}
