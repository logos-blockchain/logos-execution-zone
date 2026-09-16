//! Common utilities for sequencer actors.

use kameo::error::SendError;

use crate::marker::SendErrorMarker;

#[cfg(feature = "mock")]
pub mod mock;

mod marker {
    use kameo::error::SendError;

    /// Sealed maker trait used for some shenanigans.
    pub trait SendErrorMarker {
        type Error;
        type Message;

        fn into_send_error(self) -> SendError<Self::Message, Self::Error>;
    }

    impl<M, E> SendErrorMarker for SendError<M, E> {
        type Error = E;
        type Message = M;

        fn into_send_error(self) -> SendError<Self::Message, Self::Error> {
            self
        }
    }
}

pub trait SendErrorExt: SendErrorMarker {
    /// Erase concrete message type, replacing it with [`ErasedMessage`].
    ///
    /// Useful when exposing [`kameo::error::SendError`] in the public API without revealing the
    /// concrete message type.
    fn erase_message(self) -> SendError<ErasedMessage, Self::Error>;

    /// Flatten nested send errors, converting a `SendError<T, SendError<T, E>>` into a
    /// `SendError<T, E>`.
    fn flatten(self) -> SendError<Self::Message, <Self::Error as SendErrorMarker>::Error>
    where
        Self::Error: SendErrorMarker<Message = Self::Message>;
}

impl<M, E> SendErrorExt for SendError<M, E> {
    fn erase_message(self) -> SendError<ErasedMessage, Self::Error> {
        self.map_msg(|_| ErasedMessage)
    }

    fn flatten(self) -> SendError<Self::Message, <Self::Error as SendErrorMarker>::Error>
    where
        Self::Error: SendErrorMarker<Message = Self::Message>,
    {
        match self {
            SendError::HandlerError(send_error) => send_error.into_send_error(),
            SendError::ActorNotRunning(msg) => SendError::ActorNotRunning(msg),
            SendError::ActorStopped => SendError::ActorStopped,
            SendError::ActorRestarting(msg) => SendError::ActorRestarting(msg),
            SendError::MailboxFull(msg) => SendError::MailboxFull(msg),
            SendError::Timeout(msg) => SendError::Timeout(msg),
        }
    }
}

/// A dummy struct replacing message type in [`kameo::error::SendError`]
/// to not to expose the message type in the public API.
pub struct ErasedMessage;
