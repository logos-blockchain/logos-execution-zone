//! Message types shared between the test guests and the hosts that drive them, so a guest and its
//! callers cannot drift apart. `Script` is what `scripted` runs.

use borsh::{BorshDeserialize, BorshSerialize};
use lee_core::{
    account::{AccountId, Actor},
    program::{Call, Cast, Response, Sendable},
};

pub mod guests;

#[derive(Clone, BorshSerialize, BorshDeserialize)]
pub struct Script {
    pub response: Response,
    pub require_authorized: bool,
    pub require_sender_program: Option<AccountId>,
}

impl Default for Script {
    fn default() -> Self {
        Self {
            response: Response::keep_state(),
            require_authorized: false,
            require_sender_program: None,
        }
    }
}

impl Script {
    #[must_use]
    pub fn write(data: Vec<u8>) -> Self {
        Self {
            response: Response::set_state(data),
            ..Self::default()
        }
    }

    #[must_use]
    pub fn call<M: BorshSerialize>(self, to: Actor, message: &M) -> Self {
        self.send(Call::new(to, message))
    }

    #[must_use]
    pub fn cast<M: BorshSerialize>(self, to: Actor, message: &M) -> Self {
        self.send(Cast::new(to, message))
    }

    #[must_use]
    pub fn send(mut self, message: impl Sendable) -> Self {
        self.response = self.response.send(message);
        self
    }

    #[must_use]
    pub const fn authorized(mut self) -> Self {
        self.require_authorized = true;
        self
    }

    #[must_use]
    pub const fn from(mut self, program: AccountId) -> Self {
        self.require_sender_program = Some(program);
        self
    }
}

#[derive(Clone, Copy, BorshSerialize, BorshDeserialize)]
pub enum ForgeField {
    Receiver,
    Sender,
    IsAuthorized,
    PreState,
    Message,
}
