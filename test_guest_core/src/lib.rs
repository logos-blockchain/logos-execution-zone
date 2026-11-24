//! Message types shared between the test guests and the hosts that drive them, so a guest and its
//! callers cannot drift apart. `Script` is what `scripted` runs.

use borsh::{BorshDeserialize, BorshSerialize};
use lee_core::{
    account::{AccountId, Actor, Balance},
    program::{AsyncMessage, PdaSeed, Response, Sendable, SyncMessage},
};

pub mod guests;

// `live_payout` pays from the public PDA of its program under this seed.
pub const LIVE_PAYOUT_SEED: PdaSeed = PdaSeed::new([7; 32]);

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
    pub fn send_sync<M: BorshSerialize>(self, to: Actor, message: &M) -> Self {
        self.send(SyncMessage::new(to, message))
    }

    #[must_use]
    pub fn send_async<M: BorshSerialize>(self, to: Actor, message: &M) -> Self {
        self.send(AsyncMessage::new(to, message))
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

#[derive(Clone, Copy, BorshSerialize, BorshDeserialize)]
pub struct PayoutRequest {
    pub to: AccountId,
    pub min_payout: Balance,
}
