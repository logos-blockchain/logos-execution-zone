//! Message types shared between the test guests and the hosts that drive them, so a guest and its
//! callers cannot drift apart. `Script` is what `scripted` runs.

use borsh::{BorshDeserialize, BorshSerialize};
use lee_core::program::{
    BlockValidityWindow, Call, Cast, Origin, ProgramEvent, TimestampValidityWindow,
};

pub mod guests;

#[derive(Clone, Default, BorshSerialize, BorshDeserialize)]
pub struct Script {
    pub write: Option<Vec<u8>>,
    pub calls: Vec<Call>,
    pub casts: Vec<Cast>,
    pub events: Vec<ProgramEvent>,
    pub block_window: BlockValidityWindow,
    pub timestamp_window: TimestampValidityWindow,
    pub require_authorized: bool,
    pub require_origin: Option<Origin>,
}

impl Script {
    #[must_use]
    pub fn write(data: Vec<u8>) -> Self {
        Self {
            write: Some(data),
            ..Self::default()
        }
    }

    #[must_use]
    pub fn call(mut self, call: Call) -> Self {
        self.calls.push(call);
        self
    }

    #[must_use]
    pub fn cast(mut self, cast: Cast) -> Self {
        self.casts.push(cast);
        self
    }

    #[must_use]
    pub const fn authorized(mut self) -> Self {
        self.require_authorized = true;
        self
    }

    #[must_use]
    pub const fn from(mut self, origin: Origin) -> Self {
        self.require_origin = Some(origin);
        self
    }
}

#[derive(Clone, Copy, BorshSerialize, BorshDeserialize)]
pub enum ForgeField {
    Receiver,
    Origin,
    IsAuthorized,
    PreState,
    Message,
}
