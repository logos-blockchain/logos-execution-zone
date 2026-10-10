use std::borrow::Borrow;

use borsh::{BorshDeserialize, BorshSerialize};
use derive_more::{AsRef, Deref, From, Into};
use serde::{Deserialize, Serialize};

#[derive(
    Debug,
    Default,
    Clone,
    PartialEq,
    Eq,
    Serialize,
    Deserialize,
    BorshSerialize,
    BorshDeserialize,
    From,
    Into,
    AsRef,
    Deref,
)]
#[as_ref([u8])]
#[deref(forward)]
pub struct ActorState(Vec<u8>);

impl ActorState {
    #[must_use]
    pub const fn empty() -> Self {
        Self(Vec::new())
    }

    #[must_use]
    pub fn into_inner(self) -> Vec<u8> {
        self.0
    }
}

impl Borrow<[u8]> for ActorState {
    fn borrow(&self) -> &[u8] {
        &self.0
    }
}
