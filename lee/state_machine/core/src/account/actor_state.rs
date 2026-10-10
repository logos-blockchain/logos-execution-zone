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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn state_encoding_matches_bytes_beyond_the_former_limit() {
        let bytes = vec![7_u8; 100 * 1024 + 1];
        let state = ActorState::from(bytes.clone());

        let borsh = borsh::to_vec(&bytes).unwrap();
        assert_eq!(borsh::to_vec(&state).unwrap(), borsh);
        assert_eq!(borsh::from_slice::<ActorState>(&borsh).unwrap(), state);

        let json = serde_json::to_string(&bytes).unwrap();
        assert_eq!(serde_json::to_string(&state).unwrap(), json);
        assert_eq!(serde_json::from_str::<ActorState>(&json).unwrap(), state);
    }
}
