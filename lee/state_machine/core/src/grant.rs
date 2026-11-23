use borsh::{BorshDeserialize, BorshSerialize};
use serde::{Deserialize, Serialize};

use crate::account::Actor;

pub type WithheldIndex = u32;

/// What a grant on a delivery covers.
#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
    Serialize,
    Deserialize,
    BorshSerialize,
    BorshDeserialize,
)]
pub enum Target {
    Actor(Actor),
    /// A grant over a private actor while it is held on the public side, where it authorizes
    /// nothing; the index numbers the transaction's withheld private actors.
    Withheld(WithheldIndex),
}
