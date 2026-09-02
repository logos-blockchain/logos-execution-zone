use sequencer_stake_core::{SequencerKey, SequencerStakeConfig};

/// A non-block inscription and the key that wrote it.
#[derive(
    Clone,
    Copy,
    Debug,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    borsh::BorshSerialize,
    borsh::BorshDeserialize,
)]
pub struct Offence {
    pub offender: SequencerKey,
    /// The inscription's `MsgId`.
    pub inscription: [u8; 32],
}

/// One finalized inscription that did not decode as a block.
pub struct ReportedOffence {
    /// Ed25519 public key bytes, not yet checked for validity.
    pub signer: [u8; 32],
    pub inscription: [u8; 32],
}

/// What the follow path saw. Await it before the checkpoint moves past them.
pub struct Report {
    pub offences: Vec<ReportedOffence>,
}

/// Slash transactions for a block built on `config`.
pub struct Propose {
    pub config: SequencerStakeConfig,
}
