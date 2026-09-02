use sequencer_stake_core::{
    SequencerKey, SequencerStakeConfig,
    ed25519_dalek::{Signature, VerifyingKey},
};

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

/// Offences the follow path saw; await it before the checkpoint moves past them.
pub struct Report {
    pub offences: Vec<ReportedOffence>,
}

/// Slash transactions for a block built on `config`.
pub struct Propose {
    pub config: SequencerStakeConfig,
}

/// One sequencer's signature over an offence, gossiped for peers to collect.
#[derive(Clone, Debug, PartialEq, Eq, borsh::BorshSerialize, borsh::BorshDeserialize)]
pub struct Approval {
    pub offence: Offence,
    pub signer: SequencerKey,
    pub signature: [u8; 64],
}

impl Approval {
    /// Whether the signature is `signer`'s over exactly what `Slash` verifies.
    #[must_use]
    pub fn verify(&self) -> bool {
        let message = sequencer_stake_core::slash_approval_message(
            self.offence.offender,
            self.offence.inscription,
        );
        let Ok(key) = VerifyingKey::from_bytes(&self.signer.to_bytes()) else {
            return false;
        };

        key.verify_strict(&message, &Signature::from_bytes(&self.signature))
            .is_ok()
    }
}

/// Where this node publishes its own approvals; unset until gossip is up.
pub struct SetApprovalPublisher(pub tokio::sync::mpsc::Sender<Approval>);
