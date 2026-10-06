use std::collections::BTreeMap;

use common::transaction::LeeTransaction;
use lee::AccountId;
use lee_core::{Commitment, Identifier};
use rand::{RngCore as _, rngs::OsRng};
use referral_core::{Invitation, NodeId, ed25519_dalek::Signature};
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReferralStore {
    pub intents: BTreeMap<AccountId, ReferralIntent>,
    pub operations: BTreeMap<String, PendingOperation>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReferralIntent {
    pub program_account: AccountId,
    pub registration: Option<PendingRegistration>,
    pub invitation: Option<Invitation>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PendingRegistration {
    pub node: NodeId,
    pub referrer: Option<NodeId>,
    pub signature: Option<Signature>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum OperationKind {
    Register {
        participant: AccountId,
    },
    Claim {
        participant: AccountId,
        notes: Vec<AccountId>,
    },
    CashOut {
        participant: AccountId,
        index: u64,
    },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum SubmissionStatus {
    Pending,
    Settled,
    Rejected,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PendingOperation {
    pub reference: [u8; 32],
    pub program_account: AccountId,
    pub operation: OperationKind,
    pub transaction: LeeTransaction,
    pub input_commitments: Vec<(AccountId, Commitment)>,
    pub status: SubmissionStatus,
}

impl ReferralStore {
    #[must_use]
    pub fn operation(&self, reference: [u8; 32]) -> Option<&PendingOperation> {
        self.operations.get(&operation_key(reference))
    }

    pub fn operation_mut(&mut self, reference: [u8; 32]) -> Option<&mut PendingOperation> {
        self.operations.get_mut(&operation_key(reference))
    }

    pub fn record_operation(&mut self, operation: PendingOperation) {
        self.operations
            .insert(operation_key(operation.reference), operation);
    }
}

impl ReferralIntent {
    #[must_use]
    pub const fn new(program_account: AccountId) -> Self {
        Self {
            program_account,
            registration: None,
            invitation: None,
        }
    }
}

impl PendingRegistration {
    #[must_use]
    pub fn signed(&self) -> Option<[u8; 64]> {
        Some(self.signature?.to_bytes())
    }
}

impl OperationKind {
    #[must_use]
    pub const fn participant(&self) -> AccountId {
        match self {
            Self::Register { participant }
            | Self::Claim { participant, .. }
            | Self::CashOut { participant, .. } => *participant,
        }
    }
}

impl SubmissionStatus {
    #[must_use]
    pub const fn is_conclusive(self) -> bool {
        matches!(self, Self::Settled | Self::Rejected)
    }
}

#[must_use]
pub fn random_identifier() -> Identifier {
    let mut bytes = [0; 32];
    OsRng.fill_bytes(&mut bytes);
    Identifier::new(bytes)
}

fn operation_key(reference: [u8; 32]) -> String {
    hex::encode(reference)
}
