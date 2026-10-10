use std::collections::{BTreeMap, HashSet};

pub use lee_core::EncryptedNote;
use lee_core::{PrivacyPreservingCircuitOutput, ProvenExecution, account::Nonce};

use crate::{AccountId, TransactionMessage};

const PREFIX: &[u8; 32] = b"/LEE/v0.3/Message/Privacy/\x00\x00\x00\x00\x00\x00";

pub type Message = TransactionMessage<ProvenExecution>;

impl Message {
    #[must_use]
    pub fn from_circuit_output(
        nonces: BTreeMap<AccountId, Nonce>,
        output: PrivacyPreservingCircuitOutput,
    ) -> Self {
        let PrivacyPreservingCircuitOutput { context, execution } = output;
        Self {
            context,
            execution,
            nonces,
            admission_evidence: Vec::new(),
        }
    }

    #[must_use]
    pub fn public_account_ids(&self) -> Vec<AccountId> {
        let mut seen = HashSet::new();
        self.context
            .actors
            .iter()
            .map(|actor| actor.account_id)
            .filter(|account_id| seen.insert(*account_id))
            .collect()
    }

    #[must_use]
    pub fn hash(&self) -> [u8; 32] {
        self.hash_under(PREFIX)
    }
}

#[cfg(test)]
pub mod tests {
    use std::collections::BTreeMap;

    use lee_core::{
        Commitment, EphemeralPublicKey, Nullifier, NullifierPublicKey, PrivateAction,
        ProvenExecution,
        account::{Account, AccountId, Nonce},
        encryption::{Ciphertext, ViewingPublicKey},
        execution_state::{Boundary, PublicExecutionContext},
        program::{PdaSeed, ValidityWindows},
    };
    use sha2::{Digest as _, Sha256};

    use super::{EncryptedNote, Message, PREFIX};
    use crate::PublicAccountEvidence;

    #[must_use]
    pub fn message_for_tests() -> Message {
        let account1 = Account::default();
        let account2 = Account::default();

        let nsk1 = [11; 32];
        let nsk2 = [12; 32];

        let npk1 = NullifierPublicKey::from(&nsk1);
        let npk2 = NullifierPublicKey::from(&nsk2);
        let vpk = ViewingPublicKey::from_seed(&[7; 32], &[8; 32]);

        let nonces =
            BTreeMap::from([1, 2, 3].map(|tag| (AccountId::new([tag; 32]), Nonce(tag.into()))));

        let account_id2 = lee_core::account::AccountId::for_regular_private_account(&npk2, &vpk);
        let commitment = Commitment::new(&account_id2, &account2);

        let account_id1 = lee_core::account::AccountId::for_regular_private_account(&npk1, &vpk);
        let old_commitment = Commitment::new(&account_id1, &account1);
        let nullifier = Nullifier::for_account_update(&old_commitment, &nsk1);

        Message {
            context: PublicExecutionContext::default(),
            execution: ProvenExecution {
                boundary: Boundary::default(),
                casts: Vec::new(),
                recovery_bindings: Vec::new(),
                public_root: None,
                private_actions: vec![PrivateAction {
                    nullifier,
                    root: [0; 32],
                    commitment,
                    encrypted_post_state: EncryptedNote {
                        ciphertext: Ciphertext::from_inner(vec![]),
                        epk: EphemeralPublicKey(vec![]),
                    },
                }],
                validity: ValidityWindows::new_unbounded(),
                program_image_claims: vec![],
            },
            nonces,
            admission_evidence: vec![],
        }
    }

    #[test]
    fn a_privacy_preserving_message_has_a_pinned_layout_and_hash() {
        let message = Message {
            nonces: BTreeMap::from([(AccountId::new([2; 32]), Nonce(1))]),
            admission_evidence: vec![PublicAccountEvidence::Pda {
                program: AccountId::new([0; 32]),
                seed: PdaSeed::new([1; 32]),
            }],
            ..Message::default()
        };

        let expected: Vec<u8> = [
            &[0, 0, 0, 0][..], // context.actors: none
            &[0, 0, 0, 0],     // context.authorized_accounts: none
            &[0, 0, 0, 0],     // context.cast_promotions: none
            &[0, 0, 0, 0],     // execution.boundary: no steps
            &[0, 0, 0, 0],     // execution.casts: none
            &[0, 0, 0, 0],     // execution.recovery_bindings: none
            &[0],              // execution.public_root: None
            &[0, 0, 0, 0],     // execution.private_actions: none
            &[0, 0],           // execution.validity.blocks: from None, to None
            &[0, 0],           // execution.validity.timestamps: from None, to None
            &[0, 0, 0, 0],     // execution.program_image_claims: none
            &[1, 0, 0, 0],     // nonces: one account's nonce, a little-endian u128
            &[2; 32],
            &[1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
            &[1, 0, 0, 0], // admission_evidence: one entry
            &[1],          // PublicAccountEvidence::Pda
            &[0; 32],      // program
            &[1; 32],      // seed
        ]
        .concat();

        assert_eq!(message.to_bytes(), expected);
        let digest: [u8; 32] = Sha256::digest([&PREFIX[..], &expected].concat()).into();
        assert_eq!(message.hash(), digest);
    }
}
