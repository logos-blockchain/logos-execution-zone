use std::collections::{BTreeMap, HashSet};

pub use lee_core::EncryptedNote;
use lee_core::{PrivacyPreservingCircuitOutput, ProvenExecution, account::Nonce};

use crate::{AccountId, TransactionMessage, transaction_message::MessageDomain};

const PREFIX: &[u8; 32] = b"/LEE/v0.3/Message/Privacy/\x00\x00\x00\x00\x00\x00";
const KEYED_PREFIX: &[u8; 32] = b"/LEE/v0.4/KeyedMessage/Privacy/\x00";

pub type Message = TransactionMessage<ProvenExecution>;

impl Message {
    #[must_use]
    pub fn from_circuit_output(
        nonces: BTreeMap<AccountId, Nonce>,
        output: PrivacyPreservingCircuitOutput,
    ) -> Self {
        let PrivacyPreservingCircuitOutput {
            public_context,
            execution,
        } = output;
        Self {
            public_context,
            execution,
            nonces,
            fee: None,
            admission_evidence: Vec::new(),
        }
    }

    #[must_use]
    pub fn public_account_ids(&self) -> Vec<AccountId> {
        let mut seen = HashSet::new();
        self.public_context
            .actors
            .keys()
            .map(|actor| actor.account_id)
            .filter(|account_id| seen.insert(*account_id))
            .collect()
    }
}

impl MessageDomain for ProvenExecution {
    const KEYED_PREFIX: &'static [u8; 32] = KEYED_PREFIX;
    const PREFIX: &'static [u8; 32] = PREFIX;
}

#[cfg(test)]
pub mod tests {
    use std::collections::BTreeMap;

    use hex_literal::hex;
    use lee_core::{
        Commitment, EphemeralPublicKey, Nullifier, NullifierPublicKey, PrivateAction,
        ProvenExecution,
        account::{Account, AccountId, Actor, Nonce},
        encryption::{Ciphertext, ViewingPublicKey},
        execution_state::{Boundary, PublicExecutionContext},
        program::{PdaSeed, ValidityWindows},
        signing_key::{KeyType, SigningKeyState},
    };
    use sha2::{Digest as _, Sha256};

    use super::{EncryptedNote, KEYED_PREFIX, Message, PREFIX};
    use crate::{
        Authority, PublicAccountEvidence, public_transaction, transaction_message::hash_with_keys,
    };

    fn key(commitment: u8) -> SigningKeyState {
        SigningKeyState {
            key_type: KeyType::Schnorr,
            key_commitment: [commitment; 32],
        }
    }

    fn pinned_message() -> Message {
        Message {
            nonces: BTreeMap::from([(AccountId::new([2; 32]), Nonce(1))]),
            admission_evidence: vec![PublicAccountEvidence::Pda {
                program: AccountId::new([0; 32]),
                seed: PdaSeed::new([1; 32]),
            }],
            ..Message::default()
        }
    }

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
            public_context: PublicExecutionContext::default(),
            execution: ProvenExecution {
                boundary: Boundary::default(),
                async_messages: Vec::new(),
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
                proven_fee: None,
            },
            nonces,
            fee: None,
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
            &[0, 0, 0, 0][..], // public_context.actors: none
            &[0, 0, 0, 0],     // public_context.authorized_accounts: none
            &[0, 0, 0, 0],     // public_context.promotions: none
            &[0, 0, 0, 0],     // public_context.private_signers: none
            &[0, 0, 0, 0],     // execution.boundary: no steps
            &[0, 0, 0, 0],     // execution.async_messages: none
            &[0, 0, 0, 0],     // execution.recovery_bindings: none
            &[0],              // execution.public_root: None
            &[0, 0, 0, 0],     // execution.private_actions: none
            &[0, 0],           // execution.validity.blocks: from None, to None
            &[0, 0],           // execution.validity.timestamps: from None, to None
            &[0, 0, 0, 0],     // execution.program_image_claims: none
            &[0],              // execution.proven_fee: None
            &[1, 0, 0, 0],     // nonces: one account's nonce, a little-endian u128
            &[2; 32],
            &[1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
            &[0],          // fee: None
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

    #[test]
    fn message_with_keys_has_known_answers() {
        let message = pinned_message();
        assert_eq!(
            message.message_with_keys(&[0; 32], &[key(7)]),
            hex!("fc5cbf1fbd6d80fd98546fe2f842c5a4b643faa8866a948c96b3c80e20e5e9f9")
        );
        assert_eq!(
            message.message_with_keys(&[0; 32], &[key(1), key(2), key(3)]),
            hex!("64e0037b5c9925d326e5247ad4ded68fcbdd5114701dc3fb84672b3eb770d0e7")
        );
    }

    #[test]
    fn a_public_and_a_privacy_message_with_the_same_bytes_and_next_keys_differ() {
        let to = Actor::new(AccountId::new([42; 32]), AccountId::new([0; 32]));
        let public = public_transaction::Message::new_preserialized(
            to,
            vec![0],
            [(to, Authority::Signer)],
            BTreeMap::from([(to.account_id, Nonce(1))]),
            None,
        );
        let next = [key(7)];
        // What a privacy message with the public message's bytes would have its signers sign.
        let as_privacy = hash_with_keys(KEYED_PREFIX, &[0; 32], &public.hash_under(PREFIX), &next);

        assert_eq!(
            as_privacy,
            hex!("3336107d31c5191f08d893652499418bd141b7144c37c9260685ae64353e742f")
        );
        assert_ne!(public.message_with_keys(&[0; 32], &next), as_privacy);
    }
}
