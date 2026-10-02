use std::collections::HashSet;

use borsh::{BorshDeserialize, BorshSerialize};
pub use lee_core::{EncryptedAccountData, ViewTag};
use lee_core::{PrivacyPreservingCircuitOutput, account::Nonce};
use sha2::{Digest as _, Sha256};

use crate::{AccountId, PublicIdentity};

const PREFIX: &[u8; 32] = b"/LEE/v0.3/Message/Privacy/\x00\x00\x00\x00\x00\x00";

#[derive(Clone, Default, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct Message {
    pub execution: PrivacyPreservingCircuitOutput,
    pub nonces: Vec<Nonce>,
    pub identities: Vec<PublicIdentity>,
}

impl std::fmt::Debug for Message {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        struct HexDigest<'arr>(&'arr [u8; 32]);
        impl std::fmt::Debug for HexDigest<'_> {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                write!(f, "{}", hex::encode(self.0))
            }
        }
        let execution = &self.execution;
        let private_actions: Vec<_> = execution
            .private_actions
            .iter()
            .map(|a| {
                (
                    &a.nullifier,
                    HexDigest(&a.root),
                    &a.commitment,
                    &a.encrypted_post_state,
                )
            })
            .collect();
        f.debug_struct("Message")
            .field("declared", &execution.context)
            .field("boundary", &execution.boundary)
            .field("consumed_message", &execution.consumed_message)
            .field("private_actions", &private_actions)
            .field("block_validity_window", &execution.block_validity_window)
            .field(
                "timestamp_validity_window",
                &execution.timestamp_validity_window,
            )
            .field("program_image_claims", &execution.program_image_claims)
            .field("nonces", &self.nonces)
            .field("identities", &self.identities)
            .finish()
    }
}

impl Message {
    #[must_use]
    pub const fn from_circuit_output(
        nonces: Vec<Nonce>,
        execution: PrivacyPreservingCircuitOutput,
    ) -> Self {
        Self {
            execution,
            nonces,
            identities: Vec::new(),
        }
    }

    #[must_use]
    pub fn public_account_ids(&self) -> Vec<AccountId> {
        let mut seen = HashSet::new();
        self.execution
            .context
            .actors
            .iter()
            .map(|actor| actor.account_id)
            .filter(|account_id| seen.insert(*account_id))
            .collect()
    }

    #[must_use]
    pub fn hash(&self) -> [u8; 32] {
        let msg = self.to_bytes();
        let mut bytes = Vec::with_capacity(
            PREFIX
                .len()
                .checked_add(msg.len())
                .expect("length overflow"),
        );
        bytes.extend_from_slice(PREFIX);
        bytes.extend_from_slice(&msg);

        Sha256::digest(bytes).into()
    }
}

#[cfg(test)]
pub mod tests {
    use lee_core::{
        Commitment, EncryptionScheme, EphemeralPublicKey, EphemeralSecretKey, Identifier,
        Nullifier, NullifierPublicKey, PrivacyPreservingCircuitOutput, PrivateAccountKind,
        PrivateAction, SharedSecretKey,
        account::{Account, AccountId, Actor, Nonce},
        encryption::{Ciphertext, ViewingPublicKey},
        execution_state::{
            Assumption, Boundary, BoundaryStep, DeliverySource, PublicDelivery,
            PublicExecutionContext,
        },
        program::{BlockValidityWindow, MessageEnvelope, TimestampValidityWindow},
    };
    use sha2::{Digest as _, Sha256};

    use super::{EncryptedAccountData, Message, PREFIX};

    #[must_use]
    pub fn message_for_tests() -> Message {
        let account1 = Account::default();
        let account2 = Account::default();

        let nsk1 = [11; 32];
        let nsk2 = [12; 32];

        let npk1 = NullifierPublicKey::from(&nsk1);
        let npk2 = NullifierPublicKey::from(&nsk2);
        let vpk = ViewingPublicKey::from_seed(&[7; 32], &[8; 32]);

        let nonces = vec![1_u128.into(), 2_u128.into(), 3_u128.into()];

        let account_id2 = lee_core::account::AccountId::for_regular_private_account(
            &npk2,
            &vpk,
            Identifier::ZERO,
        );
        let commitment = Commitment::new(&account_id2, &account2);

        let account_id1 = lee_core::account::AccountId::for_regular_private_account(
            &npk1,
            &vpk,
            Identifier::ZERO,
        );
        let old_commitment = Commitment::new(&account_id1, &account1);
        let nullifier = Nullifier::for_account_update(&old_commitment, &nsk1);

        Message {
            execution: PrivacyPreservingCircuitOutput {
                context: PublicExecutionContext::default(),
                boundary: Boundary::default(),
                casts: Vec::new(),
                consumed_message: None,
                private_actions: vec![PrivateAction {
                    nullifier,
                    root: [0; 32],
                    commitment,
                    encrypted_post_state: EncryptedAccountData {
                        ciphertext: Ciphertext::from_inner(vec![]),
                        epk: EphemeralPublicKey(vec![]),
                        view_tag: 0,
                    },
                }],
                block_validity_window: BlockValidityWindow::new_unbounded(),
                timestamp_validity_window: TimestampValidityWindow::new_unbounded(),
                program_image_claims: vec![],
            },
            nonces,
            identities: vec![],
        }
    }

    #[test]
    fn a_privacy_preserving_message_has_a_pinned_layout_and_hash() {
        let public = Actor::new(AccountId::new([5; 32]), AccountId::new([6; 32]));
        let private = Actor::new(AccountId::new([9; 32]), AccountId::new([8; 32]));
        let message = Message {
            execution: PrivacyPreservingCircuitOutput {
                context: PublicExecutionContext {
                    actors: vec![public],
                    authorized_accounts: vec![AccountId::new([7; 32])],
                },
                boundary: vec![
                    BoundaryStep::CallPublic(PublicDelivery {
                        envelope: MessageEnvelope {
                            source: DeliverySource::Call(private.program_account_id),
                            to: public,
                            message: b"o".to_vec(),
                        },
                        grants: Vec::new(),
                        pda_seeds: Vec::new(),
                    }),
                    BoundaryStep::EnterPrivate(Assumption {
                        envelope: MessageEnvelope {
                            source: public,
                            to: private,
                            message: b"a".to_vec(),
                        },
                        grants: Vec::new(),
                        pda_seeds: Vec::new(),
                    }),
                    BoundaryStep::LeavePrivate,
                    BoundaryStep::ReturnPublic,
                ],
                casts: Vec::new(),
                consumed_message: None,
                private_actions: vec![],
                block_validity_window: BlockValidityWindow::new_unbounded(),
                timestamp_validity_window: TimestampValidityWindow::new_unbounded(),
                program_image_claims: vec![],
            },
            nonces: vec![Nonce(1)],
            identities: vec![],
        };

        let expected: Vec<u8> = [
            &[1, 0, 0, 0][..], // declared.public_actors: one actor
            &[5; 32],
            &[6; 32],
            &[1, 0, 0, 0], // declared.authorized_accounts: one account
            &[7; 32],
            &[4, 0, 0, 0], // boundary: four steps
            &[0],          // BoundaryStep::CallPublic
            &[1],          // source: DeliverySource::Call
            &[8; 32],
            &[5; 32], // to
            &[6; 32],
            &[1, 0, 0, 0], // message
            b"o",
            &[0, 0, 0, 0], // grants: none
            &[0, 0, 0, 0], // pda_seeds: none
            &[1],          // BoundaryStep::EnterPrivate
            &[5; 32],      // from
            &[6; 32],
            &[9; 32], // to
            &[8; 32],
            &[1, 0, 0, 0], // message
            b"a",
            &[0, 0, 0, 0], // grants: none
            &[0, 0, 0, 0], // pda_seeds: none
            &[2],          // BoundaryStep::LeavePrivate
            &[3],          // BoundaryStep::ReturnPublic
            &[0, 0, 0, 0], // casts: none
            &[0],          // consumed_message: None
            &[0, 0, 0, 0], // private_actions: none
            &[0, 0],       // block_validity_window: from None, to None
            &[0, 0],       // timestamp_validity_window: from None, to None
            &[0, 0, 0, 0], // program_image_claims: none
            &[1, 0, 0, 0], // nonces: one nonce, a little-endian u128
            &[1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
            &[0, 0, 0, 0], // identities: none
        ]
        .concat();

        assert_eq!(message.to_bytes(), expected);
        let digest: [u8; 32] = Sha256::digest([&PREFIX[..], &expected].concat()).into();
        assert_eq!(message.hash(), digest);
    }

    #[test]
    fn encrypted_account_data_constructor() {
        let npk = NullifierPublicKey::from(&[1; 32]);
        let vpk = ViewingPublicKey::from_seed(&[2_u8; 32], &[3_u8; 32]);
        let account = Account::default();
        let account_id =
            lee_core::account::AccountId::for_regular_private_account(&npk, &vpk, Identifier::ZERO);
        let nullifier = Nullifier::for_account_initialization(&account_id);
        let (shared_secret, epk) =
            SharedSecretKey::encapsulate_deterministic(&vpk, &EphemeralSecretKey([0_u8; 32]));
        let ciphertext = EncryptionScheme::encrypt(
            &account,
            &PrivateAccountKind::Regular(Identifier::ZERO),
            &shared_secret,
            &nullifier,
            None,
        );
        let encrypted_account_data =
            EncryptedAccountData::new(ciphertext.clone(), &npk, &vpk, epk.clone());

        let expected_view_tag = {
            let mut hasher = Sha256::new();
            hasher.update(b"/LEE/v0.3/ViewTag/");
            hasher.update(npk.to_byte_array());
            hasher.update(vpk.to_bytes());
            let digest: [u8; 32] = hasher.finalize().into();
            digest[0]
        };

        assert_eq!(encrypted_account_data.ciphertext, ciphertext);
        assert_eq!(encrypted_account_data.epk, epk);
        assert_eq!(
            encrypted_account_data.view_tag,
            EncryptedAccountData::compute_view_tag(&npk, &vpk)
        );
        assert_eq!(encrypted_account_data.view_tag, expected_view_tag);
    }
}
