//! Signed fee fields and payer authorization.
//!
//! The fee fields live inside the hashed/signed message of every fee-bearing
//! transaction, so any signature over the message hash covers them. This
//! module carries the shared pieces: the field group itself, the designated
//! system payer, and the authorization check both public and program-deployment
//! transactions run.
//!
//! Nothing here *charges* anything — assessment and enforcement are wired later
//! (T8); this only makes the fields carryable and the payer authorizable.

use borsh::{BorshDeserialize, BorshSerialize};
use lee_core::account::AccountId;

use crate::public_transaction::WitnessSet;

/// The payer a system transaction designates.
///
/// System transactions (clock, bridge-deposit mints, cross-zone dispatches,
/// genesis actions) are fee-exempt and are recognized structurally, not by this
/// id; it exists so every message has one uniform shape.
pub const SYSTEM_PAYER: AccountId = AccountId::new([0_u8; 32]);

/// The fee fields carried inside a signed message.
///
/// Grouped only for construction; the fields are stored flat on each message so
/// their Borsh encoding is the plain concatenation
/// `payer ‖ gas_limit ‖ tip ‖ max_fee`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct FeeFields {
    /// The fee account, always designated explicitly, never inferred from the
    /// witness set.
    pub payer: AccountId,
    /// Execution bound; metering halts here.
    pub gas_limit: u64,
    /// Priority payment, MAY be 0.
    pub tip: u64,
    /// Signed cap on the fee reserve.
    pub max_fee: u128,
}

impl FeeFields {
    /// Zeroed fee fields: the shape system transactions carry, and the shape
    /// any transaction built without a fee intent carries.
    pub const ZERO: Self = Self {
        payer: SYSTEM_PAYER,
        gas_limit: 0,
        tip: 0,
        max_fee: 0,
    };

    #[must_use]
    pub const fn new(payer: AccountId, gas_limit: u64, tip: u64, max_fee: u128) -> Self {
        Self {
            payer,
            gas_limit,
            tip,
            max_fee,
        }
    }
}

/// A message that is hashed for signing and designates a fee payer.
///
/// Implemented by the public-transaction and program-deployment messages so
/// both share one witness set, one signing path and one authorization check.
pub trait SignedMessage {
    /// The 32-byte hash signers sign, domain-separated by the message's own
    /// prefix.
    fn signing_hash(&self) -> [u8; 32];

    /// The explicitly designated fee payer.
    fn payer(&self) -> AccountId;
}

/// The account ids whose fee authorization accompanies `message`.
///
/// Q1 (answered): authorization is an explicit designation plus a signature
/// over the fee fields and the exact transaction they cover. Both routes verify
/// against the same message hash — a witness signature (the payer is one of the
/// transaction's signers) or the dedicated fee witness (a sponsor outside the
/// witness set). Signatures that do not verify contribute nothing.
// TBA(Q1-program-auth): the ruling also allows a program authorization. Adding
// it means a third arm here and nowhere else.
#[must_use]
pub fn fee_authorized_account_ids<M: SignedMessage>(
    message: &M,
    witness_set: &WitnessSet,
) -> Vec<AccountId> {
    let message_hash = message.signing_hash();
    witness_set
        .signatures_and_public_keys()
        .iter()
        .chain(witness_set.fee_witness())
        .filter(|(signature, public_key)| signature.is_valid_for(&message_hash, public_key))
        .map(|(_, public_key)| AccountId::from(public_key))
        .collect()
}

/// Whether the payer `message` designates is authorized to pay its fees.
#[must_use]
pub fn is_fee_authorized<M: SignedMessage>(message: &M, witness_set: &WitnessSet) -> bool {
    fee_authorized_account_ids(message, witness_set).contains(&message.payer())
}

#[cfg(test)]
mod tests {
    use super::{FeeFields, SYSTEM_PAYER, fee_authorized_account_ids, is_fee_authorized};
    use crate::{
        AccountId, PrivateKey, PublicKey, Signature, program_deployment_transaction,
        public_transaction::{Message, WitnessSet},
    };

    fn key(seed: u8) -> PrivateKey {
        PrivateKey::try_new([seed; 32]).unwrap()
    }

    fn account_of(key: &PrivateKey) -> AccountId {
        AccountId::from(&PublicKey::new_from_private_key(key))
    }

    /// A message signed by `signer`, designating `payer` and real fee amounts.
    fn message_paid_by(payer: AccountId) -> Message {
        Message::new_preserialized(
            [1_u32; 8],
            vec![account_of(&key(1)), account_of(&key(2))],
            vec![0_u128.into(), 0_u128.into()],
            vec![],
            FeeFields::new(payer, 60_000, 100, 1_000_000),
        )
    }

    #[test]
    fn payer_that_is_a_signer_is_authorized() {
        let (signer, other) = (key(1), key(2));
        let message = message_paid_by(account_of(&signer));
        let witness_set = WitnessSet::for_message(&message, &[&signer, &other]);

        assert!(is_fee_authorized(&message, &witness_set));
        assert_eq!(
            fee_authorized_account_ids(&message, &witness_set),
            vec![account_of(&signer), account_of(&other)]
        );
    }

    #[test]
    fn payer_outside_the_witness_set_is_rejected_without_a_fee_witness() {
        let (signer, sponsor) = (key(1), key(3));
        let message = message_paid_by(account_of(&sponsor));
        let witness_set = WitnessSet::for_message(&message, &[&signer]);

        assert!(!is_fee_authorized(&message, &witness_set));
    }

    #[test]
    fn sponsored_payer_with_a_fee_witness_is_authorized() {
        let (signer, sponsor) = (key(1), key(3));
        let message = message_paid_by(account_of(&sponsor));
        let witness_set =
            WitnessSet::for_message(&message, &[&signer]).with_fee_signer(&message, &sponsor);

        assert!(is_fee_authorized(&message, &witness_set));
        assert!(witness_set.is_valid_for(&message));
    }

    #[test]
    fn fee_witness_for_a_different_account_does_not_authorize_the_payer() {
        let (signer, sponsor, stranger) = (key(1), key(3), key(4));
        let message = message_paid_by(account_of(&sponsor));
        let witness_set =
            WitnessSet::for_message(&message, &[&signer]).with_fee_signer(&message, &stranger);

        assert!(!is_fee_authorized(&message, &witness_set));
    }

    /// The fee witness carries the payer's public key but a signature made by
    /// somebody else: it verifies against neither key, so it authorizes nobody.
    #[test]
    fn fee_witness_with_a_mismatched_public_key_is_rejected() {
        let (signer, sponsor, forger) = (key(1), key(3), key(4));
        let message = message_paid_by(account_of(&sponsor));
        let mut witness_set = WitnessSet::for_message(&message, &[&signer]);
        witness_set.fee_witness = Some((
            Signature::new(&forger, &message.hash()),
            PublicKey::new_from_private_key(&sponsor),
        ));

        assert!(!is_fee_authorized(&message, &witness_set));
        assert!(!witness_set.is_valid_for(&message));
    }

    /// A fee witness over a different message hash — e.g. lifted from another
    /// transaction — does not carry over.
    #[test]
    fn fee_witness_over_another_message_is_rejected() {
        let (signer, sponsor) = (key(1), key(3));
        let other_message = message_paid_by(account_of(&signer));
        let message = message_paid_by(account_of(&sponsor));
        let mut witness_set = WitnessSet::for_message(&message, &[&signer]);
        witness_set.fee_witness = Some((
            Signature::new(&sponsor, &other_message.hash()),
            PublicKey::new_from_private_key(&sponsor),
        ));

        assert!(!is_fee_authorized(&message, &witness_set));
    }

    /// A witness signature that does not verify contributes no authorization,
    /// even when its public key derives the designated payer.
    #[test]
    fn invalid_signer_signature_does_not_authorize() {
        let signer = key(1);
        let message = message_paid_by(account_of(&signer));
        let mut witness_set = WitnessSet::for_message(&message, &[&signer]);
        witness_set.signatures_and_public_keys[0].0 = Signature::new_for_tests([1; 64]);

        assert!(!is_fee_authorized(&message, &witness_set));
        assert!(fee_authorized_account_ids(&message, &witness_set).is_empty());
    }

    #[test]
    fn no_witnesses_authorize_nobody() {
        let message = message_paid_by(account_of(&key(1)));
        let witness_set = WitnessSet::from_raw_parts(vec![]);

        assert!(!is_fee_authorized(&message, &witness_set));
        assert!(fee_authorized_account_ids(&message, &witness_set).is_empty());
    }

    /// The zeroed fee fields system transactions carry designate the system
    /// payer, which no key derives, so they are never fee-authorized. That is
    /// intended: system transactions are fee-exempt and are recognized
    /// structurally, not through this check.
    #[test]
    fn zeroed_fee_fields_designate_the_system_payer() {
        assert_eq!(FeeFields::ZERO.payer, SYSTEM_PAYER);
        let signer = key(1);
        let message = Message::new_preserialized(
            [1_u32; 8],
            vec![account_of(&signer)],
            vec![0_u128.into()],
            vec![],
            FeeFields::ZERO,
        );
        let witness_set = WitnessSet::for_message(&message, &[&signer]);

        assert!(!is_fee_authorized(&message, &witness_set));
    }

    /// Deployments run the same authorization machinery as public transactions,
    /// through the shared `SignedMessage` implementation.
    #[test]
    fn deployment_messages_use_the_same_authorization() {
        let (deployer, sponsor, stranger) = (key(1), key(3), key(4));
        let message = program_deployment_transaction::Message::new(
            vec![0x7F, 0x45, 0x4C, 0x46],
            FeeFields::new(account_of(&sponsor), 60_000, 0, 1_000_000),
        );

        let unsponsored = WitnessSet::for_message(&message, &[&deployer]);
        assert!(!is_fee_authorized(&message, &unsponsored));

        let sponsored = unsponsored.clone().with_fee_signer(&message, &sponsor);
        assert!(is_fee_authorized(&message, &sponsored));

        let wrong_sponsor = unsponsored.with_fee_signer(&message, &stranger);
        assert!(!is_fee_authorized(&message, &wrong_sponsor));

        // Payer-is-a-signer works for deployments too.
        let self_paid = program_deployment_transaction::Message::new(
            vec![0x7F, 0x45, 0x4C, 0x46],
            FeeFields::new(account_of(&deployer), 60_000, 0, 1_000_000),
        );
        assert!(is_fee_authorized(
            &self_paid,
            &WitnessSet::for_message(&self_paid, &[&deployer])
        ));
    }
}
