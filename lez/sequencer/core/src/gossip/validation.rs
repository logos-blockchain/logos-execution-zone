//! Pure decision function for an inbound gossip message.
//!
//! The same stateless admission the RPC performs, minus mempool/seen-cache
//! side effects (those live in the drive task). Testable without a swarm.

use common::transaction::LeeTransaction;
use sequencer_stake_core::{
    SequencerKey,
    ed25519_dalek::{Signature, VerifyingKey},
    slash_approval_message,
};

use crate::gossip::message::{GossipMessage, SlashApprovalMessage};

/// Reserve ~200 bytes for block header overhead, mirroring the RPC check.
const BLOCK_HEADER_OVERHEAD: u64 = 200;

#[derive(Debug)]
pub enum Evaluation {
    /// Structurally valid and authenticated; forward and admit.
    Transaction(LeeTransaction),
    /// Signature checked against its signer; forward and collect.
    SlashApproval(SlashApprovalMessage),
    /// Malformed / forbidden; do not forward. `GossipSub` peer scoring is not
    /// configured, so this does not currently penalize the propagating peer.
    Reject(String),
}

/// Decodes and stateless-checks a gossip message.
#[must_use]
pub fn evaluate_message(data: &[u8], max_block_size: u64) -> Evaluation {
    let size = u64::try_from(data.len()).unwrap_or(u64::MAX);
    let max_size = max_block_size.saturating_sub(BLOCK_HEADER_OVERHEAD);
    if size > max_size {
        return Evaluation::Reject(format!("message too large: {size} > {max_size}"));
    }

    match borsh::from_slice::<GossipMessage>(data) {
        Ok(GossipMessage::Transaction(tx)) => evaluate_transaction(tx),
        Ok(GossipMessage::SlashApproval(approval)) => evaluate_slash_approval(approval),
        Err(err) => Evaluation::Reject(format!("undecodable message: {err}")),
    }
}

fn evaluate_transaction(tx: LeeTransaction) -> Evaluation {
    let authenticated = match tx.transaction_stateless_check() {
        Ok(tx) => tx,
        Err(err) => return Evaluation::Reject(format!("stateless check failed: {err:?}")),
    };

    if let LeeTransaction::Public(public_tx) = &authenticated
        && crate::is_sequencer_only_program(public_tx.message().program_id)
    {
        return Evaluation::Reject("sequencer-only program".to_owned());
    }

    Evaluation::Transaction(authenticated)
}

/// Accreditation is not checked here; that needs chain state and happens on collection.
fn evaluate_slash_approval(approval: SlashApprovalMessage) -> Evaluation {
    let (Some(offender), Some(_)) = (
        SequencerKey::new(approval.offender),
        SequencerKey::new(approval.signer),
    ) else {
        return Evaluation::Reject("approval names an invalid Ed25519 key".to_owned());
    };

    let Ok(verifying_key) = VerifyingKey::from_bytes(&approval.signer) else {
        return Evaluation::Reject("approval signer is not a valid Ed25519 key".to_owned());
    };
    let message = slash_approval_message(offender, approval.inscription);
    if verifying_key
        .verify_strict(&message, &Signature::from_bytes(&approval.signature))
        .is_err()
    {
        return Evaluation::Reject("approval signature does not verify".to_owned());
    }

    Evaluation::SlashApproval(approval)
}

#[cfg(test)]
mod tests {
    use logos_blockchain_key_management_system_service::keys::Ed25519Key;
    use testnet_initial_state::{initial_pub_accounts_private_keys, initial_public_user_accounts};

    use super::*;

    const INSCRIPTION: [u8; 32] = [7; 32];

    fn valid_transaction() -> LeeTransaction {
        let acc1 = initial_public_user_accounts()[0].account_id;
        let acc2 = initial_public_user_accounts()[1].account_id;
        let sign_key1 = initial_pub_accounts_private_keys()[0].pub_sign_key.clone();
        common::test_utils::create_transaction_native_token_transfer(acc1, 0, acc2, 10, &sign_key1)
    }

    fn encoded(message: &GossipMessage) -> Vec<u8> {
        borsh::to_vec(message).unwrap()
    }

    #[test]
    fn well_formed_transaction_is_accepted() {
        let bytes = encoded(&GossipMessage::Transaction(valid_transaction()));
        assert!(matches!(
            evaluate_message(&bytes, 1 << 20),
            Evaluation::Transaction(_)
        ));
    }

    #[test]
    fn garbage_bytes_are_rejected() {
        assert!(matches!(
            evaluate_message(&[0xff, 0xff, 0xff], 1 << 20),
            Evaluation::Reject(_)
        ));
    }

    #[test]
    fn oversize_transaction_is_rejected() {
        let bytes = encoded(&GossipMessage::Transaction(valid_transaction()));
        assert!(matches!(evaluate_message(&bytes, 1), Evaluation::Reject(_)));
    }

    #[test]
    fn a_signed_approval_is_accepted_and_a_tampered_one_is_not() {
        let key = Ed25519Key::from_bytes(&[5; 32]);
        let offender =
            SequencerKey::new(Ed25519Key::from_bytes(&[6; 32]).public_key().to_bytes()).unwrap();
        let signer = SequencerKey::new(key.public_key().to_bytes()).unwrap();
        let signature = key.sign_payload(&slash_approval_message(offender, INSCRIPTION));

        let approval = SlashApprovalMessage {
            offender: offender.to_bytes(),
            inscription: INSCRIPTION,
            signer: signer.to_bytes(),
            signature: signature.to_bytes(),
        };
        assert!(matches!(
            evaluate_message(
                &encoded(&GossipMessage::SlashApproval(approval.clone())),
                1 << 20
            ),
            Evaluation::SlashApproval(_)
        ));

        // The signature covers the inscription, so naming another one breaks it.
        let tampered = SlashApprovalMessage {
            inscription: [8; 32],
            ..approval
        };
        assert!(matches!(
            evaluate_message(&encoded(&GossipMessage::SlashApproval(tampered)), 1 << 20),
            Evaluation::Reject(_)
        ));
    }
}
