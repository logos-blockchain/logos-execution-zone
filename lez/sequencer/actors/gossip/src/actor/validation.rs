//! Pure decision functions for inbound gossiped messages.
//!
//! The same stateless admission the RPC performs, minus mempool/seen-cache
//! side effects (those live in the gossip actor). Testable without a swarm.

use common::transaction::LeeTransaction;
use sequencer_channel_config_actor::Wire;
use sequencer_core::{config::BLOCK_OVERHEAD, gossip::AccreditedKeys};
use sequencer_slasher_actor::Approval;
use system_upgrader_core::SignedApproval;

#[derive(Debug)]
// `Accept` is intentionally left unboxed: it is the common outcome and the enum
// is short-lived per gossiped message, so boxing it would only add a heap
// allocation on the hot validation path.
pub enum TxEvaluation {
    /// Structurally valid and authenticated; forward and admit.
    Accept(LeeTransaction),
    /// Malformed / forbidden; do not forward. `GossipSub` peer scoring is not
    /// configured, so this does not currently penalize the propagating peer.
    Reject(String),
}

#[derive(Debug)]
pub enum SystemApprovalEvaluation {
    /// Correctly signed by an accredited key; forward and hand to the approval pool.
    Accept(SignedApproval),
    /// Nothing this node can use, but not the sender's fault.
    Ignore(String),
    Reject(String),
}

#[derive(Debug)]
pub enum ApprovalEvaluation {
    /// Correctly signed by the key it names; forward and hand to the slasher.
    Accept(Approval),
    /// Nothing this node can use, but not the sender's fault.
    Ignore(String),
    Reject(String),
}

#[derive(Debug)]
pub enum ConfigEvaluation {
    /// From a channel key; forward and hand to the channel-config actor.
    Accept(Wire),
    /// Nothing this node can use, but not the sender's fault.
    Ignore(String),
    Reject(String),
}

/// Decodes and stateless-checks a gossiped transaction the same way the RPC
/// admits a submitted one: size check, signature/witness check, then the
/// sequencer-only-program guard.
#[must_use]
pub fn evaluate_transaction(data: &[u8], max_block_size: u64) -> TxEvaluation {
    let tx_size = u64::try_from(data.len()).unwrap_or(u64::MAX);
    let max_tx_size = max_block_size.saturating_sub(BLOCK_OVERHEAD);
    if tx_size > max_tx_size {
        return TxEvaluation::Reject(format!("transaction too large: {tx_size} > {max_tx_size}"));
    }

    let tx: LeeTransaction = match borsh::from_slice(data) {
        Ok(tx) => tx,
        Err(err) => return TxEvaluation::Reject(format!("undecodable transaction: {err}")),
    };

    let authenticated = match tx.transaction_stateless_check() {
        Ok(tx) => tx,
        Err(err) => return TxEvaluation::Reject(format!("stateless check failed: {err:?}")),
    };

    if sequencer_core::is_sequencer_only_tx(&authenticated) {
        return TxEvaluation::Reject("sequencer-only program".to_owned());
    }

    TxEvaluation::Accept(authenticated)
}

/// Decodes a gossiped slash approval, drops it if the committee does not
/// accredit the key it names, then checks its signature.
///
/// The accreditation check comes first so that a minted key buys no Ed25519
/// verification on every node in the mesh.
///
/// `Ignore` rather than `Reject` because accreditation is head-relative.
#[must_use]
pub fn evaluate_approval(
    data: &[u8],
    channel_id: [u8; 32],
    accredited_keys: Option<&AccreditedKeys>,
) -> ApprovalEvaluation {
    let approval: Approval = match borsh::from_slice(data) {
        Ok(approval) => approval,
        Err(err) => return ApprovalEvaluation::Reject(format!("undecodable approval: {err}")),
    };

    if accredited_keys.is_some_and(|keys| !keys.contains(&approval.signer.to_bytes())) {
        return ApprovalEvaluation::Ignore("signer is not an accredited key".to_owned());
    }

    if approval.verify(channel_id) {
        ApprovalEvaluation::Accept(approval)
    } else {
        ApprovalEvaluation::Reject("approval signature does not verify".to_owned())
    }
}

/// Decodes a gossiped `system_upgrader` approval, drops it if the committee does not accredit the
/// key it names, then checks its signature. Accreditation comes first, as for slash approvals, so a
/// minted key buys no signature check. Expiry is left to the pool, which knows the head.
#[must_use]
pub fn evaluate_system_approval(
    data: &[u8],
    channel_id: [u8; 32],
    accredited_keys: Option<&AccreditedKeys>,
) -> SystemApprovalEvaluation {
    let signed: SignedApproval = match borsh::from_slice(data) {
        Ok(signed) => signed,
        Err(err) => {
            return SystemApprovalEvaluation::Reject(format!("undecodable approval: {err}"));
        }
    };

    if accredited_keys.is_some_and(|keys| !keys.contains(&signed.approval.signer.to_bytes())) {
        return SystemApprovalEvaluation::Ignore("signer is not an accredited key".to_owned());
    }

    if signed.approval.verify(channel_id, &signed.proposal) {
        SystemApprovalEvaluation::Accept(signed)
    } else {
        SystemApprovalEvaluation::Reject("approval signature does not verify".to_owned())
    }
}

/// Decodes a gossiped channel-config message and drops it unless `origin`
/// has stake on record.
///
/// Stake, not committee membership: a slash drops the key's entry, so a
/// slashed key is muted at once, while a key that asked to leave keeps its
/// entry and still signs for the channel until the config removing it lands.
///
/// `Ignore` rather than `Reject` because the staked set is head-relative.
#[must_use]
pub fn evaluate_config_message(
    data: &[u8],
    origin: Option<[u8; 32]>,
    staked_keys: Option<&AccreditedKeys>,
) -> ConfigEvaluation {
    let Some(message) = Wire::decode(data) else {
        return ConfigEvaluation::Reject("undecodable channel-config message".to_owned());
    };
    let Some(staked_keys) = staked_keys else {
        return ConfigEvaluation::Accept(message);
    };

    if origin.is_some_and(|origin| staked_keys.contains(&origin)) {
        ConfigEvaluation::Accept(message)
    } else {
        ConfigEvaluation::Ignore("originator has no stake on record".to_owned())
    }
}

#[cfg(test)]
mod tests {
    use logos_blockchain_core::proofs::channel_multi_sig_proof::IndexedSignature;
    use logos_blockchain_key_management_system_service::keys::Ed25519Key;
    use sequencer_channel_config_actor::Signature;
    use sequencer_slasher_actor::Offence;
    use sequencer_stake_core::SequencerKey;
    use testnet_initial_state::{initial_pub_accounts_private_keys, initial_public_user_accounts};

    use super::*;

    const CHANNEL: [u8; 32] = [7; 32];

    /// A correctly signed approval, and the signer's key bytes.
    fn signed_approval(secret: [u8; 32]) -> (Vec<u8>, [u8; 32]) {
        let key = Ed25519Key::from_bytes(&secret);
        let signer = SequencerKey::new(key.public_key().to_bytes()).expect("valid key");
        let offence = Offence {
            offender: SequencerKey::new([9; 32]).expect("valid key"),
            inscription: [3; 32],
        };
        let message = sequencer_stake_core::slash_approval_message(
            CHANNEL,
            offence.offender,
            offence.inscription,
        );
        let approval = Approval {
            offence,
            signer,
            signature: key.sign_payload(&message).to_bytes(),
        };
        (borsh::to_vec(&approval).unwrap(), signer.to_bytes())
    }

    #[test]
    fn an_unaccredited_signer_is_ignored_without_verifying() {
        let (bytes, _) = signed_approval([5; 32]);
        let accredited_keys = AccreditedKeys::from([[1; 32]]);
        // Correctly signed, so only the accreditation check can drop it.
        assert!(matches!(
            evaluate_approval(&bytes, CHANNEL, Some(&accredited_keys)),
            ApprovalEvaluation::Ignore(_)
        ));
    }

    /// A `system_upgrader` approval by `secret`, encoded as gossiped, and the signer's key.
    fn signed_system_approval(secret: [u8; 32], valid_until: u64) -> (Vec<u8>, [u8; 32]) {
        use sequencer_stake_core::ed25519_dalek::{Signer as _, SigningKey};
        use system_upgrader_core::{Approval, Proposal, SystemProgramName, approval_message};

        let key = SigningKey::from_bytes(&secret);
        let signer = key.verifying_key().to_bytes();
        let proposal = Proposal::Install {
            name: SystemProgramName::new(b"new"),
            first_segment: lee::AccountId::new([9; 32]),
        };
        let signed = SignedApproval {
            proposal,
            approval: Approval {
                signer: sequencer_stake_core::SequencerKey::new(signer).unwrap(),
                valid_until,
                signature: key
                    .sign(&approval_message(CHANNEL, &proposal, valid_until))
                    .to_bytes()
                    .to_vec(),
            },
        };
        (borsh::to_vec(&signed).unwrap(), signer)
    }

    #[test]
    fn system_approvals_are_screened_by_accreditation_then_signature() {
        let (bytes, signer) = signed_system_approval([5; 32], 40);
        assert!(matches!(
            evaluate_system_approval(&bytes, CHANNEL, Some(&AccreditedKeys::from([signer]))),
            SystemApprovalEvaluation::Accept(_)
        ));
        assert!(matches!(
            evaluate_system_approval(&bytes, CHANNEL, Some(&AccreditedKeys::from([[1; 32]]))),
            SystemApprovalEvaluation::Ignore(_)
        ));
        assert!(matches!(
            evaluate_system_approval(&bytes, [6; 32], Some(&AccreditedKeys::from([signer]))),
            SystemApprovalEvaluation::Reject(_)
        ));
        assert!(matches!(
            evaluate_system_approval(&[0xff], CHANNEL, None),
            SystemApprovalEvaluation::Reject(_)
        ));
    }

    #[test]
    fn an_accredited_signer_is_accepted() {
        let (bytes, signer) = signed_approval([5; 32]);
        let accredited_keys = AccreditedKeys::from([signer]);
        assert!(matches!(
            evaluate_approval(&bytes, CHANNEL, Some(&accredited_keys)),
            ApprovalEvaluation::Accept(_)
        ));
    }

    #[test]
    fn an_unknown_committee_filters_nothing() {
        let (bytes, _) = signed_approval([5; 32]);
        assert!(matches!(
            evaluate_approval(&bytes, CHANNEL, None),
            ApprovalEvaluation::Accept(_)
        ));
    }

    #[test]
    fn a_committee_accrediting_nobody_filters_everything() {
        let (bytes, _) = signed_approval([5; 32]);
        assert!(matches!(
            evaluate_approval(&bytes, CHANNEL, Some(&AccreditedKeys::new())),
            ApprovalEvaluation::Ignore(_)
        ));
    }

    fn valid_transaction() -> LeeTransaction {
        let acc1 = initial_public_user_accounts()[0].account_id;
        let acc2 = initial_public_user_accounts()[1].account_id;
        let sign_key1 = initial_pub_accounts_private_keys()[0].pub_sign_key.clone();
        common::test_utils::create_transaction_native_token_transfer(acc1, 0, acc2, 10, &sign_key1)
    }

    #[test]
    fn well_formed_transaction_is_accepted() {
        let tx = valid_transaction();
        let bytes = borsh::to_vec(&tx).unwrap();
        assert!(matches!(
            evaluate_transaction(&bytes, 1 << 20),
            TxEvaluation::Accept(_)
        ));
    }

    #[test]
    fn a_system_upgrader_tx_from_a_peer_is_rejected() {
        let message = lee::public_transaction::Message::try_new(
            system_upgrader_core::SYSTEM_UPGRADER_ACCOUNT_ID,
            vec![],
            vec![],
            system_upgrader_core::Instruction::Apply {
                name: system_upgrader_core::SystemProgramName::new(b"clock"),
                from_height: 1,
            },
        )
        .unwrap();
        let tx = LeeTransaction::Public(lee::PublicTransaction::new(
            message,
            lee::public_transaction::WitnessSet::from_raw_parts(vec![]),
        ));
        let bytes = borsh::to_vec(&tx).unwrap();
        assert!(matches!(
            evaluate_transaction(&bytes, 1 << 20),
            TxEvaluation::Reject(reason) if reason == "sequencer-only program"
        ));
    }

    #[test]
    fn garbage_bytes_are_rejected() {
        assert!(matches!(
            evaluate_transaction(&[0xff, 0xff, 0xff], 1 << 20),
            TxEvaluation::Reject(_)
        ));
    }

    #[test]
    fn oversize_transaction_is_rejected() {
        let tx = valid_transaction();
        let bytes = borsh::to_vec(&tx).unwrap();
        assert!(matches!(
            evaluate_transaction(&bytes, 1),
            TxEvaluation::Reject(_)
        ));
    }

    /// A channel-config signature as it goes on the wire.
    fn config_bytes() -> Vec<u8> {
        let key = Ed25519Key::from_bytes(&[5; 32]);
        Wire::Signature(Signature {
            tx_hash: [7; 32],
            signature: IndexedSignature::new(0, key.sign_payload(&[7; 32])),
        })
        .encode()
    }

    #[test]
    fn a_config_message_from_a_staked_key_is_accepted() {
        let staked_keys = AccreditedKeys::from([[1; 32], [2; 32]]);
        assert!(matches!(
            evaluate_config_message(&config_bytes(), Some([2; 32]), Some(&staked_keys)),
            ConfigEvaluation::Accept(_)
        ));
    }

    #[test]
    fn a_config_message_from_a_key_without_stake_is_ignored() {
        let staked_keys = AccreditedKeys::from([[1; 32]]);
        assert!(matches!(
            evaluate_config_message(&config_bytes(), Some([9; 32]), Some(&staked_keys)),
            ConfigEvaluation::Ignore(_)
        ));
    }

    #[test]
    fn an_anonymous_config_message_is_ignored_once_stake_is_known() {
        let staked_keys = AccreditedKeys::from([[1; 32]]);
        assert!(matches!(
            evaluate_config_message(&config_bytes(), None, Some(&staked_keys)),
            ConfigEvaluation::Ignore(_)
        ));
    }

    #[test]
    fn unknown_stake_filters_no_config_message() {
        assert!(matches!(
            evaluate_config_message(&config_bytes(), Some([9; 32]), None),
            ConfigEvaluation::Accept(_)
        ));
    }

    #[test]
    fn an_undecodable_config_message_is_rejected() {
        let staked_keys = AccreditedKeys::from([[1; 32]]);
        assert!(matches!(
            evaluate_config_message(&[99, 1, 2], Some([1; 32]), Some(&staked_keys)),
            ConfigEvaluation::Reject(_)
        ));
    }
}
