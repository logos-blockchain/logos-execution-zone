//! A funded private sender, its transfers, and channel entries, for tests.

use std::collections::{BTreeMap, BTreeSet};

use common::{block::Block, transaction::LeeTransaction};
use lee::{
    Account, AccountId, Actor, RootCall, TransactionEntry, V03State,
    privacy_preserving_transaction::circuit::ProgramCatalog,
    test_utils::{TestPrivateKeys, no_seal, update_witness},
};
use lee_core::{
    EphemeralSecretKey, PrivateAccountKind, Recipient, RecipientEncryption, SenderPresentation,
    native_token,
};
use logos_blockchain_core::mantle::ops::channel::MsgId;
use logos_blockchain_zone_sdk::Slot;

use crate::ChannelEntry;

/// The alias a private sender presents under; its opening is bound for refunds.
pub const ALIAS_OPENING: [u8; 32] = [9; 32];

/// The private account [`private_transfer`] spends from.
fn private_sender() -> (TestPrivateKeys, Account) {
    (
        TestPrivateKeys {
            ask: lee_core::AuthorizationSecretKey([0x71; 32]),
            d: [0x72; 32],
            z: [0x73; 32],
        },
        Account::funded(1_000_000_000),
    )
}

/// `state` with the private sender funded.
#[must_use]
pub fn with_private_sender(state: V03State) -> V03State {
    let (keys, funded) = private_sender();
    state.with_private_accounts([(
        lee_core::Commitment::new(&keys.account_id(), &funded),
        lee_core::Nullifier::for_account_initialization(&keys.account_id(), &keys.nsk()),
    )])
}

/// A transfer out of the private sender over `state`, paying its fee inside the proof.
#[must_use]
pub fn private_transfer(state: &V03State) -> LeeTransaction {
    let sender = private_sender();
    let recipient = testnet_initial_state::initial_public_user_accounts()[1].account_id;
    let paying = |amount| {
        let fee = inbox_fee(amount, sender.0.account_id());
        private_tx_presented(state, &sender, recipient, 10, Some(fee), false)
    };
    paying(required_for(0, paying))
}

/// A deshielding transfer of `amount` from the private `sender` to a public `recipient`, paying
/// `fee` inside the proof, the sender presented under [`ALIAS_OPENING`] and bound for refunds, or
/// canonically and unbound.
#[must_use]
pub fn private_tx_presented(
    state: &V03State,
    (keys, funded): &(TestPrivateKeys, lee::Account),
    recipient: AccountId,
    amount: u128,
    fee: Option<lee_core::FeeTransfer>,
    bound: bool,
) -> LeeTransaction {
    let public_actors = vec![
        Actor::native_balance(recipient),
        Actor::native_balance(system_accounts::fee_inbox_account_id()),
    ];
    let public_actor_states = public_actors
        .iter()
        .map(|actor| {
            (
                *actor,
                state
                    .get_account_by_id(actor.account_id)
                    .data
                    .actor_state(actor.program_account_id)
                    .clone(),
            )
        })
        .collect();
    let membership_proof = state
        .get_proof_for_commitment(&lee_core::Commitment::new(&keys.account_id(), funded))
        .expect("the sender's commitment is in state");
    let (output, proof) = lee::execute_and_prove(
        lee::ProvingInput {
            claims: Vec::new(),
            root: TransactionEntry::Sync(RootCall {
                to: Actor::native_balance(keys.account_id()),
                message: borsh::to_vec(&native_token::Message::Transfer {
                    to: recipient,
                    amount,
                })
                .unwrap(),
            }),
            fee,
            public_context: lee::PublicExecutionContext::new(public_actors, []),
            private_witnesses: vec![update_witness(keys, funded.clone(), membership_proof)],
            dummy_inputs: Vec::new(),
            ciphertext_padding: None,
            recoveries: bound
                .then(|| RecipientEncryption {
                    recipient: Recipient {
                        npk: keys.npk(),
                        vpk: keys.vpk(),
                        kind: PrivateAccountKind::Regular,
                        opening: Some(ALIAS_OPENING),
                    },
                    esk: EphemeralSecretKey([1; 32]),
                })
                .into_iter()
                .collect(),
            private_promotions: BTreeSet::new(),
        },
        &lee::Simulation {
            public_actor_states,
            admitted_accounts: None,
        },
        &ProgramCatalog::default(),
        |_| {
            if bound {
                SenderPresentation::Blinded(ALIAS_OPENING)
            } else {
                SenderPresentation::Canonical
            }
        },
        |_, _| false,
        no_seal,
    )
    .expect("the private transfer proves");
    let message =
        lee::privacy_preserving_transaction::Message::from_circuit_output(BTreeMap::new(), output);
    LeeTransaction::PrivacyPreserving(lee::PrivacyPreservingTransaction::new(
        message,
        lee::privacy_preserving_transaction::WitnessSet::from_raw_parts(vec![], proof),
    ))
}

/// The base fee the transaction `build` makes owes for `cycles` at genesis, measured on a build
/// paying nothing: the amount is fixed-width, so it leaves the size alone.
#[must_use]
pub fn required_for(cycles: u64, build: impl Fn(u128) -> LeeTransaction) -> u128 {
    let size = build(0).charged_bytes().expect("a transaction's size");
    fee_core::assess::private_fee_required(cycles, size, 8, 8)
}

#[must_use]
pub fn inbox_fee(amount: u128, payer: AccountId) -> lee_core::FeeTransfer {
    lee_core::FeeTransfer {
        payer,
        recipient: system_accounts::fee_inbox_account_id(),
        amount,
        refund_to: None,
    }
}

/// Entries chained from the root, each placing its block by its signer at its slot.
#[must_use]
pub fn lineage(blocks: &[(&Block, [u8; 32], u64)]) -> Vec<ChannelEntry> {
    let mut parent = MsgId::root();
    blocks
        .iter()
        .zip(1_u8..)
        .map(|(&(block, signer, slot), n)| {
            let entry = ChannelEntry {
                msg: MsgId::from([n; 32]),
                parent,
                signer: Some(signer),
                slot: Some(Slot::from(slot)),
                block: Some(block.digested()),
            };
            parent = entry.msg;
            entry
        })
        .collect()
}
