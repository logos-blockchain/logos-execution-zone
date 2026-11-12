//! A funded private sender, its transfers, and channel entries, for tests.

use std::collections::{BTreeMap, BTreeSet};

use common::{block::Block, transaction::LeeTransaction};
use lee::{
    Account, Actor, PrivacyPreservingTransaction, RootCall, TransactionEntry, V03State,
    privacy_preserving_transaction::{Message, WitnessSet, circuit::ProgramCatalog},
    test_utils::{TestPrivateKeys, no_seal, update_witness},
};
use logos_blockchain_core::mantle::ops::channel::MsgId;
use logos_blockchain_zone_sdk::Slot;

use crate::ChannelEntry;

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
    // The fee's amount is fixed-width, so a transfer paying nothing measures the one that pays.
    let size = private_transfer_paying(state, 0)
        .charged_bytes()
        .expect("a transfer's size");
    private_transfer_paying(state, fee_core::assess::private_fee_required(0, size, 8, 8))
}

fn private_transfer_paying(state: &V03State, fee: u128) -> LeeTransaction {
    let (keys, funded) = private_sender();
    let recipient = testnet_initial_state::initial_public_user_accounts()[1].account_id;
    let fee_inbox = system_accounts::fee_inbox_account_id();
    let public_actors = vec![
        Actor::native_balance(recipient),
        Actor::native_balance(fee_inbox),
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
        .get_proof_for_commitment(&lee_core::Commitment::new(&keys.account_id(), &funded))
        .expect("the sender's commitment is in state");
    let (output, proof) = lee::execute_and_prove(
        lee::ProvingInput {
            claims: Vec::new(),
            root: TransactionEntry::Sync(RootCall {
                to: Actor::native_balance(keys.account_id()),
                message: borsh::to_vec(&lee_core::native_token::Message::Transfer {
                    to: recipient,
                    amount: 10,
                })
                .unwrap(),
            }),
            public_context: lee::PublicExecutionContext::new(public_actors, []),
            private_witnesses: vec![update_witness(&keys, funded, membership_proof)],
            dummy_inputs: Vec::new(),
            ciphertext_padding: None,
            recoveries: Vec::new(),
            private_promotions: BTreeSet::new(),
            fee: Some(lee_core::FeeTransfer {
                payer: keys.account_id(),
                recipient: fee_inbox,
                amount: fee,
                refund_to: None,
            }),
        },
        &lee::Simulation {
            public_actor_states,
            admitted_accounts: None,
        },
        &ProgramCatalog::default(),
        |_| lee::SenderPresentation::Canonical,
        |_, _| false,
        no_seal,
    )
    .expect("the private transfer proves");
    LeeTransaction::PrivacyPreserving(PrivacyPreservingTransaction::new(
        Message::from_circuit_output(BTreeMap::new(), output),
        WitnessSet::from_raw_parts(vec![], proof),
    ))
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
