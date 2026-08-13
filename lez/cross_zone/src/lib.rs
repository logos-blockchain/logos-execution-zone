//! Host-side cross-zone helpers that need program ids (`programs`) or the state
//! machine (`lee`), kept out of the guest-pure cores. Mirrors `system_accounts`:
//! it resolves builtin program ids and bakes them into transactions and genesis
//! accounts for the watcher (sequencer) and verifier (indexer).
//!
//! This crate is the reference LEZ-to-LEZ adapter: it re-derives each delivery
//! byte-for-byte from a peer LEZ zone's finalized blocks, valid only because the
//! peer runs identical LEZ code. A non-LEZ peer needs a separate adapter with its
//! own block-reading, emission-extraction, delivery-building, and trust model; a
//! shared trait is best lifted from that first real adapter, not from this one.

use std::collections::BTreeMap;

pub use cross_zone_inbox_core::{CrossZoneConfig, CrossZonePeer};
use cross_zone_inbox_core::{
    CrossZoneMessage, InboxConfig, Instruction, ZoneId, inbox_config_account_id,
    inbox_seen_shard_account_id,
};
use lee_core::{
    account::{Account, AccountId, Balance},
    program::ProgramId,
};
use serde::Serialize;

/// The cross-zone emission fields a watcher or verifier reads off a source
/// transaction, common to every emitter program.
pub struct Emission {
    pub target_zone: ZoneId,
    pub target_program_id: ProgramId,
    pub target_accounts: Vec<[u8; 32]>,
    pub payload: Vec<u8>,
}

/// Where a delivery came from on the peer chain.
///
/// One struct so the watcher and the verifier fill the same field list: their
/// dispatch transactions for one emission must be byte-identical.
///
/// `src_block_hash` is the recomputed hash on both sides, never the declared
/// `header.hash`, which the signature does not cover.
pub struct EmissionSource {
    pub src_zone: ZoneId,
    pub src_block_id: u64,
    pub src_block_hash: [u8; 32],
    pub src_tx_index: u32,
    pub src_program_id: ProgramId,
}

/// Whether a program may only be invoked by sequencer-origin transactions.
///
/// The cross-zone inbox is injected solely by the watcher; a user-submitted call
/// must be rejected at ingress, since `TransactionOrigin` is not carried in the
/// block.
#[must_use]
pub fn is_sequencer_only_program(program_id: ProgramId) -> bool {
    program_id == programs::cross_zone_inbox().id()
}

/// Extracts the cross-zone emission from a source transaction.
///
/// Recognizes the known emitter programs (`ping_sender`, `bridge_lock`). The
/// watcher and verifier both use this so they agree on what a given source tx
/// emits.
#[must_use]
pub fn extract_emission(program_id: ProgramId, instruction_data: &[u32]) -> Option<Emission> {
    if program_id == programs::ping_sender().id() {
        let ping_core::SenderInstruction::Send {
            target_zone,
            target_program_id,
            target_accounts,
            payload,
            ..
        } = risc0_zkvm::serde::from_slice(instruction_data).ok()?;
        Some(Emission {
            target_zone,
            target_program_id,
            target_accounts,
            payload,
        })
    } else if program_id == programs::bridge_lock().id() {
        let bridge_lock_core::Instruction::Lock {
            target_zone,
            target_program_id,
            target_accounts,
            payload,
            ..
        } = risc0_zkvm::serde::from_slice(instruction_data).ok()?;
        Some(Emission {
            target_zone,
            target_program_id,
            target_accounts,
            payload,
        })
    } else {
        None
    }
}

/// Builds the sequencer-origin dispatch transaction. Pure for fixed inputs, so
/// the watcher's injected tx and the indexer's re-derived tx are byte-identical.
fn build_inbox_dispatch_tx(
    inbox_id: ProgramId,
    msg: &CrossZoneMessage,
    target_account_ids: Vec<AccountId>,
) -> lee::PublicTransaction {
    let mut account_ids = Vec::with_capacity(target_account_ids.len().saturating_add(2));
    account_ids.push(inbox_config_account_id(inbox_id));
    account_ids.push(inbox_seen_shard_account_id(
        inbox_id,
        &msg.src_zone,
        msg.src_block_id,
    ));
    account_ids.extend(target_account_ids);

    let message = lee::public_transaction::Message::try_new(
        inbox_id,
        account_ids,
        vec![],
        Instruction::Dispatch(msg.clone()),
    )
    .expect("inbox dispatch instruction must serialize");

    lee::PublicTransaction::new(
        message,
        lee::public_transaction::WitnessSet::from_raw_parts(vec![]),
    )
}

/// Builds the dispatch transaction for one peer emission.
///
/// Both the sequencer's watcher and the indexer's verifier go through this so
/// their transactions are byte-identical for the same emission (the basis of the
/// Option B check).
#[must_use]
pub fn build_dispatch_from_emission(
    source: &EmissionSource,
    target_program_id: ProgramId,
    target_accounts: &[[u8; 32]],
    payload: Vec<u8>,
) -> lee::PublicTransaction {
    let msg = CrossZoneMessage {
        src_zone: source.src_zone,
        src_block_id: source.src_block_id,
        src_block_hash: source.src_block_hash,
        src_tx_index: source.src_tx_index,
        src_program_id: source.src_program_id,
        target_program_id,
        payload,
        l1_inclusion_witness: None,
    };
    let target_ids = target_accounts
        .iter()
        .copied()
        .map(AccountId::new)
        .collect();
    build_inbox_dispatch_tx(programs::cross_zone_inbox().id(), &msg, target_ids)
}

/// The inbox config a zone derives from its cross-zone config: the per-peer
/// delivery routes plus its own zone id.
fn inbox_config(self_zone: ZoneId, cross_zone: &CrossZoneConfig) -> InboxConfig {
    let mut allowed_routes = BTreeMap::new();
    for peer in &cross_zone.peers {
        allowed_routes.insert(peer.channel_id, peer.allowed_routes.clone());
    }
    InboxConfig {
        self_zone,
        allowed_routes,
    }
}

/// The genesis transaction that initializes this zone's inbox config PDA.
///
/// Lets the inbox guest authorize inbound peer messages; replaying it seeds the
/// same account on every node, keeping their state consistent.
#[must_use]
pub fn build_inbox_init_config_tx(
    self_zone: ZoneId,
    cross_zone: &CrossZoneConfig,
) -> lee::PublicTransaction {
    let inbox_id = programs::cross_zone_inbox().id();
    genesis_public_tx(
        inbox_id,
        vec![inbox_config_account_id(inbox_id)],
        Instruction::InitConfig(inbox_config(self_zone, cross_zone)),
    )
}

/// Builds the genesis holding account funding a holder's bridgeable balance.
///
/// A real native balance owned by `bridge_lock`, which can debit it on a lock; it
/// is conserved like any other balance. Not produced by any transaction, so the
/// sequencer and indexer both seed it through this one builder.
#[must_use]
pub fn build_holding_account(holder: AccountId, amount: Balance) -> (AccountId, Account) {
    let account = Account {
        program_owner: programs::bridge_lock().id(),
        balance: amount,
        ..Default::default()
    };
    (holder, account)
}

/// The genesis transaction that pins the cross-zone inbox as the wrapped-token
/// minter, without importing the inbox id into the guest.
#[must_use]
pub fn build_wrapped_token_init_config_tx() -> lee::PublicTransaction {
    let wrapped_token_id = programs::wrapped_token().id();
    genesis_public_tx(
        wrapped_token_id,
        vec![wrapped_token_core::config_account_id(wrapped_token_id)],
        wrapped_token_core::Instruction::InitConfig {
            minter: programs::cross_zone_inbox().id(),
        },
    )
}

/// Builds an unsigned, sequencer-origin genesis transaction invoking `instruction`
/// on `program_id` over `account_ids`.
fn genesis_public_tx<I: Serialize>(
    program_id: ProgramId,
    account_ids: Vec<AccountId>,
    instruction: I,
) -> lee::PublicTransaction {
    let message =
        lee::public_transaction::Message::try_new(program_id, account_ids, vec![], instruction)
            .expect("genesis instruction must serialize");
    lee::PublicTransaction::new(
        message,
        lee::public_transaction::WitnessSet::from_raw_parts(vec![]),
    )
}
