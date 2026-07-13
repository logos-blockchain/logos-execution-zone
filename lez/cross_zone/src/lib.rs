//! Host-side cross-zone helpers that need program ids (`programs`) or the state
//! machine (`lee`), kept out of the guest-pure cores. Mirrors `system_accounts`:
//! it resolves builtin program ids and bakes them into transactions and genesis
//! accounts for the watcher (sequencer) and verifier (indexer).

use std::collections::BTreeMap;

pub use cross_zone_inbox_core::{CrossZoneConfig, CrossZonePeer};
use cross_zone_inbox_core::{
    CrossZoneMessage, InboxConfig, Instruction, ZoneId, inbox_config_account_id,
    inbox_seen_shard_account_id,
};
use lee_core::{
    account::{Account, AccountId},
    program::ProgramId,
};

/// The cross-zone emission fields a watcher or verifier reads off a source
/// transaction, common to every emitter program.
pub struct Emission {
    pub target_zone: ZoneId,
    pub target_program_id: ProgramId,
    pub target_accounts: Vec<[u8; 32]>,
    pub payload: Vec<u8>,
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
    src_zone: ZoneId,
    src_block_id: u64,
    src_tx_index: u32,
    src_program_id: ProgramId,
    target_program_id: ProgramId,
    target_accounts: &[[u8; 32]],
    payload: Vec<u8>,
) -> lee::PublicTransaction {
    let msg = CrossZoneMessage {
        src_zone,
        src_block_id,
        src_tx_index,
        src_program_id,
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

/// Builds the inbox config account a zone seeds into genesis state.
///
/// Lets the inbox guest authorize inbound peer messages. The sequencer and
/// indexer seed the same account from the same config, keeping their replayed
/// state consistent.
#[must_use]
pub fn build_inbox_config_account(
    self_zone: ZoneId,
    cross_zone: &CrossZoneConfig,
) -> (AccountId, Account) {
    let inbox_id = programs::cross_zone_inbox().id();

    let mut allowed_targets = BTreeMap::new();
    for peer in &cross_zone.peers {
        allowed_targets.insert(peer.channel_id, peer.allowed_targets.clone());
    }
    let config = InboxConfig {
        self_zone,
        allowed_peers: BTreeMap::new(),
        allowed_targets,
    };

    let account = Account {
        program_owner: inbox_id,
        balance: 0,
        data: config
            .to_bytes()
            .try_into()
            .expect("inbox config fits in account data"),
        nonce: 0_u128.into(),
    };
    (inbox_config_account_id(inbox_id), account)
}

/// Builds the genesis holding account funding a holder's bridgeable balance.
///
/// Owned by `bridge_lock`, data is the LE balance. Not produced by any
/// transaction, so the sequencer and indexer both seed it through this one
/// builder.
#[must_use]
pub fn build_holding_account(holder: AccountId, amount: u128) -> (AccountId, Account) {
    let account = Account {
        program_owner: programs::bridge_lock().id(),
        data: bridge_lock_core::balance_bytes(amount)
            .to_vec()
            .try_into()
            .expect("balance fits in account data"),
        ..Default::default()
    };
    (holder, account)
}
