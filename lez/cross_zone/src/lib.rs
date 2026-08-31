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

pub use acceptance::{
    Link, OffChain, STUCK_SLOT_ALERT_PASSES, ScreenRefusal, StallState, alerts_at,
    equivocation_report, link_to_tip, pinned_keys, screen_peer_block, signed_by_any,
};
pub use cross_zone_inbox_core::{CrossZoneConfig, CrossZonePeer};
use cross_zone_inbox_core::{
    CrossZoneMessage, InboxConfig, Instruction, ZoneId, inbox_config_account_id,
    inbox_seen_shard_account_id, inbox_source_marker_account_id,
};
use lee_core::{
    account::{Account, AccountId, Balance},
    program::ProgramId,
};

pub mod acceptance;
#[cfg(any(test, feature = "test-utils"))]
pub mod test_utils;

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
    /// The emitting program's dispatch address on the peer zone, read verbatim off its
    /// `OutboxRecord.emitter` (state-machine-verified on the peer, not derivable from any
    /// `ProgramId`).
    pub src_account_id: AccountId,
}

/// Whether a program may only be invoked by sequencer-origin transactions.
///
/// The cross-zone inbox is injected solely by the watcher; a user-submitted call
/// must be rejected at ingress, since `TransactionOrigin` is not carried in the
/// block. Compares the dispatch address directly: a `ProgramId` round-trip
/// through `AccountId::from` is only exact under the legacy bijection scheme.
#[must_use]
pub fn is_sequencer_only_program(account_id: AccountId) -> bool {
    account_id
        == program_loader_core::immutable_deploy_account_id(programs::cross_zone_inbox().id())
}

/// Extracts the cross-zone emission from a source transaction.
///
/// Recognizes the known emitter programs (`ping_sender`, `bridge_lock`), matched
/// by their real dispatch address. The watcher and verifier both use this so
/// they agree on what a given source tx emits.
#[must_use]
pub fn extract_emission(account_id: AccountId, instruction_data: &[u8]) -> Option<Emission> {
    if account_id == program_loader_core::immutable_deploy_account_id(programs::ping_sender().id())
    {
        // Not every transaction to an emitter emits: `InitConfig` is one of its
        // instructions, so a non-`Send` decode is an ordinary non-emitting tx.
        let Ok(ping_core::SenderInstruction::Send {
            target_zone,
            target_program_id,
            target_accounts,
            payload,
            ..
        }) = borsh::from_slice(instruction_data)
        else {
            return None;
        };
        Some(Emission {
            target_zone,
            target_program_id,
            target_accounts,
            payload,
        })
    } else if account_id
        == program_loader_core::immutable_deploy_account_id(programs::bridge_lock().id())
    {
        let Ok(bridge_lock_core::Instruction::Lock {
            target_zone,
            target_program_id,
            target_accounts,
            payload,
            ..
        }) = borsh::from_slice(instruction_data)
        else {
            return None;
        };
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
    let inbox_account_id = program_loader_core::immutable_deploy_account_id(inbox_id);
    let mut account_ids = Vec::with_capacity(target_account_ids.len().saturating_add(3));
    account_ids.push(inbox_config_account_id(inbox_account_id));
    account_ids.push(inbox_seen_shard_account_id(
        inbox_account_id,
        &msg.src_zone,
        msg.src_block_id,
    ));
    // Declared here rather than derived by the guest, since a guest cannot
    // conjure an account. Both the watcher and the verifier build it through this
    // one function, so they cannot disagree about the source a target will see.
    account_ids.push(inbox_source_marker_account_id(
        inbox_account_id,
        &msg.src_zone,
        msg.src_account_id,
    ));
    account_ids.extend(target_account_ids);

    let message = lee::public_transaction::Message::try_new(
        inbox_account_id,
        account_ids,
        vec![],
        Instruction::Dispatch {
            message: msg.clone(),
        },
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
        src_account_id: source.src_account_id,
        target_account_id: program_loader_core::immutable_deploy_account_id(target_program_id),
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

/// The genesis transaction that initializes this zone's inbox config PDA.
///
/// The operator's per-peer routes no longer live here. They are fanned out into
/// each target program's own config, so all the inbox keeps is its zone id.
/// Replaying this seeds the same account on every node.
#[must_use]
pub fn build_inbox_init_config_tx(self_zone: ZoneId) -> lee::PublicTransaction {
    let inbox_id = programs::cross_zone_inbox().id();
    let inbox_account_id = program_loader_core::immutable_deploy_account_id(inbox_id);
    genesis_public_tx(
        inbox_id,
        vec![inbox_config_account_id(inbox_account_id)],
        Instruction::InitConfig {
            config: InboxConfig { self_zone },
        },
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
        program_owner: program_loader_core::immutable_deploy_account_id(
            programs::bridge_lock().id(),
        ),
        balance: amount,
        ..Default::default()
    };
    (holder, account)
}

/// The `(src_zone, src_account_id)` pairs the operator's routes name for one
/// target.
fn sources_for_target(
    cross_zone: Option<&CrossZoneConfig>,
    target_account_id: AccountId,
) -> Vec<(ZoneId, AccountId)> {
    let Some(cross_zone) = cross_zone else {
        return Vec::new();
    };
    let mut sources = Vec::new();
    for peer in &cross_zone.peers {
        for route in &peer.allowed_routes {
            if route.target_account_id == target_account_id {
                sources.push((peer.channel_id, route.src_account_id));
            }
        }
    }
    sources
}

/// The genesis transaction that pins the cross-zone inbox as the wrapped-token
/// minter and names the peer sources it may mint for, without importing either id
/// into the guest.
///
/// The sources are the operator's own peer routes aimed at this token, moved from
/// the inbox's allowlist to the token's own config: the same information, enforced
/// by the program that owns the value. A zone with no peers gets an empty list,
/// which authorizes nothing, and the config is still seeded so its PDA cannot be
/// claimed by a first initializer.
#[must_use]
pub fn build_wrapped_token_init_config_tx(
    cross_zone: Option<&CrossZoneConfig>,
) -> lee::PublicTransaction {
    let wrapped_token_id = programs::wrapped_token().id();
    let wrapped_token_account_id =
        program_loader_core::immutable_deploy_account_id(wrapped_token_id);
    let sources = sources_for_target(cross_zone, wrapped_token_account_id);
    genesis_public_tx(
        wrapped_token_id,
        vec![wrapped_token_core::config_account_id(
            wrapped_token_account_id,
        )],
        wrapped_token_core::Instruction::InitConfig {
            config: wrapped_token_core::WrappedTokenConfig {
                minter: program_loader_core::immutable_deploy_account_id(
                    programs::cross_zone_inbox().id(),
                ),
                governance: cross_zone
                    .and_then(|cross_zone| cross_zone.source_governance)
                    .map(program_loader_core::immutable_deploy_account_id),
                authority: cross_zone.and_then(|cross_zone| cross_zone.source_authority),
                sources,
            },
        },
    )
}

/// The genesis transaction that pins the outbox `ping_sender` chains into,
/// without importing the outbox id into the guest.
#[must_use]
pub fn build_ping_sender_init_config_tx() -> lee::PublicTransaction {
    let ping_sender_id = programs::ping_sender().id();
    let ping_sender_account_id = program_loader_core::immutable_deploy_account_id(ping_sender_id);
    let outbox_id = programs::cross_zone_outbox().id();
    genesis_public_tx(
        ping_sender_id,
        vec![ping_core::sender_config_account_id(ping_sender_account_id)],
        ping_core::SenderInstruction::InitConfig {
            outbox_account_id: program_loader_core::immutable_deploy_account_id(outbox_id),
        },
    )
}

/// The genesis transaction that pins the outbox `bridge_lock` chains into and the
/// wrapped token it mints, without importing either id into the guest.
#[must_use]
pub fn build_bridge_lock_init_config_tx() -> lee::PublicTransaction {
    let bridge_lock_id = programs::bridge_lock().id();
    let bridge_lock_account_id = program_loader_core::immutable_deploy_account_id(bridge_lock_id);
    let outbox_id = programs::cross_zone_outbox().id();
    genesis_public_tx(
        bridge_lock_id,
        vec![bridge_lock_core::config_account_id(bridge_lock_account_id)],
        bridge_lock_core::Instruction::InitConfig {
            outbox_account_id: program_loader_core::immutable_deploy_account_id(outbox_id),
            target_program_id: programs::wrapped_token().id(),
        },
    )
}

/// The genesis transaction naming the peer sources `ping_receiver` accepts a
/// delivery from, fanned out of the operator's routes exactly as the wrapped
/// token's is.
#[must_use]
pub fn build_ping_receiver_init_config_tx(
    cross_zone: Option<&CrossZoneConfig>,
) -> lee::PublicTransaction {
    let receiver_id = programs::ping_receiver().id();
    let receiver_account_id = program_loader_core::immutable_deploy_account_id(receiver_id);
    let sources = sources_for_target(cross_zone, receiver_account_id);
    genesis_public_tx(
        receiver_id,
        vec![ping_core::receiver_config_account_id(receiver_account_id)],
        ping_core::ReceiverInstruction::InitConfig {
            config: ping_core::ReceiverConfig {
                deliverer: program_loader_core::immutable_deploy_account_id(
                    programs::cross_zone_inbox().id(),
                ),
                governance: cross_zone
                    .and_then(|cross_zone| cross_zone.source_governance)
                    .map(program_loader_core::immutable_deploy_account_id),
                authority: cross_zone.and_then(|cross_zone| cross_zone.source_authority),
                sources,
            },
        },
    )
}

/// Builds an unsigned, sequencer-origin genesis transaction invoking `instruction`
/// on `program_id` over `account_ids`.
fn genesis_public_tx<I: borsh::BorshSerialize>(
    program_id: ProgramId,
    account_ids: Vec<AccountId>,
    instruction: I,
) -> lee::PublicTransaction {
    let message = lee::public_transaction::Message::try_new(
        program_loader_core::immutable_deploy_account_id(program_id),
        account_ids,
        vec![],
        instruction,
    )
    .expect("genesis instruction must serialize");
    lee::PublicTransaction::new(
        message,
        lee::public_transaction::WitnessSet::from_raw_parts(vec![]),
    )
}
