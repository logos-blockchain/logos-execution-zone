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

use std::collections::{BTreeMap, BTreeSet};

pub use acceptance::{
    CommitteeFloorState, FloorVerdict, KEPT_FLOOR_READ_FAILURES, Link, OffChain,
    STUCK_SLOT_ALERT_PASSES, ScreenRefusal, StallState, alerts_at, equivocation_report,
    link_to_tip, screen_peer_block,
};
use borsh::{BorshDeserialize, BorshSerialize};
use common::HashType;
use cross_zone_inbox_core::{
    CrossZoneMessage, InboxConfig, Message, ZoneId, inbox_config_account_id,
    inbox_seen_shard_account_id, inbox_seen_shard_seed,
};
use lee_core::{
    account::{AccountId, Actor, Balance},
    native_token::NATIVE_TOKEN_PROGRAM_ID,
    program::{PROGRAM_LOADER_ACCOUNT_ID, PdaSeed},
};
use serde::{Deserialize, Serialize};

pub mod acceptance;
#[cfg(any(test, feature = "test-utils"))]
pub mod test_utils;

/// The cross-zone emission fields a watcher or verifier reads off a source
/// transaction, common to every emitter program.
pub struct Emission {
    pub source: AccountId,
    pub target_zone: ZoneId,
    pub target_account_id: AccountId,
    pub target_accounts: Vec<Actor>,
    pub payload: Vec<u8>,
}

impl Emission {
    /// The ordinal only shapes the source-side outbox slot, so it is dropped.
    #[must_use]
    pub fn from_wire(source: AccountId, wire: cross_zone_emission_core::CrossZoneEmission) -> Self {
        Self {
            source,
            target_zone: wire.target_zone,
            target_account_id: wire.target_account_id,
            target_accounts: wire.target_accounts,
            payload: wire.payload,
        }
    }
}

/// One delivery a peer is allowed to make: a program on the peer that may emit,
/// paired with the program here it may reach.
///
/// The pair is the unit because the target authorizes a source, not a zone. A
/// bridging peer needs `wrapped_token` reachable, and `ping_sender` lets its
/// caller choose the target, so a zone-wide allowance would let it mint with no
/// lock behind it. That rule now lives in each target, seeded from these pairs at
/// genesis, rather than in the inbox.
/// Unknown fields are refused so a misspelled `mint_cap` fails startup instead
/// of silently seeding the source uncapped.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, BorshSerialize, BorshDeserialize)]
#[serde(deny_unknown_fields)]
pub struct CrossZoneRoute {
    /// The program on the peer zone that emitted the message.
    pub src_account_id: AccountId,
    /// The program on this zone it may be delivered to.
    pub target_account_id: AccountId,
    /// Lifetime mint allowance for this source at the target; `None` is
    /// uncapped. Only meaningful on a route whose target mints against the
    /// message (`wrapped_token`); genesis refuses it on any other target.
    #[serde(default)]
    pub mint_cap: Option<Balance>,
}

/// A peer zone whose outbox a zone watches for inbound cross-zone messages.
///
/// Unknown fields are refused so a stale or misspelled key in an operator
/// config fails startup instead of silently pinning nothing.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CrossZonePeer {
    /// The peer's Bedrock channel; its 32 bytes double as the peer's zone id.
    pub channel_id: ZoneId,
    /// Which of this peer's programs may reach which local program.
    ///
    /// No longer enforced in transit: the inbox delivers to whatever a message
    /// names, and the target refuses a source it did not authorize. This is the
    /// operator's statement of intent, fanned out at genesis into each target's
    /// own config. A route naming a program that does not authorize cross-zone
    /// sources is refused there, at genesis.
    pub allowed_routes: Vec<CrossZoneRoute>,
    /// Programs on this peer, beyond the builtins, read for emissions under the
    /// generic contract (see `cross_zone_emission_core::declared_emission`).
    ///
    /// Listing one asserts, unverifiably, that it honors that contract, that it
    /// panics on any tag-0 call it does not intend delivered (an abort is its
    /// only veto, from any of its actors), and that its code will not be
    /// swapped, since the id pins an account rather than code.
    ///
    /// Must match the indexer's copy: an emitter it lacks halts it as `Forged`.
    /// Builtin ids are refused at startup.
    #[serde(default)]
    pub emitters: Vec<AccountId>,
    /// Minimum live committee size (accredited keys on the peer's channel)
    /// below which reading from this peer is suspended, by the sequencer's
    /// watcher and the indexer's verifier alike. 0, the default, disables the
    /// floor, and a production peer should set it. With a floor set, a channel
    /// state unreadable before the first successful read counts as below it (fail-closed), while a
    /// bounded run of later read failures keeps the last known size. Unknown fields are
    /// refused above, so a misspelling fails startup instead of silently running floorless.
    #[serde(default)]
    pub min_committee_size: u32,
    /// Recomputed hash of the peer's genesis block. Set, a first read that
    /// hashes differently is refused; unset, the first genesis read is trusted
    /// as-is. A production peer should set it.
    #[serde(default)]
    pub genesis_hash: Option<HashType>,
}

/// Cross-zone configuration shared by a zone's sequencer (watcher) and indexer
/// (verifier): the peers it reads from Bedrock and, per peer, the deliveries the
/// operator intends each target to accept.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CrossZoneConfig {
    /// Read once at startup by the watchers and the verifier, so adding a peer
    /// zone needs a config change and a restart on both sequencer and indexer.
    /// Defaulted so a source-only zone declares `"cross_zone": {}`.
    #[serde(default)]
    pub peers: Vec<CrossZonePeer>,
    /// Account allowed to change which peer sources each target program accepts,
    /// seeded into every target's own config at genesis.
    ///
    /// Unset by default, which leaves those lists fixed at genesis. It can only
    /// ever be set at genesis and there is no rotation. One value seeds every
    /// target, including the ones that mint, and whoever holds it can authorize
    /// a source, so its compromise is theft rather than delay.
    #[serde(default)]
    pub source_authority: Option<AccountId>,
    /// Program allowed to act on the source authority's behalf by message, seeded
    /// into every target's config at genesis. Needed only for a PDA
    /// authority, which cannot sign; unset means the authority acts at top level.
    #[serde(default)]
    pub source_governance: Option<AccountId>,
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
    pub src_account_id: AccountId,
}

/// Whether a program may only be invoked by sequencer-origin transactions.
///
/// The cross-zone inbox is injected solely by the watcher; a user-submitted call
/// must be rejected at ingress, since `TransactionOrigin` is not carried in the
/// block.
#[must_use]
pub fn is_sequencer_only_program(account_id: AccountId) -> bool {
    account_id == programs::cross_zone_inbox_account_id()
}

/// Extracts the cross-zone emission from a source transaction.
///
/// Recognizes the builtin emitters through their own decoders and any program
/// in `peer_emitters` through the generic contract. The watcher and verifier
/// share this, so both sides must pass the same set; build it with
/// [`peer_emitter_set`].
#[must_use]
pub fn extract_emission(
    tx: &lee::PublicTransaction,
    peer_emitters: &BTreeSet<AccountId>,
) -> Option<Emission> {
    let lee::RootCall { to, message } = &tx.message().execution.root;
    if to.program_account_id == programs::ping_sender_account_id() {
        // Not every transaction to an emitter emits: `InitConfig` is one of its
        // messages, so a non-`Send` decode is an ordinary non-emitting tx.
        let Ok(ping_core::SenderMessage::Send { emission, .. }) = borsh::from_slice(message) else {
            return None;
        };
        Some(Emission::from_wire(to.program_account_id, emission))
    } else if to.program_account_id == programs::bridge_lock_account_id() {
        let Ok(bridge_lock_core::Message::Lock { emission, .. }) = borsh::from_slice(message)
        else {
            return None;
        };
        Some(Emission::from_wire(to.program_account_id, emission))
    } else if peer_emitters.contains(&to.program_account_id) {
        let emission = cross_zone_emission_core::declared_emission(message)?;
        Some(Emission::from_wire(to.program_account_id, emission))
    } else {
        None
    }
}

/// The validated registered-emitter set for one peer.
///
/// Panics on a builtin id: builtins are recognized by their own decoders, and
/// their encodings were never written against the generic contract, so their
/// ordinary transactions could be misread as emissions (the loader's tag-0
/// `WriteSegment` carries attacker-chosen bytes). A config typo must not cost
/// a channel silently.
#[must_use]
pub fn peer_emitter_set(peer: &CrossZonePeer) -> BTreeSet<AccountId> {
    let builtins = [
        programs::ping_sender_account_id(),
        programs::bridge_lock_account_id(),
        programs::cross_zone_inbox_account_id(),
        programs::cross_zone_outbox_account_id(),
        programs::ping_receiver_account_id(),
        programs::wrapped_token_account_id(),
        programs::fee_account_id(),
        programs::clock_account_id(),
        programs::bridge_account_id(),
        programs::sequencer_stake_account_id(),
        PROGRAM_LOADER_ACCOUNT_ID,
        NATIVE_TOKEN_PROGRAM_ID,
    ];
    for emitter in &peer.emitters {
        assert!(
            !builtins.contains(emitter),
            "cross-zone peer {} lists builtin program {emitter:?} as a registered emitter; builtins are recognized by their own decoders and must not be listed",
            hex::encode(peer.channel_id)
        );
    }
    peer.emitters.iter().copied().collect()
}

/// Builds the sequencer-origin dispatch transaction. Pure for fixed inputs, so
/// the watcher's injected tx and the indexer's re-derived tx are byte-identical.
fn build_inbox_dispatch_tx(
    inbox_id: AccountId,
    msg: &CrossZoneMessage,
    target_accounts: Vec<Actor>,
) -> lee::PublicTransaction {
    // The inbox's config and seen actors, then the target's coordinator the delivery
    // lands on, then the target's own actors the delivery reaches. Declared here
    // rather than by the guest, since a guest cannot conjure an actor; both the
    // watcher and the verifier build it through this one function.
    let config = Actor::new(inbox_config_account_id(inbox_id), inbox_id);
    let mut public_actors = Vec::with_capacity(target_accounts.len().saturating_add(3));
    public_actors.push(config);
    public_actors.push(Actor::new(
        inbox_seen_shard_account_id(inbox_id, &msg.src_zone, msg.src_block_id),
        inbox_id,
    ));
    public_actors.push(Actor::new(msg.target_account_id, msg.target_account_id));
    public_actors.extend(target_accounts);

    let message = lee::public_transaction::Message {
        admission_evidence: vec![lee::PublicAccountEvidence::Pda {
            program: inbox_id,
            seed: inbox_seen_shard_seed(&msg.src_zone, msg.src_block_id),
        }],
        ..lee::public_transaction::Message::try_new(
            config,
            public_actors,
            BTreeMap::new(),
            Message::Dispatch(msg.clone()),
        )
        .expect("inbox dispatch message must serialize")
    };

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
    target_account_id: AccountId,
    target_accounts: &[Actor],
    payload: Vec<u8>,
) -> lee::PublicTransaction {
    let msg = CrossZoneMessage {
        src_zone: source.src_zone,
        src_block_id: source.src_block_id,
        src_block_hash: source.src_block_hash,
        src_tx_index: source.src_tx_index,
        src_account_id: source.src_account_id,
        target_account_id,
        payload,
        l1_inclusion_witness: None,
    };
    build_inbox_dispatch_tx(
        programs::cross_zone_inbox_account_id(),
        &msg,
        target_accounts.to_vec(),
    )
}

/// The genesis transaction that initializes this zone's inbox config PDA.
///
/// The operator's per-peer routes no longer live here. They are fanned out into
/// each target program's own config, so all the inbox keeps is its zone id.
/// Replaying this seeds the same account on every node.
#[must_use]
pub fn build_inbox_init_config_tx(self_zone: ZoneId) -> lee::PublicTransaction {
    genesis_public_tx(
        programs::cross_zone_inbox_account_id(),
        cross_zone_inbox_core::inbox_config_seed(),
        Message::InitConfig(InboxConfig { self_zone }),
    )
}

/// The `(src_zone, src_account_id)` pairs the operator's routes name for one
/// target.
///
/// Panics on a route naming a program that does not authorize cross-zone sources.
/// Nothing downstream would notice otherwise: the route is dropped here, the
/// watcher no longer filters targets, and every delivery would be refused by a
/// program that never opted in, dead-lettering after three attempts. A typo in a
/// config file should not cost a channel silently.
///
/// Only the sequencer builds genesis, so an indexer handed the same typo starts
/// normally and only the sequencer refuses to boot.
fn sources_for_target(
    cross_zone: &CrossZoneConfig,
    target_account_id: AccountId,
) -> Vec<(ZoneId, AccountId, Option<Balance>)> {
    let mut sources = Vec::new();
    for peer in &cross_zone.peers {
        for route in &peer.allowed_routes {
            assert!(
                cross_zone_targets().contains(&route.target_account_id),
                "cross-zone route names {:?}, which does not authorize cross-zone sources",
                route.target_account_id
            );
            assert!(
                route.mint_cap.is_none()
                    || route.target_account_id == programs::wrapped_token_account_id(),
                "cross-zone route sets a mint cap, but its target {:?} does not mint",
                route.target_account_id
            );
            // A cap only the authority can raise, on a zone with no authority,
            // is a fuse with no replacement: once honest volume exhausts it,
            // every later delivery dead-letters and the peer's escrow strands.
            assert!(
                route.mint_cap.is_none() || cross_zone.source_authority.is_some(),
                "cross-zone route sets a mint cap, but no source_authority is configured to ever raise it"
            );
            if route.target_account_id == target_account_id {
                sources.push((peer.channel_id, route.src_account_id, route.mint_cap));
            }
        }
    }
    // Mint's counter advances the first matching entry, so a duplicated pair
    // would split one source's policy across entries an auditor reads as two.
    for (index, (zone, program, _)) in sources.iter().enumerate() {
        assert!(
            !sources[..index].iter().any(
                |(other_zone, other_program, _)| other_zone == zone && other_program == program
            ),
            "cross-zone routes list the same source twice for one target"
        );
    }
    sources
}

/// The programs a cross-zone route may name as a target on this zone.
fn cross_zone_targets() -> [AccountId; 2] {
    [
        programs::wrapped_token_account_id(),
        programs::ping_receiver_account_id(),
    ]
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
pub fn build_wrapped_token_init_config_tx(cross_zone: &CrossZoneConfig) -> lee::PublicTransaction {
    let wrapped_token_id = programs::wrapped_token_account_id();
    let sources = sources_for_target(cross_zone, wrapped_token_id)
        .into_iter()
        .map(
            |(src_zone, src_account_id, mint_cap)| wrapped_token_core::SourceEntry {
                policy: wrapped_token_core::SourcePolicy {
                    src_zone,
                    src_account_id,
                    mint_cap,
                },
                minted: 0,
            },
        )
        .collect();
    genesis_public_tx(
        wrapped_token_id,
        wrapped_token_core::config_seed(),
        wrapped_token_core::Message::InitConfig(wrapped_token_core::WrappedTokenConfig {
            minter: programs::cross_zone_inbox_account_id(),
            governance: cross_zone.source_governance,
            authority: cross_zone.source_authority,
            sources,
        }),
    )
}

/// The genesis transaction that pins the outbox `ping_sender` sends to,
/// without importing the outbox id into the guest.
#[must_use]
pub fn build_ping_sender_init_config_tx() -> lee::PublicTransaction {
    genesis_public_tx(
        programs::ping_sender_account_id(),
        ping_core::sender_config_seed(),
        ping_core::SenderMessage::InitConfig {
            outbox_account_id: programs::cross_zone_outbox_account_id(),
        },
    )
}

/// The genesis transaction that pins the outbox `bridge_lock` emits through and the
/// wrapped token it mints, without importing either id into the guest.
#[must_use]
pub fn build_bridge_lock_init_config_tx() -> lee::PublicTransaction {
    genesis_public_tx(
        programs::bridge_lock_account_id(),
        bridge_lock_core::config_seed(),
        bridge_lock_core::Message::InitConfig {
            outbox_account_id: programs::cross_zone_outbox_account_id(),
            target_account_id: programs::wrapped_token_account_id(),
        },
    )
}

/// The holding PDA a holder's bridgeable balance lives in.
#[must_use]
pub fn bridge_lock_holding_account_id(holder: AccountId) -> AccountId {
    bridge_lock_core::holding_account_id(programs::bridge_lock_account_id(), &holder.into_value())
}

/// The genesis transaction naming the peer sources `ping_receiver` accepts a
/// delivery from, fanned out of the operator's routes exactly as the wrapped
/// token's is.
#[must_use]
pub fn build_ping_receiver_init_config_tx(cross_zone: &CrossZoneConfig) -> lee::PublicTransaction {
    let receiver_id = programs::ping_receiver_account_id();
    // Caps are refused on non-minting targets above, so the cap is always
    // absent here and the receiver's pair list keeps its shape.
    let sources = sources_for_target(cross_zone, receiver_id)
        .into_iter()
        .map(|(src_zone, src_account_id, _)| (src_zone, src_account_id))
        .collect();
    genesis_public_tx(
        receiver_id,
        ping_core::receiver_config_seed(),
        ping_core::ReceiverMessage::InitConfig(ping_core::ReceiverConfig {
            deliverer: programs::cross_zone_inbox_account_id(),
            governance: cross_zone.source_governance,
            authority: cross_zone.source_authority,
            sources,
        }),
    )
}

/// Builds an unsigned, sequencer-origin genesis transaction sending `message` to `program`'s
/// config PDA under `seed`, the only actor an `InitConfig` touches.
fn genesis_public_tx<M: borsh::BorshSerialize>(
    program: AccountId,
    seed: PdaSeed,
    message: M,
) -> lee::PublicTransaction {
    let root = Actor::new(AccountId::for_public_pda(&program, &seed), program);
    let message = lee::public_transaction::Message {
        admission_evidence: vec![lee::PublicAccountEvidence::Pda { program, seed }],
        ..lee::public_transaction::Message::try_new(root, [root], BTreeMap::new(), message)
            .expect("genesis message must serialize")
    };
    lee::PublicTransaction::new(
        message,
        lee::public_transaction::WitnessSet::from_raw_parts(vec![]),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Unwraps the public transaction the test emissions are built as.
    fn public(tx: common::transaction::LeeTransaction) -> lee::PublicTransaction {
        let common::transaction::LeeTransaction::Public(tx) = tx else {
            panic!("test emissions are public transactions");
        };
        tx
    }

    fn peer_with_emitters(emitters: Vec<AccountId>) -> CrossZonePeer {
        CrossZonePeer {
            channel_id: [2; 32],
            allowed_routes: vec![],
            min_committee_size: 0,
            genesis_hash: None,
            emitters,
        }
    }

    #[test]
    fn a_registered_emitter_is_recognized_through_the_generic_contract() {
        let emitter = AccountId::new([8; 32]);
        let target = AccountId::new([9; 32]);
        let tx = public(test_utils::generic_emission(
            emitter, [2; 32], target, b"hi",
        ));

        let emission = extract_emission(&tx, &BTreeSet::from([emitter]))
            .expect("a registered emitter's tag-0 instruction is an emission");
        assert_eq!(emission.source, emitter);
        assert_eq!(emission.target_zone, [2; 32]);
        assert_eq!(emission.target_account_id, target);
        assert_eq!(emission.payload, b"hi".to_vec());

        assert!(
            extract_emission(&tx, &BTreeSet::new()).is_none(),
            "the same transaction is invisible while the emitter is unregistered"
        );
    }

    fn wire_emission() -> cross_zone_emission_core::CrossZoneEmission {
        cross_zone_emission_core::CrossZoneEmission {
            target_zone: [2; 32],
            target_account_id: AccountId::new([9; 32]),
            target_accounts: vec![],
            payload: vec![0xAA],
            ordinal: 0,
        }
    }

    #[test]
    fn trailing_program_fields_do_not_hide_a_registered_emission() {
        let emitter = AccountId::new([8; 32]);
        let mut instruction =
            cross_zone_emission_core::emitting_instruction_bytes(&wire_emission());
        instruction.extend_from_slice(&[0xDE, 0xAD]);
        let tx = public(test_utils::emitter_instruction(emitter, instruction));

        let emission = extract_emission(&tx, &BTreeSet::from([emitter]))
            .expect("trailing fields are the emitter's own");
        assert_eq!(emission.payload, vec![0xAA]);
    }

    #[test]
    fn a_non_zero_tag_from_a_registered_emitter_is_not_an_emission() {
        let emitter = AccountId::new([8; 32]);
        let mut instruction =
            cross_zone_emission_core::emitting_instruction_bytes(&wire_emission());
        instruction[0] = 1;
        let tx = public(test_utils::emitter_instruction(emitter, instruction));

        assert!(extract_emission(&tx, &BTreeSet::from([emitter])).is_none());
    }

    #[test]
    fn the_builtin_ping_sender_arm_ignores_the_registered_set() {
        let tx = public(test_utils::ping_emission(
            [2; 32],
            programs::ping_receiver_account_id(),
            b"hi",
        ));
        for set in [BTreeSet::new(), BTreeSet::from([AccountId::new([8; 32])])] {
            let emission =
                extract_emission(&tx, &set).expect("ping_sender is recognized by its own decoder");
            assert_eq!(emission.source, programs::ping_sender_account_id());
        }
    }

    #[test]
    #[should_panic(expected = "must not be listed")]
    fn a_builtin_listed_as_a_registered_emitter_is_refused() {
        let _set = peer_emitter_set(&peer_with_emitters(
            vec![programs::ping_sender_account_id()],
        ));
    }

    #[test]
    #[should_panic(expected = "must not be listed")]
    fn the_program_loader_listed_as_a_registered_emitter_is_refused() {
        let _set = peer_emitter_set(&peer_with_emitters(vec![PROGRAM_LOADER_ACCOUNT_ID]));
    }

    #[test]
    fn the_registered_emitter_set_is_the_peers_list() {
        let emitters = vec![AccountId::new([8; 32]), AccountId::new([9; 32])];
        assert_eq!(
            peer_emitter_set(&peer_with_emitters(emitters.clone())),
            emitters.into_iter().collect::<BTreeSet<_>>()
        );
    }

    /// A route naming a program that never opted into cross-zone sources is an
    /// operator typo that nothing downstream would report: the fan-out would drop
    /// it, the watcher no longer filters targets, and every delivery would be
    /// refused by the target and dead-lettered.
    #[test]
    #[should_panic(expected = "does not authorize cross-zone sources")]
    fn a_route_to_a_program_that_does_not_authorize_sources_is_refused() {
        let cross_zone = CrossZoneConfig {
            peers: vec![CrossZonePeer {
                channel_id: [2; 32],
                allowed_routes: vec![CrossZoneRoute {
                    src_account_id: programs::bridge_lock_account_id(),
                    target_account_id: programs::fee_account_id(),
                    mint_cap: None,
                }],
                min_committee_size: 0,
                genesis_hash: None,
                emitters: vec![],
            }],
            source_authority: None,
            source_governance: None,
        };
        let _tx = build_wrapped_token_init_config_tx(&cross_zone);
    }

    /// A capped route on an authority-less zone is a fuse with no replacement:
    /// once honest volume exhausts the cap, every later delivery dead-letters
    /// and the peer's escrow strands, so genesis refuses the combination.
    #[test]
    #[should_panic(expected = "no source_authority is configured")]
    fn a_capped_route_without_an_authority_is_refused() {
        let cross_zone = CrossZoneConfig {
            peers: vec![CrossZonePeer {
                channel_id: [2; 32],
                allowed_routes: vec![CrossZoneRoute {
                    src_account_id: programs::bridge_lock_account_id(),
                    target_account_id: programs::wrapped_token_account_id(),
                    mint_cap: Some(1_000),
                }],
                min_committee_size: 0,
                genesis_hash: None,
                emitters: vec![],
            }],
            source_authority: None,
            source_governance: None,
        };
        let _tx = build_wrapped_token_init_config_tx(&cross_zone);
    }

    /// Mint advances the first matching entry, so a source listed twice would
    /// split one policy across entries an auditor reads as two.
    #[test]
    #[should_panic(expected = "same source twice")]
    fn a_duplicated_route_for_one_target_is_refused() {
        let route = CrossZoneRoute {
            src_account_id: programs::bridge_lock_account_id(),
            target_account_id: programs::wrapped_token_account_id(),
            mint_cap: None,
        };
        let cross_zone = CrossZoneConfig {
            peers: vec![CrossZonePeer {
                channel_id: [2; 32],
                allowed_routes: vec![route.clone(), route],
                min_committee_size: 0,
                genesis_hash: None,
                emitters: vec![],
            }],
            source_authority: None,
            source_governance: None,
        };
        let _tx = build_wrapped_token_init_config_tx(&cross_zone);
    }

    #[test]
    fn a_genesis_init_config_carries_the_evidence_deriving_its_root() {
        let cross_zone = CrossZoneConfig {
            peers: Vec::new(),
            source_authority: None,
            source_governance: None,
        };
        for tx in [
            build_inbox_init_config_tx([1; 32]),
            build_wrapped_token_init_config_tx(&cross_zone),
            build_ping_sender_init_config_tx(),
            build_bridge_lock_init_config_tx(),
            build_ping_receiver_init_config_tx(&cross_zone),
        ] {
            let root = tx.message.execution.root.to;
            assert!(
                matches!(
                    &*tx.message.admission_evidence,
                    [evidence @ lee::PublicAccountEvidence::Pda { program, .. }]
                        if *program == root.program_account_id
                            && evidence.account_id() == root.account_id
                ),
                "{root:?} carries {:?}",
                tx.message.admission_evidence
            );
        }
    }

    #[test]
    fn a_dispatch_carries_the_evidence_of_the_seen_shard_it_declares() {
        let tx = build_dispatch_from_emission(
            &EmissionSource {
                src_zone: [3; 32],
                src_block_id: 7,
                src_block_hash: [4; 32],
                src_tx_index: 0,
                src_account_id: AccountId::new([5; 32]),
            },
            programs::ping_receiver_account_id(),
            &[],
            Vec::new(),
        );

        let inbox_id = programs::cross_zone_inbox_account_id();
        let shard = Actor::new(inbox_seen_shard_account_id(inbox_id, &[3; 32], 7), inbox_id);
        assert!(tx.message.public_context.actors.contains(&shard));
        assert_eq!(
            tx.message
                .admission_evidence
                .iter()
                .map(lee::PublicAccountEvidence::account_id)
                .collect::<Vec<_>>(),
            vec![shard.account_id]
        );
    }
}
