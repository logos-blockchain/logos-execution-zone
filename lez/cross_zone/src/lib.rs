//! Host-side cross-zone helpers that need program ids (`programs`) or the state machine (`lee`),
//! kept out of the guest-pure cores.

use std::collections::BTreeMap;

pub use acceptance::{
    CommitteeFloorState, FloorVerdict, Link, OffChain, ScreenRefusal, StallState, alerts_at,
    link_to_tip, log_equivocation, screen_peer_block,
};
use borsh::{BorshDeserialize, BorshSerialize};
use common::HashType;
use cross_zone_inbox_core::{
    CrossZoneMessage, InboxConfig, Message, ZoneId, inbox_config_account_id,
    inbox_seen_shard_account_id, inbox_seen_shard_seed,
};
use lee_core::{
    account::{AccountId, Actor, Balance},
    program::PdaSeed,
};
use serde::{Deserialize, Serialize};

pub mod acceptance;
#[cfg(any(test, feature = "test-utils"))]
pub mod test_utils;

/// One delivery a peer is allowed to make: a program on the peer that may emit, paired with the
/// program here it may reach.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, BorshSerialize, BorshDeserialize)]
#[serde(deny_unknown_fields)]
pub struct CrossZoneRoute {
    /// The program on the peer zone that emitted the message, from any of its actors at any call
    /// depth; a source that must stay top-level asserts it in its own guest.
    pub src_account_id: AccountId,
    /// The program on this zone it may be delivered to.
    pub target_account_id: AccountId,
    /// Lifetime mint allowance for this source at the target; `None` is uncapped.
    #[serde(default)]
    pub mint_cap: Option<Balance>,
}

/// A peer zone whose blocks a zone watches for inbound cross-zone messages.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CrossZonePeer {
    /// The peer's Bedrock channel; its 32 bytes double as the peer's zone id.
    pub channel_id: ZoneId,
    /// Which of this peer's programs may reach which local program.
    pub allowed_routes: Vec<CrossZoneRoute>,
    /// Minimum live committee size (accredited keys on the peer's channel) below which reading
    /// from this peer is suspended, by the sequencer's watcher and the indexer's verifier alike.
    #[serde(default)]
    pub min_committee_size: u32,
    /// Recomputed hash of the peer's genesis block.
    #[serde(default)]
    pub genesis_hash: Option<HashType>,
}

/// Cross-zone configuration shared by a zone's sequencer (watcher) and indexer (verifier): the
/// peers it reads from Bedrock and, per peer, the deliveries the operator intends each target to
/// accept.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CrossZoneConfig {
    /// Read once at startup by the watchers and the verifier, so adding a peer zone needs a config
    /// change and a restart on both sequencer and indexer.
    #[serde(default)]
    pub peers: Vec<CrossZonePeer>,
    /// The zones `bridge_lock` may name as a lock target on this zone, the send-direction
    /// counterpart of `peers`, seeded into its config at genesis.
    pub lock_target_zones: Vec<ZoneId>,
    /// Account allowed to change which peer sources each target program accepts, seeded into every
    /// target's own config at genesis.
    #[serde(default)]
    pub source_authority: Option<AccountId>,
    /// Program allowed to act on the source authority's behalf by message, seeded into every
    /// target's config at genesis.
    #[serde(default)]
    pub source_governance: Option<AccountId>,
}

/// Where a delivery came from on the peer chain.
pub struct OutboundSource {
    pub src_zone: ZoneId,
    pub src_block_id: u64,
    pub src_block_hash: [u8; 32],
    pub src_outbound_index: u32,
}

/// Whether a program may only be invoked by sequencer-origin transactions.
#[must_use]
pub fn is_sequencer_only_program(account_id: AccountId) -> bool {
    account_id == programs::cross_zone_inbox_account_id()
        || account_id == programs::fee_account_id()
        || account_id == programs::system_upgrader_account_id()
}

fn build_inbox_dispatch_tx(
    inbox_id: AccountId,
    msg: &CrossZoneMessage,
    accounts: Vec<Actor>,
) -> lee::PublicTransaction {
    let config = Actor::new(inbox_config_account_id(inbox_id), inbox_id);
    let mut public_actors = Vec::with_capacity(accounts.len().saturating_add(3));
    public_actors.push(config);
    public_actors.push(Actor::new(
        inbox_seen_shard_account_id(inbox_id, &msg.src_zone, msg.src_block_id),
        inbox_id,
    ));
    public_actors.push(msg.target);
    public_actors.extend(accounts);

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

/// Builds the dispatch transaction for one message of a peer block's outbound list.
#[must_use]
pub fn build_dispatch(
    source: &OutboundSource,
    message: &lee::OutboundMessage,
) -> lee::PublicTransaction {
    let msg = CrossZoneMessage {
        src_zone: source.src_zone,
        src_block_id: source.src_block_id,
        src_block_hash: source.src_block_hash,
        src_outbound_index: source.src_outbound_index,
        src_account_id: message.from.program_account_id,
        target: message.to,
        payload: message.message.clone(),
        l1_inclusion_witness: None,
    };
    build_inbox_dispatch_tx(
        programs::cross_zone_inbox_account_id(),
        &msg,
        message.accounts.clone(),
    )
}

/// The genesis transaction that initializes this zone's inbox config PDA.
#[must_use]
pub fn build_inbox_init_config_tx(self_zone: ZoneId) -> lee::PublicTransaction {
    genesis_public_tx(
        programs::cross_zone_inbox_account_id(),
        cross_zone_inbox_core::inbox_config_seed(),
        Message::InitConfig(InboxConfig { self_zone }),
    )
}

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
            assert!(
                route.mint_cap.is_none() || cross_zone.source_authority.is_some(),
                "cross-zone route sets a mint cap, but no source_authority is configured to ever raise it"
            );
            if route.target_account_id == target_account_id {
                sources.push((peer.channel_id, route.src_account_id, route.mint_cap));
            }
        }
    }
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

fn cross_zone_targets() -> [AccountId; 2] {
    [
        programs::wrapped_token_account_id(),
        programs::ping_receiver_account_id(),
    ]
}

/// The genesis transaction that pins the cross-zone inbox as the wrapped-token minter and names the
/// peer sources it may mint for, without importing either id into the guest.
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

/// The genesis transaction that pins the wrapped token `bridge_lock` mints and the zones it may
/// lock to, without importing their ids into the guest.
#[must_use]
pub fn build_bridge_lock_init_config_tx(cross_zone: &CrossZoneConfig) -> lee::PublicTransaction {
    genesis_public_tx(
        programs::bridge_lock_account_id(),
        bridge_lock_core::config_seed(),
        bridge_lock_core::Message::InitConfig {
            target_account_id: programs::wrapped_token_account_id(),
            lock_target_zones: cross_zone.lock_target_zones.clone(),
        },
    )
}

/// The holding PDA a holder's bridgeable balance lives in.
#[must_use]
pub fn bridge_lock_holding_account_id(holder: AccountId) -> AccountId {
    bridge_lock_core::holding_account_id(programs::bridge_lock_account_id(), &holder.into_value())
}

/// The genesis transaction naming the peer sources `ping_receiver` accepts a delivery from, fanned
/// out of the operator's routes exactly as the wrapped token's is.
#[must_use]
pub fn build_ping_receiver_init_config_tx(cross_zone: &CrossZoneConfig) -> lee::PublicTransaction {
    let receiver_id = programs::ping_receiver_account_id();
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

/// Builds an unsigned, sequencer-origin genesis transaction sending `message` to `program`'s config
/// PDA under `seed`, the only actor an `InitConfig` touches.
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
            }],
            lock_target_zones: Vec::new(),
            source_authority: None,
            source_governance: None,
        };
        let _tx = build_wrapped_token_init_config_tx(&cross_zone);
    }

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
            }],
            lock_target_zones: Vec::new(),
            source_authority: None,
            source_governance: None,
        };
        let _tx = build_wrapped_token_init_config_tx(&cross_zone);
    }

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
            }],
            lock_target_zones: Vec::new(),
            source_authority: None,
            source_governance: None,
        };
        let _tx = build_wrapped_token_init_config_tx(&cross_zone);
    }

    #[test]
    fn a_genesis_init_config_carries_the_evidence_deriving_its_root() {
        let cross_zone = CrossZoneConfig {
            peers: Vec::new(),
            lock_target_zones: Vec::new(),
            source_authority: None,
            source_governance: None,
        };
        for tx in [
            build_inbox_init_config_tx([1; 32]),
            build_wrapped_token_init_config_tx(&cross_zone),
            build_bridge_lock_init_config_tx(&cross_zone),
            build_ping_receiver_init_config_tx(&cross_zone),
        ] {
            let root = tx.message.execution.root.to.actor();
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
    fn a_genesis_bridge_lock_config_carries_the_zones_it_may_lock_to() {
        let cross_zone = CrossZoneConfig {
            peers: Vec::new(),
            lock_target_zones: vec![[7; 32], [8; 32]],
            source_authority: None,
            source_governance: None,
        };
        let tx = build_bridge_lock_init_config_tx(&cross_zone);
        assert_eq!(
            borsh::from_slice::<bridge_lock_core::Message>(&tx.message.execution.root.message)
                .expect("the init config decodes"),
            bridge_lock_core::Message::InitConfig {
                target_account_id: programs::wrapped_token_account_id(),
                lock_target_zones: vec![[7; 32], [8; 32]],
            }
        );
    }

    #[test]
    fn a_dispatch_carries_the_evidence_of_the_seen_shard_it_declares() {
        let receiver = programs::ping_receiver_account_id();
        let tx = build_dispatch(
            &OutboundSource {
                src_zone: [3; 32],
                src_block_id: 7,
                src_block_hash: [4; 32],
                src_outbound_index: 0,
            },
            &lee::OutboundMessage {
                from: Actor::new(AccountId::new([5; 32]), AccountId::new([5; 32])),
                zone: [3; 32],
                to: Actor::new(receiver, receiver),
                message: Vec::new(),
                accounts: Vec::new(),
            },
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
