use cross_zone_inbox_core::{
    InboxConfig, Instruction, SeenShard, ZoneId, inbox_config_account_id,
    inbox_seen_shard_account_id,
};
use cross_zone_marker_core::inbox_source_marker_account_id;
use lee_core::{
    account::{AccountId, ProgramShardSelector},
    program::{
        AccountMeta, ChainedCall, LeeCall, Plan, ProgramInput, read_lee_call, resolve_keep,
        resolve_write,
    },
};

#[derive(borsh::BorshSerialize, borsh::BorshDeserialize)]
enum Effect {
    ForeignZone(ZoneId),
    MarkDelivery {
        src_block_hash: [u8; 32],
        src_tx_index: u32,
    },
    /// Requiring the delivery to already be recorded is what makes the replay no-op sound.
    RequireDelivered {
        src_block_hash: [u8; 32],
        src_tx_index: u32,
    },
    InitConfig(InboxConfig),
}

fn main() {
    match read_lee_call::<Instruction>() {
        LeeCall::Execute(input, instruction_data) => execute(&input, instruction_data),
        LeeCall::Resolve(input) => {
            let effect =
                borsh::from_slice(&input.effect_data).expect("the inbox wrote its own effect");
            match resolve_effect(&effect, &input.pre_data) {
                None => resolve_keep(input),
                Some(data) => {
                    resolve_write(input, data.try_into().expect("data fits in account data"))
                }
            }
        }
    }
}

fn resolve_effect(effect: &Effect, pre_data: &[u8]) -> Option<Vec<u8>> {
    match effect {
        Effect::ForeignZone(src_zone) => {
            let cfg = InboxConfig::from_bytes(pre_data).expect("inbox config decodes");
            assert!(
                *src_zone != cfg.self_zone,
                "Source zone must not be this zone"
            );
            None
        }
        Effect::MarkDelivery {
            src_block_hash,
            src_tx_index,
        } => {
            let mut shard = seen_shard(pre_data, src_block_hash);
            assert!(
                !shard.contains(*src_tx_index),
                "Dispatch claims to be a first delivery but this one is already recorded"
            );
            shard.insert(*src_block_hash, *src_tx_index);
            Some(shard.to_bytes())
        }
        Effect::RequireDelivered {
            src_block_hash,
            src_tx_index,
        } => {
            let shard = seen_shard(pre_data, src_block_hash);
            assert!(
                shard.contains(*src_tx_index),
                "Dispatch claims to be a replay but this delivery was never recorded"
            );
            None
        }
        Effect::InitConfig(config) => {
            let bytes = config.to_bytes();
            // Genesis is replayed onto seeded state during multi-sequencer reconstruction, so
            // a written config must already hold exactly this.
            if !pre_data.is_empty() {
                assert_eq!(
                    pre_data, bytes,
                    "inbox config already initialized differently"
                );
            }
            Some(bytes)
        }
    }
}

/// One block id, one delivering block. The address binds the zone and block id but not which
/// block claimed them, so an equivocating peer's two blocks at one id land here; the first
/// binds the shard and the second aborts.
///
/// Before either replay branch, not after: reaching the replay branch first would turn a
/// wrong-block delivery into a silent no-op, which the indexer's already-seen short circuit
/// would then wave through.
fn seen_shard(pre_data: &[u8], src_block_hash: &[u8; 32]) -> SeenShard {
    let shard = SeenShard::from_bytes(pre_data).expect("seen shard decodes");
    assert!(
        shard.binds(src_block_hash),
        "Seen shard is bound to a different peer block at this block id"
    );
    shard
}

fn execute(input: &ProgramInput<Instruction>, instruction_data: Vec<u8>) -> ! {
    assert!(
        input.caller_account_id.is_none(),
        "Inbox is only invoked as a top-level sequencer-origin transaction"
    );

    match &input.instruction {
        Instruction::Dispatch {
            message,
            already_seen,
        } => dispatch(input, instruction_data, message, *already_seen),
        Instruction::InitConfig(config) => {
            let [config_meta] = <[_; 1]>::try_from(input.accounts.clone())
                .expect("InitConfig requires the config account");
            assert_config_account(&config_meta, input.self_account_id);

            let mut plan = Plan::new(input, instruction_data);
            plan.update(&config_meta, &Effect::InitConfig(config.clone()));
            plan.write()
        }
    }
}

/// Delivers a finalized peer message to its target program, no-op on replay.
///
/// The inbox does not decide who may deliver what. It authenticates transport
/// and nothing else: any program this zone hosts can be named as a target, with
/// instruction bytes and shard selectors the peer chose. So a program meant to be
/// reachable across zones MUST check the marker at position 0 against sources it
/// authorized itself, the way `wrapped_token` and `ping_receiver` do. A program
/// not meant to be reachable has only whatever its own code happens to do. Some
/// refuse: four assert `caller_account_id` is none, several chain into the
/// marker's zero program id and are stopped by the host, and the rest are saved
/// by an address assert on a PDA. What a target without such a check can be made
/// to do is write its own shard at the addresses the peer names. None of that
/// was written with cross-zone delivery in mind. User-deployed programs are
/// reachable too, and were written with no expectation of an inbox caller at all.
fn dispatch(
    input: &ProgramInput<Instruction>,
    instruction_data: Vec<u8>,
    msg: &cross_zone_inbox_core::CrossZoneMessage,
    already_seen: bool,
) -> ! {
    assert!(
        msg.l1_inclusion_witness.is_none(),
        "l1_inclusion_witness must be None in v1"
    );

    let mut accounts = input.accounts.iter();
    let config = accounts.next().expect("config account required");
    let seen = accounts.next().expect("seen shard account required");
    let marker = accounts.next().expect("source marker account required");

    assert_config_account(config, input.self_account_id);
    assert_eq!(
        seen.account_id,
        inbox_seen_shard_account_id(input.self_account_id, &msg.src_zone, msg.src_block_id),
        "Second account must be the seen-shard PDA"
    );
    // The replay branch only inspects the seen shard, so its own shard has to be the one named.
    assert_eq!(
        seen.program_account_id, input.self_account_id,
        "The seen shard must be named under this program's shard"
    );
    // The one value the chained call carries about where the message came from.
    // The target re-derives this address from the source it accepts, so binding it
    // here is what makes a target's own check meaningful.
    assert_eq!(
        marker.account_id,
        inbox_source_marker_account_id(input.self_account_id, &msg.src_zone, msg.src_account_id),
        "Third account must be the source marker PDA for this message"
    );

    let mut plan = Plan::new(input, instruction_data);
    plan.effect(config, &Effect::ForeignZone(msg.src_zone));
    if already_seen {
        // A replay makes no call, but the shard still has to confirm that it is one.
        plan.effect(
            seen,
            &Effect::RequireDelivered {
                src_block_hash: msg.src_block_hash,
                src_tx_index: msg.src_tx_index,
            },
        );
    } else {
        plan.update(
            seen,
            &Effect::MarkDelivery {
                src_block_hash: msg.src_block_hash,
                src_tx_index: msg.src_tx_index,
            },
        );
        // Put the source marker first, followed by the requested shard selectors.
        let mut shard_selectors = vec![ProgramShardSelector::balance(marker.account_id)];
        shard_selectors.extend(accounts.map(ProgramShardSelector::from));
        plan.call(ChainedCall {
            program_account_id: msg.target_account_id,
            shard_selectors,
            instruction_data: msg.payload.clone(),
            pda_seeds: vec![],
        });
    }
    plan.write()
}

fn assert_config_account(config: &AccountMeta, self_account_id: AccountId) {
    assert_eq!(
        config.account_id,
        inbox_config_account_id(self_account_id),
        "First account must be the inbox config PDA"
    );
    assert_eq!(
        config.program_account_id, self_account_id,
        "The inbox config must be named under this program's shard"
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    const HASH: [u8; 32] = [1; 32];
    const OTHER_HASH: [u8; 32] = [2; 32];

    fn shard_with(indices: &[u32]) -> Vec<u8> {
        let mut shard = SeenShard::default();
        for index in indices {
            shard.insert(HASH, *index);
        }
        shard.to_bytes()
    }

    fn mark(src_tx_index: u32) -> Effect {
        Effect::MarkDelivery {
            src_block_hash: HASH,
            src_tx_index,
        }
    }

    fn require(src_tx_index: u32) -> Effect {
        Effect::RequireDelivered {
            src_block_hash: HASH,
            src_tx_index,
        }
    }

    #[test]
    fn a_first_delivery_is_recorded() {
        assert_eq!(resolve_effect(&mark(3), &[]), Some(shard_with(&[3])));
        assert_eq!(
            resolve_effect(&mark(4), &shard_with(&[3])),
            Some(shard_with(&[3, 4]))
        );
    }

    #[test]
    #[should_panic(expected = "claims to be a first delivery but this one is already recorded")]
    fn a_recorded_delivery_cannot_claim_to_be_the_first() {
        // The replay amplifier: taken, this re-fires the target's chained call for a message
        // the zone already delivered.
        resolve_effect(&mark(3), &shard_with(&[3]));
    }

    #[test]
    fn a_replay_leaves_the_shard_untouched() {
        assert_eq!(resolve_effect(&require(3), &shard_with(&[3])), None);
    }

    #[test]
    #[should_panic(expected = "claims to be a replay but this delivery was never recorded")]
    fn an_undelivered_message_cannot_claim_to_be_a_replay() {
        // Accepting it would drop a real message on the floor as a silent no-op.
        resolve_effect(&require(3), &shard_with(&[4]));
    }

    #[test]
    #[should_panic(expected = "bound to a different peer block")]
    fn a_second_block_at_one_block_id_cannot_mark_a_delivery() {
        resolve_effect(
            &Effect::MarkDelivery {
                src_block_hash: OTHER_HASH,
                src_tx_index: 5,
            },
            &shard_with(&[3]),
        );
    }

    #[test]
    #[should_panic(expected = "bound to a different peer block")]
    fn the_block_binding_is_checked_before_the_replay_branch() {
        resolve_effect(
            &Effect::RequireDelivered {
                src_block_hash: OTHER_HASH,
                src_tx_index: 3,
            },
            &shard_with(&[3]),
        );
    }

    #[test]
    fn a_message_from_a_peer_zone_is_accepted() {
        let config = InboxConfig { self_zone: [9; 32] };
        assert_eq!(
            resolve_effect(&Effect::ForeignZone([7; 32]), &config.to_bytes()),
            None
        );
    }

    #[test]
    #[should_panic(expected = "Source zone must not be this zone")]
    fn a_message_this_zone_addressed_to_itself_is_refused() {
        let config = InboxConfig { self_zone: [9; 32] };
        resolve_effect(&Effect::ForeignZone([9; 32]), &config.to_bytes());
    }

    #[test]
    #[should_panic(expected = "inbox config already initialized differently")]
    fn a_reinit_with_different_contents_is_refused() {
        let config = InboxConfig { self_zone: [9; 32] };
        resolve_effect(
            &Effect::InitConfig(InboxConfig { self_zone: [8; 32] }),
            &config.to_bytes(),
        );
    }
}
