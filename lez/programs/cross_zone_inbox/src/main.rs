use cross_zone_inbox_core::{
    InboxConfig, Instruction, SeenShard, ZoneId, inbox_config_account_id,
    inbox_seen_shard_account_id,
};
use cross_zone_marker_core::inbox_source_marker_account_id;
use lee_core::{
    account::{AccountId, ProgramShardSelector},
    program::{AccountMeta, ChainedCall, Plan, PlanInput, run_program, write_once},
};

#[derive(borsh::BorshSerialize, borsh::BorshDeserialize)]
enum Effect {
    ForeignZone(ZoneId),
    MarkDelivery {
        src_block_hash: [u8; 32],
        src_tx_index: u32,
    },
    InitConfig(InboxConfig),
}

fn main() {
    run_program(plan, apply)
}

fn apply(effect: Effect, pre_data: &[u8]) -> Option<Vec<u8>> {
    match effect {
        Effect::ForeignZone(src_zone) => {
            let cfg = InboxConfig::from_bytes(pre_data).expect("inbox config decodes");
            assert!(
                src_zone != cfg.self_zone,
                "Source zone must not be this zone"
            );
            None
        }
        Effect::MarkDelivery {
            src_block_hash,
            src_tx_index,
        } => {
            let mut shard = SeenShard::from_bytes(pre_data).expect("seen shard decodes");
            // One block id, one delivering block. The address binds the zone and block id but
            // not which block claimed them, so an equivocating peer's two blocks at one id land
            // here; the first binds the shard and the second aborts.
            assert!(
                shard.binds(&src_block_hash),
                "Seen shard is bound to a different peer block at this block id"
            );
            assert!(
                !shard.contains(src_tx_index),
                "This delivery is already recorded"
            );
            shard.insert(src_block_hash, src_tx_index);
            Some(shard.to_bytes())
        }
        // Genesis is replayed onto seeded state during multi-sequencer reconstruction, so
        // a written config must already hold exactly this.
        Effect::InitConfig(config) => Some(write_once(pre_data, config.to_bytes())),
    }
}

fn plan(input: &PlanInput, instruction: Instruction) -> Plan {
    assert!(
        input.caller_account_id.is_none(),
        "Inbox is only invoked as a top-level sequencer-origin transaction"
    );

    let mut plan = Plan::new(input);
    let self_account_id = input.self_account_id;
    let accounts = &input.accounts;
    match instruction {
        Instruction::Dispatch(message) => dispatch(&mut plan, self_account_id, accounts, message),
        Instruction::InitConfig(config) => {
            let [config_meta] = <&[_; 1]>::try_from(accounts.as_slice())
                .expect("InitConfig requires the config account");
            assert_config_account(config_meta, self_account_id);
            plan.effect(config_meta, &Effect::InitConfig(config));
        }
    }
    plan
}

/// Delivers a finalized peer message to its target program, refusing a replay.
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
    plan: &mut Plan,
    self_account_id: AccountId,
    accounts: &[AccountMeta],
    msg: cross_zone_inbox_core::CrossZoneMessage,
) {
    assert!(
        msg.l1_inclusion_witness.is_none(),
        "l1_inclusion_witness must be None in v1"
    );

    let mut accounts = accounts.iter();
    let config = accounts.next().expect("config account required");
    let seen = accounts.next().expect("seen shard account required");
    let marker = accounts.next().expect("source marker account required");

    assert_config_account(config, self_account_id);
    assert_eq!(
        seen.account_id,
        inbox_seen_shard_account_id(self_account_id, &msg.src_zone, msg.src_block_id),
        "Second account must be the seen-shard PDA"
    );
    // The one value the chained call carries about where the message came from.
    // The target re-derives this address from the source it accepts, so binding it
    // here is what makes a target's own check meaningful.
    assert_eq!(
        marker.account_id,
        inbox_source_marker_account_id(self_account_id, &msg.src_zone, msg.src_account_id),
        "Third account must be the source marker PDA for this message"
    );

    plan.effect(config, &Effect::ForeignZone(msg.src_zone));
    plan.effect(
        seen,
        &Effect::MarkDelivery {
            src_block_hash: msg.src_block_hash,
            src_tx_index: msg.src_tx_index,
        },
    );
    // Put the source marker first, followed by the requested shard selectors.
    let mut shard_selectors = vec![ProgramShardSelector::native_balance(marker.account_id)];
    shard_selectors.extend(accounts.map(ProgramShardSelector::from));
    plan.call(ChainedCall {
        program_account_id: msg.target_account_id,
        shard_selectors,
        instruction_data: msg.payload,
        pda_seeds: vec![],
    });
}

fn assert_config_account(config: &AccountMeta, self_account_id: AccountId) {
    assert_eq!(
        config.account_id,
        inbox_config_account_id(self_account_id),
        "First account must be the inbox config PDA"
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

    #[test]
    fn a_first_delivery_is_recorded() {
        assert_eq!(apply(mark(3), &[]), Some(shard_with(&[3])));
        assert_eq!(apply(mark(4), &shard_with(&[3])), Some(shard_with(&[3, 4])));
    }

    #[test]
    #[should_panic(expected = "This delivery is already recorded")]
    fn a_recorded_delivery_cannot_claim_to_be_the_first() {
        // The replay amplifier: taken, this re-fires the target's chained call for a message
        // the zone already delivered.
        apply(mark(3), &shard_with(&[3]));
    }

    #[test]
    #[should_panic(expected = "bound to a different peer block")]
    fn a_second_block_at_one_block_id_cannot_mark_a_delivery() {
        apply(
            Effect::MarkDelivery {
                src_block_hash: OTHER_HASH,
                src_tx_index: 5,
            },
            &shard_with(&[3]),
        );
    }

    #[test]
    fn a_message_from_a_peer_zone_is_accepted() {
        let config = InboxConfig { self_zone: [9; 32] };
        assert_eq!(
            apply(Effect::ForeignZone([7; 32]), &config.to_bytes()),
            None
        );
    }

    #[test]
    #[should_panic(expected = "Source zone must not be this zone")]
    fn a_message_this_zone_addressed_to_itself_is_refused() {
        let config = InboxConfig { self_zone: [9; 32] };
        apply(Effect::ForeignZone([9; 32]), &config.to_bytes());
    }

    #[test]
    #[should_panic(expected = "shard already holds different data")]
    fn a_reinit_with_different_contents_is_refused() {
        let config = InboxConfig { self_zone: [9; 32] };
        apply(
            Effect::InitConfig(InboxConfig { self_zone: [8; 32] }),
            &config.to_bytes(),
        );
    }
}
