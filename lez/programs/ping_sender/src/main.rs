use cross_zone_outbox_core::Instruction as OutboxInstruction;
use lee_core::{
    account::{AccountId, ProgramShardSelector},
    program::{AccountMeta, ChainedCall, Plan, PlanInput, run_program, write_once},
};
use ping_core::{SenderInstruction, outbox_bytes, read_outbox, sender_config_account_id};

#[derive(Clone, Copy, borsh::BorshSerialize, borsh::BorshDeserialize)]
enum Effect {
    OutboxIs(AccountId),
    InitConfig(AccountId),
}

fn main() {
    run_program(plan, apply)
}

fn apply(effect: Effect, pre_data: &[u8]) -> Option<Vec<u8>> {
    match effect {
        Effect::OutboxIs(outbox_account_id) => {
            let pinned = read_outbox(pre_data).expect("config account holds an outbox program id");
            assert_eq!(
                pinned, outbox_account_id,
                "the emission names a program the ping-sender config does not pin as its outbox"
            );
            None
        }
        // Genesis is replayed onto seeded state during multi-sequencer reconstruction, so
        // a written config must already pin exactly this outbox.
        Effect::InitConfig(outbox_account_id) => Some(write_once(
            pre_data,
            outbox_bytes(outbox_account_id).to_vec(),
        )),
    }
}

fn plan(input: &PlanInput, instruction: SenderInstruction) -> Plan {
    assert!(
        input.caller_account_id.is_none(),
        "ping_sender is only invoked as a top-level user transaction"
    );

    let mut plan = Plan::new(input);
    let self_account_id = input.self_account_id;
    let accounts = &input.accounts;
    match instruction {
        SenderInstruction::Send {
            target_zone,
            target_account_id,
            target_accounts,
            payload,
            ordinal,
        } => {
            let [config, outbox] = <&[_; 2]>::try_from(accounts.as_slice())
                .expect("Send requires the config and outbox accounts");
            assert_config_account(config, self_account_id);

            // The outbox program arrives as the outbox handle's own shard selector, which is
            // transaction-chosen; the config effect is what pins it.
            plan.effect(config, &Effect::OutboxIs(outbox.program_account_id));
            plan.call(ChainedCall::new(
                outbox.program_account_id,
                vec![ProgramShardSelector::from(outbox)],
                &OutboxInstruction::Emit {
                    target_zone,
                    target_account_id,
                    target_accounts,
                    payload,
                    ordinal,
                },
            ));
        }
        SenderInstruction::InitConfig { outbox_account_id } => {
            let [config] = <&[_; 1]>::try_from(accounts.as_slice())
                .expect("InitConfig requires the config account");
            assert_config_account(config, self_account_id);
            plan.effect(config, &Effect::InitConfig(outbox_account_id));
        }
    }
    plan
}

/// Pinned rather than caller-named: the address is what makes the config's answer this
/// program's own.
fn assert_config_account(config: &AccountMeta, self_account_id: AccountId) {
    assert_eq!(
        config.account_id,
        sender_config_account_id(self_account_id),
        "first account must be the ping-sender config PDA"
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    const OUTBOX: AccountId = AccountId::new([9; 32]);

    #[test]
    fn the_pinned_outbox_is_accepted() {
        assert_eq!(apply(Effect::OutboxIs(OUTBOX), &outbox_bytes(OUTBOX)), None);
    }

    #[test]
    #[should_panic(expected = "does not pin as its outbox")]
    fn another_program_cannot_stand_in_for_the_outbox() {
        // Unguarded this redirects the emission's child call to an arbitrary program, which
        // then reads the outbox account's shard under its own interpretation.
        apply(
            Effect::OutboxIs(AccountId::new([1; 32])),
            &outbox_bytes(OUTBOX),
        );
    }

    #[test]
    fn an_empty_config_takes_the_first_init() {
        assert_eq!(
            apply(Effect::InitConfig(OUTBOX), &[]),
            Some(outbox_bytes(OUTBOX).to_vec())
        );
    }

    #[test]
    fn an_identical_reinit_is_a_no_op_rewrite() {
        assert_eq!(
            apply(Effect::InitConfig(OUTBOX), &outbox_bytes(OUTBOX)),
            Some(outbox_bytes(OUTBOX).to_vec())
        );
    }

    #[test]
    #[should_panic(expected = "shard already holds different data")]
    fn a_reinit_naming_a_different_outbox_is_refused() {
        apply(
            Effect::InitConfig(AccountId::new([1; 32])),
            &outbox_bytes(OUTBOX),
        );
    }
}
