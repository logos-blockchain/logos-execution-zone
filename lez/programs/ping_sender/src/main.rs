use cross_zone_outbox_core::Instruction as OutboxInstruction;
use lee_core::{
    account::{AccountId, ProgramShardSelector},
    program::{
        AccountMeta, ChainedCall, LeeCall, Plan, ProgramInput, Proposed, read_lee_call,
        resolve_keep, resolve_write,
    },
};
use ping_core::{SenderInstruction, outbox_bytes, read_outbox, sender_config_account_id};

#[derive(borsh::BorshSerialize, borsh::BorshDeserialize)]
enum Effect {
    /// The config is what says this is the real outbox: chaining elsewhere would let an
    /// emission skip it and leave no record of itself.
    OutboxIs(AccountId),
    InitConfig(AccountId),
}

fn main() {
    match read_lee_call::<SenderInstruction>() {
        LeeCall::Execute(input, instruction_data) => execute(&input, instruction_data),
        LeeCall::Resolve(input) => {
            let effect =
                borsh::from_slice(&input.effect_data).expect("ping_sender wrote its own effect");
            match resolve_effect(&effect, &input.pre_data) {
                None => resolve_keep(input),
                Some(data) => resolve_write(
                    input,
                    data.try_into().expect("outbox id fits in account data"),
                ),
            }
        }
    }
}

fn resolve_effect(effect: &Effect, pre_data: &[u8]) -> Option<Vec<u8>> {
    match effect {
        Effect::OutboxIs(outbox_account_id) => {
            let pinned = read_outbox(pre_data).expect("config account holds an outbox program id");
            assert_eq!(
                pinned, *outbox_account_id,
                "the emission names a program the ping-sender config does not pin as its outbox"
            );
            None
        }
        Effect::InitConfig(outbox_account_id) => {
            let bytes = outbox_bytes(*outbox_account_id);
            // Genesis is replayed onto seeded state during multi-sequencer reconstruction, so
            // a written config must already pin exactly this outbox.
            if !pre_data.is_empty() {
                assert_eq!(
                    pre_data, bytes,
                    "ping-sender config already pins a different outbox"
                );
            }
            Some(bytes.to_vec())
        }
    }
}

fn execute(input: &ProgramInput<SenderInstruction>, instruction_data: Vec<u8>) -> ! {
    assert!(
        input.caller_account_id.is_none(),
        "ping_sender is only invoked as a top-level user transaction"
    );

    match &input.instruction {
        SenderInstruction::Send {
            target_zone,
            target_account_id,
            target_accounts,
            payload,
            ordinal,
        } => {
            let [config, outbox] = <[_; 2]>::try_from(input.accounts.clone())
                .expect("Send requires the config and outbox accounts");
            assert_config_account(&config, input.self_account_id);

            let mut plan = Plan::new(input, instruction_data);
            // The outbox program arrives as the outbox handle's own shard selector, which is
            // transaction-chosen; the config effect is what pins it.
            let outbox_account_id = plan.require(
                &config,
                &Effect::OutboxIs(outbox.program_account_id),
                Proposed::new(outbox.program_account_id),
            );
            plan.call(ChainedCall::new(
                outbox_account_id.get(),
                vec![ProgramShardSelector::from(&outbox)],
                &OutboxInstruction::Emit {
                    target_zone: *target_zone,
                    target_account_id: *target_account_id,
                    target_accounts: target_accounts.clone(),
                    payload: payload.clone(),
                    ordinal: *ordinal,
                },
            ));
            plan.write()
        }
        SenderInstruction::InitConfig { outbox_account_id } => {
            let [config] = <[_; 1]>::try_from(input.accounts.clone())
                .expect("InitConfig requires the config account");
            assert_config_account(&config, input.self_account_id);

            let mut plan = Plan::new(input, instruction_data);
            plan.update(&config, &Effect::InitConfig(*outbox_account_id));
            plan.write()
        }
    }
}

/// Pinned rather than caller-named: the address, and the shard under it, are both what make
/// the config's answer this program's own.
fn assert_config_account(config: &AccountMeta, self_account_id: AccountId) {
    assert_eq!(
        config.account_id,
        sender_config_account_id(self_account_id),
        "first account must be the ping-sender config PDA"
    );
    assert_eq!(
        config.program_account_id, self_account_id,
        "the config must be named under this program's shard"
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    const OUTBOX: AccountId = AccountId::new([9; 32]);

    #[test]
    fn the_pinned_outbox_is_accepted() {
        assert_eq!(
            resolve_effect(&Effect::OutboxIs(OUTBOX), &outbox_bytes(OUTBOX)),
            None
        );
    }

    #[test]
    #[should_panic(expected = "does not pin as its outbox")]
    fn another_program_cannot_stand_in_for_the_outbox() {
        // Unguarded this redirects the emission's child call to an arbitrary program, which
        // then reads the outbox account's shard under its own interpretation.
        resolve_effect(
            &Effect::OutboxIs(AccountId::new([1; 32])),
            &outbox_bytes(OUTBOX),
        );
    }

    #[test]
    fn an_empty_config_takes_the_first_init() {
        assert_eq!(
            resolve_effect(&Effect::InitConfig(OUTBOX), &[]),
            Some(outbox_bytes(OUTBOX).to_vec())
        );
    }

    #[test]
    fn an_identical_reinit_is_a_no_op_rewrite() {
        assert_eq!(
            resolve_effect(&Effect::InitConfig(OUTBOX), &outbox_bytes(OUTBOX)),
            Some(outbox_bytes(OUTBOX).to_vec())
        );
    }

    #[test]
    #[should_panic(expected = "already pins a different outbox")]
    fn a_reinit_naming_a_different_outbox_is_refused() {
        resolve_effect(
            &Effect::InitConfig(AccountId::new([1; 32])),
            &outbox_bytes(OUTBOX),
        );
    }
}
