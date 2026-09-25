use cross_zone_outbox_core::{Instruction, OutboxRecord, outbox_pda};
use lee_core::program::{Plan, PlanInput, run_program};

#[derive(borsh::BorshSerialize, borsh::BorshDeserialize)]
enum Effect {
    /// A slot holds one message for ever.
    CreateRecord(OutboxRecord),
}

fn main() {
    run_program(plan, apply)
}

#[expect(
    clippy::unnecessary_wraps,
    reason = "run_program's apply returns None to keep a shard"
)]
fn apply(effect: Effect, pre_data: &[u8]) -> Option<Vec<u8>> {
    let Effect::CreateRecord(record) = effect;
    assert!(
        pre_data.is_empty(),
        "Outbox slot already written: one Emit per (emitter, target_zone, ordinal)"
    );
    Some(record.to_bytes())
}

fn plan(input: &PlanInput, instruction: Instruction) -> Plan {
    // The emitter, and the only identity here the state machine verifies: it
    // checks a guest's claimed caller against the real one. Note this is the
    // immediate chained caller, not the top-level program that cross-zone
    // discovery names; the two coincide only while every emitter refuses to be
    // called by another program, which both do today.
    let Some(emitter) = input.caller_account_id else {
        panic!("Outbox is only callable through a chain call from a user program");
    };

    let mut plan = Plan::new(input);
    let Instruction::Emit {
        target_zone,
        target_account_id,
        target_accounts,
        payload,
        ordinal,
    } = instruction;

    let [outbox] =
        <&[_; 1]>::try_from(input.accounts.as_slice()).expect("Emit requires exactly 1 account");

    // Identity first, so a wrong account that happens to be free is reported as
    // the wrong account rather than as a used slot.
    //
    // A slot can still be denied to its intended writer by a real emission: the
    // ordinal is caller-chosen in a shard every user of an emitter shares,
    // and an emission needs no signature, so anyone can occupy one. A client must
    // pick an ordinal the chain does not already hold rather than counting from
    // zero.
    assert_eq!(
        outbox.account_id,
        outbox_pda(input.self_account_id, emitter, &target_zone, ordinal),
        "Account must be the outbox PDA for (emitter, target_zone, ordinal)"
    );

    plan.effect(
        outbox,
        &Effect::CreateRecord(OutboxRecord {
            emitter,
            target_zone,
            ordinal,
            target_account_id,
            target_accounts,
            payload,
        }),
    );
    plan
}

#[cfg(test)]
mod tests {
    use lee_core::account::AccountId;

    use super::*;

    fn record() -> OutboxRecord {
        OutboxRecord {
            emitter: AccountId::new([4; 32]),
            target_zone: [1; 32],
            ordinal: 7,
            target_account_id: AccountId::new([6; 32]),
            target_accounts: vec![],
            payload: b"payload".to_vec(),
        }
    }

    #[test]
    fn an_empty_slot_takes_the_record() {
        assert_eq!(
            apply(Effect::CreateRecord(record()), &[]),
            Some(record().to_bytes())
        );
    }

    #[test]
    #[should_panic(expected = "Outbox slot already written")]
    fn an_occupied_slot_refuses_a_second_message() {
        apply(Effect::CreateRecord(record()), &record().to_bytes());
    }
}
