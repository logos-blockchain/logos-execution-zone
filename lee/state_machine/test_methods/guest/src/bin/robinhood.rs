//! Routes a transfer from the richer of two accounts to the poorer, deciding the direction from
//! balances the plan never sees.
//!
//! # Why this exists
//!
//! A plan receives account ids and metadata, never account data, so a routing decision that
//! compares two balances looks unexpressible. It is not. The balances arrive as untrusted
//! proposals in the instruction, `require` emits a guard against each account before handing the
//! value back, and the plan branches on the guarded values. Each guard is resolved against the
//! account's real balance, so a proposal that does not match the chain aborts the whole
//! transaction. That is the same outcome a stale pre-state produces under the binding model, so
//! the routing is reproduced at no loss.
//!
//! Both accounts are PDAs of this program, which is what authorizes the debit in either
//! direction.

use core::cmp::Ordering;

use lee_core::{
    native_token::{custody_transfer, decode_balance},
    program::{LeeCall, PdaSeed, Plan, ProgramInput, Proposed, read_lee_call, resolve_keep},
};

/// Seeds of the two accounts this program custodies, in the order the caller declares them.
const SEEDS: [[u8; 32]; 2] = [[0; 32], [1; 32]];

#[derive(borsh::BorshSerialize, borsh::BorshDeserialize)]
pub enum RobinhoodInstruction {
    /// `balance_a` and `balance_b` are the caller's proposals for what the two accounts hold.
    /// They are untrusted: a guard pins each to its account's real balance before the comparison
    /// below is allowed to use it.
    Rebalance {
        balance_a: u128,
        balance_b: u128,
        amount: u128,
    },
}

/// It never writes: the native balance shard belongs to the native token program, so the only
/// sound outcome of a foreign inspection is `Keep`.
#[derive(borsh::BorshSerialize, borsh::BorshDeserialize)]
enum Guard {
    BalanceIs(u128),
}

fn main() {
    match read_lee_call::<RobinhoodInstruction>() {
        LeeCall::Execute(input, instruction_data) => execute(&input, instruction_data),
        LeeCall::Resolve(input) => {
            let Guard::BalanceIs(proposed) =
                borsh::from_slice(&input.effect_data).expect("robinhood wrote its own guard");
            let balance = decode_balance(&input.pre_data)
                .expect("the guarded shard is a native balance shard");
            assert_eq!(
                balance, proposed,
                "Proposed balance {proposed} is not the account's actual balance {balance}"
            );
            resolve_keep(input)
        }
    }
}

fn execute(input: &ProgramInput<RobinhoodInstruction>, instruction_data: Vec<u8>) -> ! {
    let RobinhoodInstruction::Rebalance {
        balance_a,
        balance_b,
        amount,
    } = &input.instruction;

    let Ok([account_a, account_b]) = <[_; 2]>::try_from(input.accounts.clone()) else {
        panic!("Rebalance requires exactly 2 accounts");
    };
    let mut plan = Plan::new(input, instruction_data);

    // `require` emits each guard before returning the value, so neither comparand can reach the
    // match below unpinned. That the guard validates this particular value is the pairing this
    // program is responsible for, not something `Checked` establishes.
    let balance_a = plan.require(
        &account_a,
        &Guard::BalanceIs(*balance_a),
        Proposed::new(*balance_a),
    );
    let balance_b = plan.require(
        &account_b,
        &Guard::BalanceIs(*balance_b),
        Proposed::new(*balance_b),
    );

    match balance_a.get().cmp(&balance_b.get()) {
        Ordering::Greater => plan.call(custody_transfer(
            account_a.account_id,
            PdaSeed::new(SEEDS[0]),
            account_b.account_id,
            *amount,
        )),
        Ordering::Less => plan.call(custody_transfer(
            account_b.account_id,
            PdaSeed::new(SEEDS[1]),
            account_a.account_id,
            *amount,
        )),
        Ordering::Equal => {}
    }

    plan.write()
}
