use amm_core::{PoolDefinition, compute_vault_pda_seed};
use borsh::{BorshDeserialize, BorshSerialize};
use lee_core::{
    account::{AccountId, ShardData},
    program::{AccountMeta, Plan},
};

use crate::{Effect, transfer_call};

#[derive(Clone, Copy, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct SwapBinding {
    pub token_program_id: AccountId,
    pub input_vault_id: AccountId,
    pub output_vault_id: AccountId,
    pub definition_id_in: AccountId,
    pub definition_id_out: AccountId,
    pub amount_in: u128,
    pub amount_out: u128,
}

pub fn swap(plan: &mut Plan, accounts: &[AccountMeta; 5], binding: SwapBinding) {
    let [pool, input_vault, output_vault, user_input, user_output] = accounts;

    assert!(
        binding.amount_in != 0 && binding.amount_out != 0,
        "Swap amounts must be nonzero"
    );
    // A trader holding that is also a vault would turn a self-transfer into new funding.
    for user in [user_input, user_output] {
        assert!(
            user.account_id != input_vault.account_id && user.account_id != output_vault.account_id,
            "A trader holding cannot be a pool vault"
        );
    }

    // An `amount_out` the pool cannot afford is a vault drain: the withdraw leg pays it out of
    // reserves that never backed it. `Effect::Swap` checks the offer against the live pool
    // before any leg runs.
    plan.effect(pool, &Effect::Swap(binding));

    plan.call(transfer_call(
        binding.token_program_id,
        user_input,
        input_vault,
        binding.definition_id_in,
        binding.amount_in,
    ));
    plan.call(
        transfer_call(
            binding.token_program_id,
            output_vault,
            user_output,
            binding.definition_id_out,
            binding.amount_out,
        )
        .with_pda_seeds(vec![compute_vault_pda_seed(
            pool.account_id,
            binding.definition_id_out,
        )]),
    );
}

// Accepts any offer the live curve can afford and keeps the rest of the quote in the reserves.
// Vault backing, not a guard here, keeps the paid-out reserve real: only this program can debit
// a vault, and every reserve change it records is paired with an equal transfer.
#[must_use]
pub fn pool_after_swap(pre_data: &ShardData, binding: &SwapBinding) -> ShardData {
    let pool = PoolDefinition::try_from(pre_data)
        .expect("AMM Program expects a valid Pool Definition Account");

    assert!(pool.active, "Pool is inactive");
    assert_eq!(
        pool.token_program_id, binding.token_program_id,
        "Swap routes through a token program the pool does not use"
    );

    let (input, output) = pool
        .sides(binding.definition_id_in)
        .expect("AccountId is not a token type for the pool");
    assert_eq!(
        binding.definition_id_out, output.definition_id,
        "AccountId is not a token type for the pool"
    );
    assert_eq!(
        binding.input_vault_id, input.vault_id,
        "Input vault was not provided"
    );
    assert_eq!(
        binding.output_vault_id, output.vault_id,
        "Output vault was not provided"
    );
    let (reserve_in, reserve_out) = (input.reserve, output.reserve);

    assert!(
        reserve_in != 0 && reserve_out != 0,
        "Pool reserves must be nonzero"
    );
    assert!(
        binding.amount_out < reserve_out,
        "Swap output exhausts the reserve"
    );
    let quote = amm_core::quote_exact_input(reserve_in, reserve_out, binding.amount_in)
        .expect("reserve * amount_in overflows u128");
    assert!(
        binding.amount_out <= quote,
        "The pool cannot afford this offer at its live price"
    );

    // The quote already summed the input reserve and refused an overflow.
    let reserve_in = reserve_in + binding.amount_in;
    let reserve_out = reserve_out - binding.amount_out;
    let (reserve_a, reserve_b) = if input.definition_id == pool.definition_token_a_id {
        (reserve_in, reserve_out)
    } else {
        (reserve_out, reserve_in)
    };

    ShardData::from(&PoolDefinition {
        reserve_a,
        reserve_b,
        ..pool
    })
}
