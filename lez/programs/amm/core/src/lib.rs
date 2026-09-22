//! This crate contains core data structures and utilities for the AMM Program.

use borsh::{BorshDeserialize, BorshSerialize};
use lee_core::{
    account::{AccountId, ShardData},
    program::PdaSeed,
};

/// AMM Program Instruction.
///
/// The pool uses this program's shard. Vaults, holdings, and the liquidity token definition
/// use the token program's shards.
#[derive(BorshSerialize, BorshDeserialize)]
pub enum Instruction {
    /// Initializes a new Pool (or re-initializes an inactive Pool).
    ///
    /// Required accounts:
    /// - AMM Pool
    /// - Vault Holding Account for Token A
    /// - Vault Holding Account for Token B
    /// - Pool Liquidity Token Definition
    /// - User Holding Account for Token A (authorized)
    /// - User Holding Account for Token B (authorized)
    /// - User Holding Account for Pool Liquidity
    NewDefinition {
        token_a_amount: u128,
        token_b_amount: u128,
        token_program_id: AccountId,
        definition_token_a_id: AccountId,
        definition_token_b_id: AccountId,
        pool_is_empty: bool,
    },

    /// Adds liquidity to the Pool.
    ///
    /// Required accounts:
    /// - AMM Pool (initialized)
    /// - Vault Holding Account for Token A (initialized)
    /// - Vault Holding Account for Token B (initialized)
    /// - Pool Liquidity Token Definition (initialized)
    /// - User Holding Account for Token A (authorized)
    /// - User Holding Account for Token B (authorized)
    /// - User Holding Account for Pool Liquidity
    AddLiquidity {
        min_amount_liquidity: u128,
        max_amount_to_add_token_a: u128,
        max_amount_to_add_token_b: u128,
        token_program_id: AccountId,
        definition_token_a_id: AccountId,
        definition_token_b_id: AccountId,
        amount_to_add_token_a: u128,
        amount_to_add_token_b: u128,
        amount_liquidity: u128,
        reserve_bound_a: u128,
        reserve_bound_b: u128,
    },

    /// Removes liquidity from the Pool.
    ///
    /// Required accounts:
    /// - AMM Pool (initialized)
    /// - Vault Holding Account for Token A (initialized)
    /// - Vault Holding Account for Token B (initialized)
    /// - Pool Liquidity Token Definition (initialized)
    /// - User Holding Account for Token A (initialized)
    /// - User Holding Account for Token B (initialized)
    /// - User Holding Account for Pool Liquidity (authorized)
    RemoveLiquidity {
        remove_liquidity_amount: u128,
        min_amount_to_remove_token_a: u128,
        min_amount_to_remove_token_b: u128,
        token_program_id: AccountId,
        definition_token_a_id: AccountId,
        definition_token_b_id: AccountId,
        amount_to_remove_token_a: u128,
        amount_to_remove_token_b: u128,
        amount_liquidity_burned: u128,
        liquidity_supply_bound: u128,
    },

    /// Swap some quantity of Tokens (either Token A or Token B)
    /// while maintaining the Pool constant product.
    ///
    /// Required accounts:
    /// - AMM Pool (initialized)
    /// - Vault Holding Account for Token A (initialized)
    /// - Vault Holding Account for Token B (initialized)
    /// - User Holding Account for Token A
    /// - User Holding Account for Token B Either User Holding Account for Token A or Token B is
    ///   authorized.
    SwapExactInput {
        swap_amount_in: u128,
        min_amount_out: u128,
        token_definition_id_in: AccountId,
        token_program_id: AccountId,
        token_definition_id_out: AccountId,
        input_is_token_a: bool,
        amount_out: u128,
        reserve_bound_a: u128,
        reserve_bound_b: u128,
    },

    /// Swap tokens specifying the exact desired output amount,
    /// while maintaining the Pool constant product.
    ///
    /// Required accounts:
    /// - AMM Pool (initialized)
    /// - Vault Holding Account for Token A (initialized)
    /// - Vault Holding Account for Token B (initialized)
    /// - User Holding Account for Token A
    /// - User Holding Account for Token B Either User Holding Account for Token A or Token B is
    ///   authorized.
    SwapExactOutput {
        exact_amount_out: u128,
        max_amount_in: u128,
        token_definition_id_in: AccountId,
        token_program_id: AccountId,
        token_definition_id_out: AccountId,
        input_is_token_a: bool,
        amount_in: u128,
        reserve_bound_a: u128,
        reserve_bound_b: u128,
    },
}

#[derive(Debug, Clone, Default, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct PoolDefinition {
    /// The token program selected when the pool is initialized.
    pub token_program_id: AccountId,
    pub definition_token_a_id: AccountId,
    pub definition_token_b_id: AccountId,
    pub vault_a_id: AccountId,
    pub vault_b_id: AccountId,
    pub liquidity_pool_id: AccountId,
    pub liquidity_pool_supply: u128,
    pub reserve_a: u128,
    pub reserve_b: u128,
    /// Fees are currently not used.
    pub fees: u128,
    /// A pool becomes inactive (active = false)
    /// once all of its liquidity has been removed (e.g., reserves are emptied and
    /// `liquidity_pool_supply` = 0).
    pub active: bool,
}

impl TryFrom<&ShardData> for PoolDefinition {
    type Error = std::io::Error;

    fn try_from(data: &ShardData) -> Result<Self, Self::Error> {
        Self::try_from_slice(data.as_ref())
    }
}

impl From<&PoolDefinition> for ShardData {
    fn from(definition: &PoolDefinition) -> Self {
        // Using size_of_val as size hint for Vec allocation
        let mut data = Vec::with_capacity(std::mem::size_of_val(definition));

        BorshSerialize::serialize(definition, &mut data)
            .expect("Serialization to Vec should not fail");

        Self::try_from(data).expect("Token definition encoded data should fit into ShardData")
    }
}

#[must_use]
pub fn compute_pool_pda(
    amm_program_id: AccountId,
    definition_token_a_id: AccountId,
    definition_token_b_id: AccountId,
    token_program_id: AccountId,
) -> AccountId {
    AccountId::for_public_pda(
        &amm_program_id,
        &compute_pool_pda_seed(
            definition_token_a_id,
            definition_token_b_id,
            token_program_id,
        ),
    )
}

// Include the token program so different token programs derive different pools.
#[must_use]
fn compute_pool_pda_seed(
    definition_token_a_id: AccountId,
    definition_token_b_id: AccountId,
    token_program_id: AccountId,
) -> PdaSeed {
    use risc0_zkvm::sha::{Impl, Sha256 as _};

    let (token_1, token_2) = match definition_token_a_id
        .value()
        .cmp(definition_token_b_id.value())
    {
        std::cmp::Ordering::Less => (definition_token_b_id, definition_token_a_id),
        std::cmp::Ordering::Greater => (definition_token_a_id, definition_token_b_id),
        std::cmp::Ordering::Equal => panic!("Definitions match"),
    };

    let mut bytes = [0; 96];
    bytes[0..32].copy_from_slice(&token_1.to_bytes());
    bytes[32..64].copy_from_slice(&token_2.to_bytes());
    bytes[64..96].copy_from_slice(&token_program_id.to_bytes());

    PdaSeed::new(
        Impl::hash_bytes(&bytes)
            .as_bytes()
            .try_into()
            .expect("Hash output must be exactly 32 bytes long"),
    )
}

#[must_use]
pub fn compute_vault_pda(
    amm_program_id: AccountId,
    pool_id: AccountId,
    definition_token_id: AccountId,
) -> AccountId {
    AccountId::for_public_pda(
        &amm_program_id,
        &compute_vault_pda_seed(pool_id, definition_token_id),
    )
}

#[must_use]
pub fn compute_vault_pda_seed(pool_id: AccountId, definition_token_id: AccountId) -> PdaSeed {
    use risc0_zkvm::sha::{Impl, Sha256 as _};

    let mut bytes = [0; 64];
    bytes[0..32].copy_from_slice(&pool_id.to_bytes());
    bytes[32..].copy_from_slice(&definition_token_id.to_bytes());

    PdaSeed::new(
        Impl::hash_bytes(&bytes)
            .as_bytes()
            .try_into()
            .expect("Hash output must be exactly 32 bytes long"),
    )
}

#[must_use]
pub fn compute_liquidity_token_pda(amm_program_id: AccountId, pool_id: AccountId) -> AccountId {
    AccountId::for_public_pda(&amm_program_id, &compute_liquidity_token_pda_seed(pool_id))
}

#[must_use]
pub fn compute_liquidity_token_pda_seed(pool_id: AccountId) -> PdaSeed {
    use risc0_zkvm::sha::{Impl, Sha256 as _};

    let mut bytes = [0; 64];
    bytes[0..32].copy_from_slice(&pool_id.to_bytes());
    bytes[32..].copy_from_slice(&[0; 32]);

    PdaSeed::new(
        Impl::hash_bytes(&bytes)
            .as_bytes()
            .try_into()
            .expect("Hash output must be exactly 32 bytes long"),
    )
}

// The wallet calls these on observed reserves to build a proposal; each resolver calls them on
// actual reserves to verify it, so a rule that drifted between the two would price a trade the
// pool then refuses. `None` is a pool that cannot price the trade at all.
//
// Rounding is part of the price: exact-input floors and exact-output takes the ceiling, so a
// caller cannot buy a pool out a unit at a time from either side.
#[must_use]
pub fn quote_exact_input(reserve_in: u128, reserve_out: u128, amount_in: u128) -> Option<u128> {
    reserve_out
        .checked_mul(amount_in)?
        .checked_div(reserve_in.checked_add(amount_in)?)
}

// The caller checks `amount_out < reserve_out` first so it can attribute that rejection to its
// own guard; this returns `None` rather than underflowing if it did not.
#[must_use]
pub fn quote_exact_output(reserve_in: u128, reserve_out: u128, amount_out: u128) -> Option<u128> {
    Some(
        reserve_in
            .checked_mul(amount_out)?
            .div_ceil(reserve_out.checked_sub(amount_out)?),
    )
}

#[must_use]
pub fn ideal_deposit(reserve_this: u128, reserve_other: u128, max_other: u128) -> Option<u128> {
    reserve_this
        .checked_mul(max_other)?
        .checked_div(reserve_other)
}

// The smaller of the two shares is what the pool can actually back.
#[must_use]
pub fn liquidity_minted(
    supply: u128,
    amount_a: u128,
    amount_b: u128,
    reserve_a: u128,
    reserve_b: u128,
) -> Option<u128> {
    let from_a = supply.checked_mul(amount_a)?.checked_div(reserve_a)?;
    let from_b = supply.checked_mul(amount_b)?.checked_div(reserve_b)?;
    Some(if from_a < from_b { from_a } else { from_b })
}

// Also computes the LP burn itself, passing the supply as `reserve`: the division is what
// refuses a removal against an empty pool.
#[must_use]
pub fn withdrawal_share(reserve: u128, liquidity_amount: u128, supply: u128) -> Option<u128> {
    reserve.checked_mul(liquidity_amount)?.checked_div(supply)
}
