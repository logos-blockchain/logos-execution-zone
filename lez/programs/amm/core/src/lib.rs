//! This crate contains core data structures and utilities for the AMM Program.

use borsh::{BorshDeserialize, BorshSerialize};
use lee_core::{
    account::{AccountId, AccountIdData, ShardData},
    program::PdaSeed,
};
use token_core::{HoldingKind, HoldingTarget};

/// AMM Program Instruction.
///
/// The pool uses this program's shard. Vaults, holdings, and the liquidity token definition
/// use the token program's shards. Vaults are the token holdings owned by the pool; the user's
/// holdings are derived from `user`, whose owner is the last account.
#[derive(BorshSerialize, BorshDeserialize)]
pub enum Instruction {
    /// Initializes a new Pool (or re-initializes an inactive Pool).
    ///
    /// Required accounts:
    /// - AMM Pool
    /// - Vault Holding Account for Token A
    /// - Vault Holding Account for Token B
    /// - Pool Liquidity Token Definition
    /// - User Holding Account for Token A
    /// - User Holding Account for Token B
    /// - User Holding Account for Pool Liquidity
    /// - User's owner (authorized)
    NewDefinition {
        token_a_amount: u128,
        token_b_amount: u128,
        token_program_id: AccountId,
        user: HoldingTarget,
    },

    /// Adds liquidity to the Pool.
    ///
    /// Required accounts:
    /// - AMM Pool (initialized)
    /// - Vault Holding Account for Token A (initialized)
    /// - Vault Holding Account for Token B (initialized)
    /// - Pool Liquidity Token Definition (initialized)
    /// - User Holding Account for Token A
    /// - User Holding Account for Token B
    /// - User Holding Account for Pool Liquidity
    /// - User's owner (authorized)
    AddLiquidity {
        min_amount_liquidity: u128,
        max_amount_to_add_token_a: u128,
        max_amount_to_add_token_b: u128,
        user: HoldingTarget,
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
    /// - User Holding Account for Pool Liquidity
    /// - User's owner (authorized)
    RemoveLiquidity {
        remove_liquidity_amount: u128,
        min_amount_to_remove_token_a: u128,
        min_amount_to_remove_token_b: u128,
        user: HoldingTarget,
    },

    /// Swap some quantity of Tokens (either Token A or Token B)
    /// while maintaining the Pool constant product.
    ///
    /// Required accounts:
    /// - AMM Pool (initialized)
    /// - Vault Holding Account for Token A (initialized)
    /// - Vault Holding Account for Token B (initialized)
    /// - User Holding Account for Token A
    /// - User Holding Account for Token B
    /// - User's owner (authorized)
    SwapExactInput {
        swap_amount_in: u128,
        min_amount_out: u128,
        token_definition_id_in: AccountId,
        user: HoldingTarget,
    },

    /// Swap tokens specifying the exact desired output amount,
    /// while maintaining the Pool constant product.
    ///
    /// Required accounts:
    /// - AMM Pool (initialized)
    /// - Vault Holding Account for Token A (initialized)
    /// - Vault Holding Account for Token B (initialized)
    /// - User Holding Account for Token A
    /// - User Holding Account for Token B
    /// - User's owner (authorized)
    SwapExactOutput {
        exact_amount_out: u128,
        max_amount_in: u128,
        token_definition_id_in: AccountId,
        user: HoldingTarget,
    },
}

#[derive(Clone, Default, BorshSerialize, BorshDeserialize)]
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
    AccountIdData::public().derive_pda_id(
        amm_program_id,
        &compute_pool_pda_seed(
            definition_token_a_id,
            definition_token_b_id,
            token_program_id,
        ),
    )
}

// Include the token program so different token programs derive different pools.
#[must_use]
pub fn compute_pool_pda_seed(
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
pub const fn vault_holder(pool_id: AccountId) -> HoldingTarget {
    HoldingTarget {
        owner_id: pool_id,
        account_id_data: AccountIdData::public(),
    }
}

#[must_use]
pub fn compute_vault_id(
    token_program_id: AccountId,
    pool_id: AccountId,
    definition_token_id: AccountId,
) -> AccountId {
    token_core::holding_id(
        &vault_holder(pool_id),
        token_program_id,
        definition_token_id,
        HoldingKind::Fungible,
    )
}

#[must_use]
pub fn compute_liquidity_token_pda(amm_program_id: AccountId, pool_id: AccountId) -> AccountId {
    AccountIdData::public()
        .derive_pda_id(amm_program_id, &compute_liquidity_token_pda_seed(pool_id))
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
