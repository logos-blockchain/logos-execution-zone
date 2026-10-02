//! This crate contains core data structures and utilities for the AMM Program.

use borsh::{BorshDeserialize, BorshSerialize};
use lee_core::{
    account::{AccountId, Actor, ActorState},
    program::{PdaSeed, SendMode},
};
use token_core::{Notify, TokenDescriptor};

pub const AMM_NAME: [u8; 3] = *b"amm";

#[derive(Clone, Copy, BorshSerialize, BorshDeserialize)]
pub enum Message {
    NewDefinition {
        token_a_amount: u128,
        token_b_amount: u128,
        token_program_id: AccountId,
        definition_token_a_id: AccountId,
        definition_token_b_id: AccountId,
        user_a: AccountId,
        user_b: AccountId,
        user_lp: AccountId,
    },
    AddLiquidity {
        max_amount_to_add_token_a: u128,
        max_amount_to_add_token_b: u128,
        amount_to_add_token_a: u128,
        amount_to_add_token_b: u128,
        amount_liquidity: u128,
        user_a: AccountId,
        user_b: AccountId,
        user_lp: AccountId,
    },
    RemoveLiquidity {
        remove_liquidity_amount: u128,
        amount_to_remove_token_a: u128,
        amount_to_remove_token_b: u128,
        user_a: AccountId,
        user_b: AccountId,
        user_lp: AccountId,
    },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct SwapOffer {
    pub definition_id_out: AccountId,
    pub amount_out: u128,
    pub payout: AccountId,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct ExactInput {
    pub definition_id_out: AccountId,
    pub min_amount_out: u128,
    pub payout: AccountId,
    pub mode: SendMode,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub enum SwapRequest {
    Offer(SwapOffer),
    ExactInput(ExactInput),
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

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PoolSide {
    pub definition_id: AccountId,
    pub vault_id: AccountId,
    pub reserve: u128,
}

impl PoolDefinition {
    /// The input and output sides of a swap paying in `definition_id_in`, or `None` if the pool
    /// does not hold that token.
    #[must_use]
    pub fn sides(&self, definition_id_in: AccountId) -> Option<(PoolSide, PoolSide)> {
        let a = PoolSide {
            definition_id: self.definition_token_a_id,
            vault_id: self.vault_a_id,
            reserve: self.reserve_a,
        };
        let b = PoolSide {
            definition_id: self.definition_token_b_id,
            vault_id: self.vault_b_id,
            reserve: self.reserve_b,
        };
        if definition_id_in == a.definition_id {
            Some((a, b))
        } else if definition_id_in == b.definition_id {
            Some((b, a))
        } else {
            None
        }
    }
}

impl TryFrom<&ActorState> for PoolDefinition {
    type Error = std::io::Error;

    fn try_from(data: &ActorState) -> Result<Self, Self::Error> {
        Self::try_from_slice(data.as_ref())
    }
}

impl From<&PoolDefinition> for ActorState {
    fn from(definition: &PoolDefinition) -> Self {
        // Using size_of_val as size hint for Vec allocation
        let mut data = Vec::with_capacity(std::mem::size_of_val(definition));

        BorshSerialize::serialize(definition, &mut data)
            .expect("Serialization to Vec should not fail");

        Self::from(data)
    }
}

#[must_use]
pub fn amm_account_id() -> AccountId {
    AccountId::from_builtin_program_name(&AMM_NAME)
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

#[must_use]
pub fn quote_exact_input(reserve_in: u128, reserve_out: u128, amount_in: u128) -> Option<u128> {
    reserve_out
        .checked_mul(amount_in)?
        .checked_div(reserve_in.checked_add(amount_in)?)
}

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

#[must_use]
pub fn withdrawal_share(reserve: u128, liquidity_amount: u128, supply: u128) -> Option<u128> {
    reserve.checked_mul(liquidity_amount)?.checked_div(supply)
}

#[must_use]
pub fn swap_transfer(
    pool: Actor,
    input_vault: AccountId,
    descriptor_in: TokenDescriptor,
    amount_in: u128,
    request: SwapRequest,
) -> token_core::Message {
    token_core::Message::Transfer {
        to: input_vault,
        descriptor: descriptor_in,
        amount: amount_in,
        notify: Some(Notify {
            to: pool,
            payload: borsh::to_vec(&request).expect("borsh serialization is infallible"),
        }),
        mode: SendMode::Call,
    }
}
