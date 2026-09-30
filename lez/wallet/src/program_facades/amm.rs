use amm_core::{
    PoolDefinition, SwapOffer, SwapRequest, compute_liquidity_token_pda, compute_pool_pda,
    compute_vault_pda, swap_transfer,
};
use common::HashType;
use lee::{
    AccountId, Actor, Assumption, privacy_preserving_transaction::circuit::ProgramCatalog,
    program::Program,
};
use lee_core::{
    SharedSecretKey,
    program::{Action, Call, CallInput},
};
use token_core::{Delivery, TokenDescriptor, TokenHolding, TokenKind, expected_sends};

use crate::{
    AccountIdentity, AccountMention, ExecutionFailureKind, WalletCore,
    program_facades::{shard, token_holding},
};
pub struct Amm<'wallet>(pub &'wallet WalletCore);

/// The pool's PDA family, derived from the definitions the two user holdings carry. A pair given
/// in the opposite order to the pool's own derives the other vault and is rejected on chain.
#[expect(
    clippy::struct_field_names,
    reason = "every field is an account id, named as the pool and the instruction name it"
)]
struct Route {
    amm_program_id: AccountId,
    token_program_id: AccountId,
    definition_token_a_id: AccountId,
    definition_token_b_id: AccountId,
    pool_id: AccountId,
    vault_a_id: AccountId,
    vault_b_id: AccountId,
}

impl Route {
    async fn resolve(
        wallet: &WalletCore,
        user_holding_a: &AccountIdentity,
        user_holding_b: &AccountIdentity,
    ) -> Result<Self, ExecutionFailureKind> {
        let amm_program_id = programs::amm_account_id();
        let token_program_id = programs::token_account_id();

        let definition_token_a_id = token_holding(wallet, user_holding_a, token_program_id)
            .await?
            .definition_id();
        let definition_token_b_id = token_holding(wallet, user_holding_b, token_program_id)
            .await?
            .definition_id();

        let pool_id = compute_pool_pda(
            amm_program_id,
            definition_token_a_id,
            definition_token_b_id,
            token_program_id,
        );

        Ok(Self {
            amm_program_id,
            token_program_id,
            definition_token_a_id,
            definition_token_b_id,
            pool_id,
            vault_a_id: compute_vault_pda(amm_program_id, pool_id, definition_token_a_id),
            vault_b_id: compute_vault_pda(amm_program_id, pool_id, definition_token_b_id),
        })
    }

    // The pool's actor is the root; the user holdings follow the pool's own token actors.
    fn liquidity_accounts(
        &self,
        user_holding_a: AccountIdentity,
        user_holding_b: AccountIdentity,
        user_holding_lp: AccountIdentity,
    ) -> Vec<AccountMention> {
        vec![
            AccountIdentity::PublicNoSign(self.pool_id).select_program_shard(self.amm_program_id),
            AccountIdentity::PublicNoSign(self.vault_a_id)
                .select_program_shard(self.token_program_id),
            AccountIdentity::PublicNoSign(self.vault_b_id)
                .select_program_shard(self.token_program_id),
            AccountIdentity::PublicNoSign(compute_liquidity_token_pda(
                self.amm_program_id,
                self.pool_id,
            ))
            .select_program_shard(self.token_program_id),
            user_holding_a.select_program_shard(self.token_program_id),
            user_holding_b.select_program_shard(self.token_program_id),
            user_holding_lp.select_program_shard(self.token_program_id),
        ]
    }
}

impl Amm<'_> {
    pub async fn send_new_pool(
        &self,
        user_holding_a: AccountIdentity,
        user_holding_b: AccountIdentity,
        user_holding_lp: AccountIdentity,
        balance_a: u128,
        balance_b: u128,
    ) -> Result<(AccountId, HashType, Vec<SharedSecretKey>), ExecutionFailureKind> {
        let route = Route::resolve(self.0, &user_holding_a, &user_holding_b).await?;

        let accounts = route.liquidity_accounts(user_holding_a, user_holding_b, user_holding_lp);
        let [user_a, user_b, user_lp] = user_ids(&accounts);
        let message = amm_core::Message::NewDefinition {
            token_a_amount: balance_a,
            token_b_amount: balance_b,
            token_program_id: route.token_program_id,
            definition_token_a_id: route.definition_token_a_id,
            definition_token_b_id: route.definition_token_b_id,
            user_a,
            user_b,
            user_lp,
        };

        let (tx_hash, secrets) = self.send_liquidity(accounts, &message).await?;
        Ok((route.pool_id, tx_hash, secrets))
    }

    pub async fn send_swap(
        &self,
        pool_id: AccountId,
        user_input: AccountIdentity,
        user_output: AccountIdentity,
        amount_in: u128,
        amount_out: u128,
    ) -> Result<(HashType, Vec<SharedSecretKey>), ExecutionFailureKind> {
        let pool = pool_definition(self.0, pool_id).await?;
        let source = token_holding(self.0, &user_input, pool.token_program_id).await?;
        let terms = SwapTerms::new(
            pool_id,
            &pool,
            user_input.account_id(),
            &source,
            amount_in,
            amount_out,
        )?;
        let accounts = terms.accounts(user_input, user_output);
        let transfer = terms.transfer(&accounts);
        let message = Program::serialize_message(&transfer).expect("Message should serialize");
        if accounts.iter().any(|mention| mention.identity.is_private()) {
            let assumed = terms.promised_payout(&accounts);
            self.0
                .send_privacy_preserving_tx_assuming(
                    accounts,
                    0,
                    message,
                    assumed,
                    &amm_with_token_dependency(),
                )
                .await
        } else {
            self.0
                .send_pub_tx(accounts, 0, message)
                .await
                .map(|tx_hash| (tx_hash, Vec::new()))
        }
    }

    pub async fn quote(
        &self,
        pool_id: AccountId,
        definition_id_in: AccountId,
        amount: QuoteAmount,
    ) -> Result<Estimate, ExecutionFailureKind> {
        estimate(
            &pool_definition(self.0, pool_id).await?,
            definition_id_in,
            amount,
        )
    }

    pub async fn send_add_liquidity(
        &self,
        user_holding_a: AccountIdentity,
        user_holding_b: AccountIdentity,
        user_holding_lp: AccountIdentity,
        min_amount_liquidity: u128,
        max_amount_to_add_token_a: u128,
        max_amount_to_add_token_b: u128,
    ) -> Result<(HashType, Vec<SharedSecretKey>), ExecutionFailureKind> {
        let route = Route::resolve(self.0, &user_holding_a, &user_holding_b).await?;
        let pool = pool_definition(self.0, route.pool_id).await?;
        let accounts = route.liquidity_accounts(user_holding_a, user_holding_b, user_holding_lp);
        let message = add_liquidity(
            &pool,
            min_amount_liquidity,
            max_amount_to_add_token_a,
            max_amount_to_add_token_b,
            user_ids(&accounts),
        )?;

        self.send_liquidity(accounts, &message).await
    }

    pub async fn send_remove_liquidity(
        &self,
        user_holding_a: AccountIdentity,
        user_holding_b: AccountIdentity,
        user_holding_lp: AccountIdentity,
        remove_liquidity_amount: u128,
        min_amount_to_remove_token_a: u128,
        min_amount_to_remove_token_b: u128,
    ) -> Result<(HashType, Vec<SharedSecretKey>), ExecutionFailureKind> {
        let route = Route::resolve(self.0, &user_holding_a, &user_holding_b).await?;
        let pool = pool_definition(self.0, route.pool_id).await?;
        let accounts = route.liquidity_accounts(user_holding_a, user_holding_b, user_holding_lp);
        let message = remove_liquidity(
            &pool,
            remove_liquidity_amount,
            min_amount_to_remove_token_a,
            min_amount_to_remove_token_b,
            user_ids(&accounts),
        )?;

        self.send_liquidity(accounts, &message).await
    }

    // The pool is the root.
    async fn send_liquidity(
        &self,
        accounts: Vec<AccountMention>,
        message: &amm_core::Message,
    ) -> Result<(HashType, Vec<SharedSecretKey>), ExecutionFailureKind> {
        let message = Program::serialize_message(message).expect("Message should serialize");
        self.0
            .send_tx(accounts, 0, message, &amm_with_token_dependency())
            .await
    }
}

#[derive(Debug, Clone, Copy)]
pub enum QuoteAmount {
    In(u128),
    Out(u128),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Estimate {
    pub amount_in: u128,
    pub amount_out: u128,
}

// The trader's exact terms and the pool's vaults for them. Nothing here reads or checks the
// pool's reserves: settlement decides whether the pool can afford the offer.
struct SwapTerms {
    pool_id: AccountId,
    token_program_id: AccountId,
    input_vault_id: AccountId,
    output_vault_id: AccountId,
    definition_id_in: AccountId,
    definition_id_out: AccountId,
    amount_in: u128,
    amount_out: u128,
}

impl SwapTerms {
    fn new(
        pool_id: AccountId,
        pool: &PoolDefinition,
        source_id: AccountId,
        source: &TokenHolding,
        amount_in: u128,
        amount_out: u128,
    ) -> Result<Self, ExecutionFailureKind> {
        // The wallet proves private swaps with the built-in token program only, so both paths
        // refuse any other rather than one of them failing late.
        if pool.token_program_id != programs::token_account_id() {
            return Err(ExecutionFailureKind::TransactionBuildError(
                lee::error::LeeError::InvalidInput(format!(
                    "Pool {pool_id} uses token program {}, which this wallet cannot swap through",
                    pool.token_program_id
                )),
            ));
        }
        let TokenHolding::Fungible { definition_id, .. } = source else {
            return Err(ExecutionFailureKind::AccountDataError(source_id));
        };
        let (input, output) = pool
            .sides(*definition_id)
            .ok_or(ExecutionFailureKind::AccountDataError(source_id))?;
        Ok(Self {
            pool_id,
            token_program_id: pool.token_program_id,
            input_vault_id: input.vault_id,
            output_vault_id: output.vault_id,
            definition_id_in: input.definition_id,
            definition_id_out: output.definition_id,
            amount_in,
            amount_out,
        })
    }

    // The trader's input holding is the root. Only the payer signs: a public recipient is named
    // without a signature; a private one keeps its keys so the proof can create or update it.
    fn accounts(
        &self,
        user_input: AccountIdentity,
        user_output: AccountIdentity,
    ) -> Vec<AccountMention> {
        let user_output = user_output
            .public_account_id()
            .map_or(user_output, AccountIdentity::PublicNoSign);
        vec![
            user_input.select_program_shard(self.token_program_id),
            user_output.select_program_shard(self.token_program_id),
            AccountIdentity::PublicNoSign(self.pool_id)
                .select_program_shard(programs::amm_account_id()),
            AccountIdentity::PublicNoSign(self.input_vault_id)
                .select_program_shard(self.token_program_id),
            AccountIdentity::PublicNoSign(self.output_vault_id)
                .select_program_shard(self.token_program_id),
        ]
    }

    // The token transfer into the input vault that notifies the pool with the offer.
    fn transfer(&self, accounts: &[AccountMention]) -> token_core::Message {
        swap_transfer(
            Actor::new(self.pool_id, programs::amm_account_id()),
            self.input_vault_id,
            fungible(self.definition_id_in),
            self.amount_in,
            SwapRequest::Offer(SwapOffer {
                definition_id_out: self.definition_id_out,
                amount_out: self.amount_out,
                payout: accounts[1].identity.account_id(),
            }),
        )
    }

    // A fixed offer's payout does not depend on the live price: under the pool's grant, the output
    // vault credits exactly the offered amount. So the proof promises it instead of deriving it
    // from today's reserves, and settlement discharges it only if the pool affords the offer
    // then.
    fn promised_payout(&self, accounts: &[AccountMention]) -> Vec<Vec<Assumption>> {
        let vault = Actor::new(self.output_vault_id, self.token_program_id);
        let payout = token_core::Message::Transfer {
            to: accounts[1].identity.account_id(),
            descriptor: fungible(self.definition_id_out),
            amount: self.amount_out,
            notify: None,
            delivery: Delivery::Call,
        };
        vec![
            expected_sends(vault, &payout)
                .into_iter()
                .filter_map(|action| {
                    let Action::Call(Call {
                        input: CallInput::Inline { to, message },
                        pda_seeds,
                    }) = action
                    else {
                        return None;
                    };
                    accounts
                        .iter()
                        .any(|mention| {
                            mention.identity.is_private()
                                && mention.identity.account_id() == to.account_id
                        })
                        .then(|| Assumption {
                            from: vault,
                            to,
                            message,
                            in_flight: None,
                            grants: vec![self.output_vault_id],
                            pda_seeds,
                        })
                })
                .collect(),
        ]
    }
}

fn add_liquidity(
    pool: &PoolDefinition,
    min_amount_liquidity: u128,
    max_amount_to_add_token_a: u128,
    max_amount_to_add_token_b: u128,
    [user_a, user_b, user_lp]: [AccountId; 3],
) -> Result<amm_core::Message, ExecutionFailureKind> {
    let ideal_a =
        amm_core::ideal_deposit(pool.reserve_a, pool.reserve_b, max_amount_to_add_token_b)
            .ok_or_else(unpriceable)?;
    let ideal_b =
        amm_core::ideal_deposit(pool.reserve_b, pool.reserve_a, max_amount_to_add_token_a)
            .ok_or_else(unpriceable)?;
    let amount_to_add_token_a = ideal_a.min(max_amount_to_add_token_a);
    let amount_to_add_token_b = ideal_b.min(max_amount_to_add_token_b);
    let amount_liquidity = amm_core::liquidity_minted(
        pool.liquidity_pool_supply,
        amount_to_add_token_a,
        amount_to_add_token_b,
        pool.reserve_a,
        pool.reserve_b,
    )
    .ok_or_else(unpriceable)?;
    if amount_liquidity < min_amount_liquidity {
        return Err(outside_limit());
    }

    Ok(amm_core::Message::AddLiquidity {
        max_amount_to_add_token_a,
        max_amount_to_add_token_b,
        amount_to_add_token_a,
        amount_to_add_token_b,
        amount_liquidity,
        user_a,
        user_b,
        user_lp,
    })
}

fn remove_liquidity(
    pool: &PoolDefinition,
    remove_liquidity_amount: u128,
    min_amount_to_remove_token_a: u128,
    min_amount_to_remove_token_b: u128,
    [user_a, user_b, user_lp]: [AccountId; 3],
) -> Result<amm_core::Message, ExecutionFailureKind> {
    let amount_to_remove_token_a = amm_core::withdrawal_share(
        pool.reserve_a,
        remove_liquidity_amount,
        pool.liquidity_pool_supply,
    )
    .ok_or_else(unpriceable)?;
    let amount_to_remove_token_b = amm_core::withdrawal_share(
        pool.reserve_b,
        remove_liquidity_amount,
        pool.liquidity_pool_supply,
    )
    .ok_or_else(unpriceable)?;
    if amount_to_remove_token_a < min_amount_to_remove_token_a
        || amount_to_remove_token_b < min_amount_to_remove_token_b
    {
        return Err(outside_limit());
    }

    Ok(amm_core::Message::RemoveLiquidity {
        remove_liquidity_amount,
        amount_to_remove_token_a,
        amount_to_remove_token_b,
        user_a,
        user_b,
        user_lp,
    })
}

// The three user holdings of a liquidity operation; the pool addresses each at its token program.
fn user_ids(accounts: &[AccountMention]) -> [AccountId; 3] {
    [4, 5, 6].map(|index| accounts[index].actor().account_id)
}

const fn fungible(definition_id: AccountId) -> TokenDescriptor {
    TokenDescriptor {
        definition_id,
        kind: TokenKind::Fungible,
    }
}

fn estimate(
    pool: &PoolDefinition,
    definition_id_in: AccountId,
    amount: QuoteAmount,
) -> Result<Estimate, ExecutionFailureKind> {
    let (input, output) = pool
        .sides(definition_id_in)
        .ok_or(ExecutionFailureKind::AccountDataError(definition_id_in))?;
    match amount {
        QuoteAmount::In(amount_in) => Ok(Estimate {
            amount_in,
            amount_out: amm_core::quote_exact_input(input.reserve, output.reserve, amount_in)
                .ok_or_else(unpriceable)?,
        }),
        QuoteAmount::Out(amount_out) => {
            if amount_out >= output.reserve {
                return Err(unpriceable());
            }
            Ok(Estimate {
                amount_in: amm_core::quote_exact_output(input.reserve, output.reserve, amount_out)
                    .ok_or_else(unpriceable)?,
                amount_out,
            })
        }
    }
}

async fn pool_definition(
    wallet: &WalletCore,
    pool_id: AccountId,
) -> Result<PoolDefinition, ExecutionFailureKind> {
    let data = shard(
        wallet,
        &AccountIdentity::PublicNoSign(pool_id),
        programs::amm_account_id(),
    )
    .await?;
    PoolDefinition::try_from(&data).map_err(|_err| ExecutionFailureKind::AccountDataError(pool_id))
}

fn amm_with_token_dependency() -> ProgramCatalog {
    ProgramCatalog::from([
        (programs::amm_account_id(), programs::amm()),
        (programs::token_account_id(), programs::token()),
    ])
}

fn unpriceable() -> ExecutionFailureKind {
    ExecutionFailureKind::TransactionBuildError(lee::error::LeeError::InvalidInput(
        "The AMM pool's observed reserves cannot price this trade".to_owned(),
    ))
}

fn outside_limit() -> ExecutionFailureKind {
    ExecutionFailureKind::TransactionBuildError(lee::error::LeeError::InvalidInput(
        "The AMM pool's observed reserves price this trade outside the given limit".to_owned(),
    ))
}

#[cfg(test)]
mod tests {
    use lee::error::LeeError;

    use super::*;

    const TOKEN_A: AccountId = AccountId::new([1; 32]);
    const TOKEN_B: AccountId = AccountId::new([2; 32]);
    const POOL: AccountId = AccountId::new([5; 32]);
    const VAULT_A: AccountId = AccountId::new([6; 32]);
    const VAULT_B: AccountId = AccountId::new([7; 32]);
    const SOURCE: AccountId = AccountId::new([10; 32]);
    const DESTINATION: AccountId = AccountId::new([11; 32]);

    // Reserves 1000/500 with the supply `NewDefinition` mints for them, isqrt(500_000).
    fn pool() -> PoolDefinition {
        PoolDefinition {
            token_program_id: programs::token_account_id(),
            definition_token_a_id: TOKEN_A,
            definition_token_b_id: TOKEN_B,
            vault_a_id: AccountId::new([6; 32]),
            vault_b_id: AccountId::new([7; 32]),
            liquidity_pool_id: AccountId::new([8; 32]),
            liquidity_pool_supply: 707,
            reserve_a: 1000,
            reserve_b: 500,
            fees: 0,
            active: true,
        }
    }

    fn users() -> [AccountId; 3] {
        [12, 13, 14].map(|tag| AccountId::new([tag; 32]))
    }

    fn assert_outside_limit<T>(result: Result<T, ExecutionFailureKind>) {
        let Err(err) = result else {
            panic!("the trade was built despite the limit");
        };
        assert!(
            matches!(
                &err,
                ExecutionFailureKind::TransactionBuildError(LeeError::InvalidInput(message))
                    if message == "The AMM pool's observed reserves price this trade outside the given limit"
            ),
            "refused for the wrong reason: {err:?}"
        );
    }

    #[test]
    fn an_add_meeting_its_minimum_liquidity_is_built_and_one_unit_more_is_refused() {
        // Up to 100 of each deposits 100 of A and 50 of B, minting 707 * 100 / 1000 = 70.
        let message = add_liquidity(&pool(), 70, 100, 100, users()).unwrap();
        let amm_core::Message::AddLiquidity {
            amount_to_add_token_a,
            amount_to_add_token_b,
            amount_liquidity,
            ..
        } = message
        else {
            panic!("an add builds an AddLiquidity");
        };
        assert_eq!(
            (
                amount_to_add_token_a,
                amount_to_add_token_b,
                amount_liquidity
            ),
            (100, 50, 70)
        );

        assert_outside_limit(add_liquidity(&pool(), 71, 100, 100, users()));
    }

    #[test]
    fn a_removal_meeting_both_minimums_is_built_and_either_one_unit_higher_is_refused() {
        // Burning 70 of 707 withdraws 1000 * 70 / 707 = 99 of A and 500 * 70 / 707 = 49 of B.
        let message = remove_liquidity(&pool(), 70, 99, 49, users()).unwrap();
        let amm_core::Message::RemoveLiquidity {
            amount_to_remove_token_a,
            amount_to_remove_token_b,
            ..
        } = message
        else {
            panic!("a removal builds a RemoveLiquidity");
        };
        assert_eq!(
            (amount_to_remove_token_a, amount_to_remove_token_b),
            (99, 49)
        );

        assert_outside_limit(remove_liquidity(&pool(), 70, 100, 49, users()));
        assert_outside_limit(remove_liquidity(&pool(), 70, 99, 50, users()));
    }
    fn fungible(definition_id: AccountId) -> TokenHolding {
        TokenHolding::Fungible {
            definition_id,
            balance: 1,
        }
    }

    fn offer(source: AccountId, amount_in: u128, amount_out: u128) -> SwapTerms {
        SwapTerms::new(
            POOL,
            &pool(),
            SOURCE,
            &fungible(source),
            amount_in,
            amount_out,
        )
        .unwrap()
    }

    fn signed_terms(offer: &SwapTerms) -> (AccountId, AccountId, u128, u128) {
        assert_eq!(offer.token_program_id, pool().token_program_id);
        (
            offer.definition_id_in,
            offer.definition_id_out,
            offer.amount_in,
            offer.amount_out,
        )
    }

    #[test]
    fn a_swap_signs_the_requested_amounts_whatever_the_pool_would_quote() {
        // 100 of A into 1000/500 is quoted 45 of B. Asking for less or more is the trader's call,
        // and settlement decides whether the pool can pay it.
        for amount_out in [10, 45, 46, 80] {
            let offer = offer(TOKEN_A, 100, amount_out);
            assert_eq!(signed_terms(&offer), (TOKEN_A, TOKEN_B, 100, amount_out));
            assert_eq!(
                (offer.input_vault_id, offer.output_vault_id),
                (VAULT_A, VAULT_B)
            );
        }

        let reverse = offer(TOKEN_B, 50, 90);
        assert_eq!(signed_terms(&reverse), (TOKEN_B, TOKEN_A, 50, 90));
        assert_eq!(
            (reverse.input_vault_id, reverse.output_vault_id),
            (VAULT_B, VAULT_A)
        );
    }

    #[test]
    fn a_pool_on_a_token_program_the_wallet_cannot_prove_with_is_refused() {
        let pool = PoolDefinition {
            token_program_id: AccountId::new([4; 32]),
            ..pool()
        };
        let Err(err) = SwapTerms::new(POOL, &pool, SOURCE, &fungible(TOKEN_A), 100, 45) else {
            panic!("the offer was built through a token program the wallet cannot prove with");
        };
        assert!(
            matches!(
                &err,
                ExecutionFailureKind::TransactionBuildError(LeeError::InvalidInput(message))
                    if message.contains("which this wallet cannot swap through")
            ),
            "refused for the wrong reason: {err:?}"
        );
    }

    #[test]
    fn a_source_that_is_not_a_fungible_token_of_the_pool_is_refused() {
        for source in [
            fungible(AccountId::new([9; 32])),
            TokenHolding::NftMaster {
                definition_id: TOKEN_A,
                print_balance: 1,
            },
        ] {
            assert!(matches!(
                SwapTerms::new(POOL, &pool(), SOURCE, &source, 100, 45),
                Err(ExecutionFailureKind::AccountDataError(account_id)) if account_id == SOURCE
            ));
        }
    }

    #[test]
    fn a_swap_names_the_pool_its_vaults_and_both_traders_in_order() {
        let keycard = |account_id| AccountIdentity::PublicKeycard {
            account_id,
            key_path: "m/44'/60'/0'/0/1".to_owned(),
        };
        // Given source and destination, then the identities the transaction must carry for them.
        let cases = [
            (
                AccountIdentity::Public(SOURCE),
                AccountIdentity::Public(DESTINATION),
                AccountIdentity::Public(SOURCE),
                AccountIdentity::PublicNoSign(DESTINATION),
            ),
            (
                keycard(SOURCE),
                keycard(DESTINATION),
                keycard(SOURCE),
                AccountIdentity::PublicNoSign(DESTINATION),
            ),
            (
                AccountIdentity::PrivateOwned(SOURCE),
                AccountIdentity::Public(DESTINATION),
                AccountIdentity::PrivateOwned(SOURCE),
                AccountIdentity::PublicNoSign(DESTINATION),
            ),
            (
                AccountIdentity::Public(SOURCE),
                AccountIdentity::PrivateOwned(DESTINATION),
                AccountIdentity::Public(SOURCE),
                AccountIdentity::PrivateOwned(DESTINATION),
            ),
            (
                AccountIdentity::PrivateOwned(SOURCE),
                AccountIdentity::PrivateOwned(DESTINATION),
                AccountIdentity::PrivateOwned(SOURCE),
                AccountIdentity::PrivateOwned(DESTINATION),
            ),
        ];

        let token_program_id = pool().token_program_id;
        for (user_input, user_output, signed_input, named_output) in cases {
            // The destination is only named, never read: an empty holding is created by the
            // deposit.
            let accounts = offer(TOKEN_B, 50, 90).accounts(user_input, user_output);
            let expected = [
                (signed_input, token_program_id),
                (named_output, token_program_id),
                (
                    AccountIdentity::PublicNoSign(POOL),
                    programs::amm_account_id(),
                ),
                (AccountIdentity::PublicNoSign(VAULT_B), token_program_id),
                (AccountIdentity::PublicNoSign(VAULT_A), token_program_id),
            ];
            assert_eq!(accounts.len(), expected.len());
            for (row, (mention, (identity, program_account_id))) in
                accounts.iter().zip(&expected).enumerate()
            {
                assert!(
                    mention.identity == *identity
                        && mention.program_account_id == *program_account_id,
                    "row {row} names the wrong identity or shard"
                );
            }
        }
    }

    #[test]
    fn a_swap_promises_its_exact_payout_only_into_a_private_holding() {
        let terms = offer(TOKEN_A, 100, 45);
        let payout_to = |destination: AccountIdentity| {
            terms.promised_payout(
                &terms.accounts(AccountIdentity::PrivateOwned(SOURCE), destination),
            )
        };
        let vault = Actor::new(terms.output_vault_id, terms.token_program_id);
        let Action::Call(Call {
            input: CallInput::Inline { to, message },
            ..
        }) = expected_sends(
            vault,
            &token_core::Message::Transfer {
                to: DESTINATION,
                descriptor: super::fungible(terms.definition_id_out),
                amount: 45,
                notify: None,
                delivery: Delivery::Call,
            },
        )
        .remove(0)
        else {
            panic!("the token program's payout is an inline call");
        };

        assert_eq!(
            payout_to(AccountIdentity::PrivateOwned(DESTINATION)),
            vec![vec![Assumption {
                from: vault,
                to,
                message,
                in_flight: None,
                grants: vec![terms.output_vault_id],
                pda_seeds: Vec::new(),
            }]]
        );
        assert_eq!(
            payout_to(AccountIdentity::Public(DESTINATION)),
            vec![Vec::new()]
        );
    }

    #[test]
    fn a_quote_estimates_either_amount_from_the_current_reserves() {
        // 100 of A into 1000/500 is quoted 500 * 100 / 1100 = 45 of B; 45 of B out costs
        // ceil(1000 * 45 / 455) = 99 of A.
        assert_eq!(
            estimate(&pool(), TOKEN_A, QuoteAmount::In(100)).unwrap(),
            Estimate {
                amount_in: 100,
                amount_out: 45
            }
        );
        assert_eq!(
            estimate(&pool(), TOKEN_A, QuoteAmount::Out(45)).unwrap(),
            Estimate {
                amount_in: 99,
                amount_out: 45
            }
        );
        assert_eq!(
            estimate(&pool(), TOKEN_B, QuoteAmount::In(50)).unwrap(),
            Estimate {
                amount_in: 50,
                amount_out: 90
            }
        );

        assert!(matches!(
            estimate(&pool(), TOKEN_A, QuoteAmount::Out(500)),
            Err(ExecutionFailureKind::TransactionBuildError(
                LeeError::InvalidInput(_)
            ))
        ));
        assert!(matches!(
            estimate(&pool(), AccountId::new([9; 32]), QuoteAmount::In(1)),
            Err(ExecutionFailureKind::AccountDataError(_))
        ));
    }
}
