use nssa_core::account::{AccountId, AccountWithMetadata};

pub fn read_fungible_holding(account: &AccountWithMetadata, context: &str) -> (AccountId, u128) {
    let token_holding = token_core::TokenHolding::try_from(&account.account.data)
        .unwrap_or_else(|_| panic!("{context}: AMM Program expects a valid Token Holding Account"));

    let token_core::TokenHolding::Fungible {
        definition_id,
        balance,
    } = token_holding
    else {
        panic!("{context}: AMM Program expects a valid Fungible Token Holding Account");
    };

    (definition_id, balance)
}

pub fn read_vault_fungible_balances(
    vault_a: &AccountWithMetadata,
    vault_b: &AccountWithMetadata,
) -> (u128, u128) {
    let (_, vault_a_balance) = read_fungible_holding(vault_a, "Vault A");
    let (_, vault_b_balance) = read_fungible_holding(vault_b, "Vault B");

    (vault_a_balance, vault_b_balance)
}
