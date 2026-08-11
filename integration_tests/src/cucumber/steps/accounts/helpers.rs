use test_fixtures::config::default_public_accounts_for_wallet;

pub(super) fn expected_public_balance(account: lee::AccountId) -> Option<u128> {
    default_public_accounts_for_wallet()
        .into_iter()
        .find_map(|(private_key, balance)| {
            let configured_account =
                lee::AccountId::from(&lee::PublicKey::new_from_private_key(&private_key));
            (configured_account == account).then_some(balance)
        })
}
