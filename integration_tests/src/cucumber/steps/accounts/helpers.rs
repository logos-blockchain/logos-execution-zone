use test_fixtures::config::{
    default_private_accounts_for_wallet, default_public_accounts_for_wallet, private_total,
};

pub(super) fn expected_public_balance(account: lee::AccountId) -> Option<u128> {
    default_public_accounts_for_wallet()
        .into_iter()
        .enumerate()
        .find_map(|(index, (private_key, balance))| {
            let configured_account =
                lee::AccountId::from(&lee::PublicKey::new_from_private_key(&private_key));
            if configured_account != account {
                return None;
            }

            // The public Cucumber fixture deliberately skips private-account
            // initialization, but genesis still adds the private pool total
            // to its public funder account.
            if index == 0 {
                balance.checked_add(private_total(&default_private_accounts_for_wallet()))
            } else {
                Some(balance)
            }
        })
}
