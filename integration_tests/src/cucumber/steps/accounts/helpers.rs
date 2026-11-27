use lee::test_utils::TestSigner;
use test_fixtures::config::{
    default_private_accounts_for_wallet, default_public_accounts_for_wallet,
    private_funder_account_id, private_funding_cost,
};

pub(super) fn expected_public_balance(account: lee::AccountId) -> Option<u128> {
    let private_funder = private_funder_account_id();
    let private_pool_total = private_funding_cost(&default_private_accounts_for_wallet());

    default_public_accounts_for_wallet()
        .into_iter()
        .find_map(|(private_key, balance)| {
            let configured_account = TestSigner::from(&private_key).account_id();
            if configured_account != account {
                return None;
            }

            // The public Cucumber fixture deliberately skips private-account
            // initialization, but genesis still adds the private pool total
            // and its shielding fees to the public funder account.
            if configured_account == private_funder {
                balance.checked_add(private_pool_total)
            } else {
                Some(balance)
            }
        })
}
