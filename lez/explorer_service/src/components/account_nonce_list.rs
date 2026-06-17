use indexer_service_protocol::AccountId;
use itertools::{EitherOrBoth, Itertools as _};
use leptos::prelude::*;
use leptos_router::components::A;

#[component]
pub fn AccountNonceList(account_ids: Vec<AccountId>, nonces: Vec<u128>) -> impl IntoView {
    view! {
        <div class="accounts-list">
            {account_ids
                .into_iter()
                .zip_longest(nonces.into_iter())
                .map(|maybe_pair| {
                    match maybe_pair {
                        EitherOrBoth::Both(account_id, nonce) => {
                            let account_id_str = account_id.to_string();
                            view! {
                                <div class="account-item">
                                    <A href=format!("/account/{}", account_id_str)>
                                        <span class="hash">{account_id_str}</span>
                                    </A>
                                    <span class="nonce">
                                        " (nonce: " {nonce.to_string()} ")"
                                    </span>
                                </div>
                            }
                        }
                        EitherOrBoth::Left(account_id) => {
                            let account_id_str = account_id.to_string();
                            view! {
                                <div class="account-item">
                                    <A href=format!("/account/{}", account_id_str)>
                                        <span class="hash">{account_id_str}</span>
                                    </A>
                                    <span class="nonce">
                                        " (nonce: "{"Not affected by this transaction".to_owned()}" )"
                                    </span>
                                </div>
                            }
                        }
                        EitherOrBoth::Right(_) => {
                            view! {
                                <div class="account-item">
                                    <A href=format!("/account/{}", "Account not found")>
                                        <span class="hash">{"Account not found"}</span>
                                    </A>
                                    <span class="nonce">
                                        " (nonce: "{"Account not found".to_owned()}" )"
                                    </span>
                                </div>
                            }
                        }
                    }
                })
                .collect::<Vec<_>>()}
        </div>
    }
}
