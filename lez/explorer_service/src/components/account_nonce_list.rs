use indexer_service_protocol::ProgramShardSelector;
use itertools::{EitherOrBoth, Itertools as _};
use leptos::prelude::*;
use leptos_router::components::A;

/// Displays the account link and optional program account ID.
fn shard_selector_link(shard_selector: ProgramShardSelector) -> impl IntoView {
    let account_id_str = shard_selector.account_id.to_string();
    let program_str = shard_selector
        .program_account_id
        .map(|program| program.to_string());
    view! {
        <A href=format!("/account/{}", account_id_str)>
            <span class="hash">{account_id_str}</span>
        </A>
        {program_str
            .map(|program_str| {
                view! {
                    <span class="program">
                        " (program: " <span class="hash">{program_str}</span> ")"
                    </span>
                }
            })}
    }
}

#[component]
pub fn AccountNonceList(
    shard_selectors: Vec<ProgramShardSelector>,
    nonces: Vec<u128>,
) -> impl IntoView {
    view! {
        <div class="accounts-list">
            {shard_selectors
                .into_iter()
                .zip_longest(nonces.into_iter())
                .map(|maybe_pair| {
                    match maybe_pair {
                        EitherOrBoth::Both(shard_selector, nonce) => {
                            view! {
                                <div class="account-item">
                                    {shard_selector_link(shard_selector)}
                                    <span class="nonce">
                                        " (nonce: " {nonce.to_string()} ")"
                                    </span>
                                </div>
                            }
                            .into_any()
                        }
                        EitherOrBoth::Left(shard_selector) => {
                            view! {
                                <div class="account-item">
                                    {shard_selector_link(shard_selector)}
                                    <span class="nonce">
                                        " (nonce: "{"Not affected by this transaction".to_owned()}" )"
                                    </span>
                                </div>
                            }
                            .into_any()
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
                            .into_any()
                        }
                    }
                })
                .collect::<Vec<_>>()}
        </div>
    }
}
