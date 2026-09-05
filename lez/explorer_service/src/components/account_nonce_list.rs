use indexer_service_protocol::Position;
use itertools::{EitherOrBoth, Itertools as _};
use leptos::prelude::*;
use leptos_router::components::A;

/// The account link plus, when the position names one, the program whose record it names.
fn position_link(position: Position) -> impl IntoView {
    let account_id_str = position.account_id.to_string();
    let program_str = position.program.map(|program| program.to_string());
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
pub fn AccountNonceList(positions: Vec<Position>, nonces: Vec<u128>) -> impl IntoView {
    view! {
        <div class="accounts-list">
            {positions
                .into_iter()
                .zip_longest(nonces.into_iter())
                .map(|maybe_pair| {
                    match maybe_pair {
                        EitherOrBoth::Both(position, nonce) => {
                            view! {
                                <div class="account-item">
                                    {position_link(position)}
                                    <span class="nonce">
                                        " (nonce: " {nonce.to_string()} ")"
                                    </span>
                                </div>
                            }
                            .into_any()
                        }
                        EitherOrBoth::Left(position) => {
                            view! {
                                <div class="account-item">
                                    {position_link(position)}
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
