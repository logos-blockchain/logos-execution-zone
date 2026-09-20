use indexer_service_protocol::{BalanceDiff, DeferredResolution, PublicActionWithID};
use leptos::prelude::*;
use leptos_router::components::A;

/// Renders each public action, distinguishing `Bound` (fully resolved) from `Deferred`
/// (an unresolved delta, not final until settlement).
#[component]
pub fn PublicActionList(actions: Vec<PublicActionWithID>) -> impl IntoView {
    view! {
        <div class="accounts-list">
            {actions
                .into_iter()
                .map(|action| match action {
                    PublicActionWithID::Bound { account_id, post_state } => {
                        let account_id_str = account_id.to_string();
                        view! {
                            <div class="account-item">
                                <A href=format!("/account/{account_id_str}")>
                                    <span class="hash">{account_id_str}</span>
                                </A>
                                <span class="action-badge action-badge-bound">"Bound"</span>
                                <span class="nonce">
                                    " balance: " {post_state.balance.to_string()} ", data: "
                                    {post_state.data.0.len().to_string()} " bytes"
                                </span>
                            </div>
                        }
                            .into_any()
                    }
                    PublicActionWithID::Deferred { account_id, resolutions } => {
                        let account_id_str = account_id.to_string();
                        let resolution_count = resolutions.len();
                        view! {
                            <div class="account-item">
                                <A href=format!("/account/{account_id_str}")>
                                    <span class="hash">{account_id_str}</span>
                                </A>
                                <span class="action-badge action-badge-deferred">"Deferred"</span>
                                <span class="nonce">
                                    " " {resolution_count.to_string()}
                                    " pending update(s) - resolved at settlement, not final here"
                                </span>
                                <div class="resolution-list">
                                    {resolutions
                                        .into_iter()
                                        .map(|resolution| {
                                            let DeferredResolution {
                                                executing_account_id,
                                                post_balance_diff,
                                                post_data,
                                            } = resolution;
                                            let program_str = executing_account_id.to_string();
                                            let balance_delta = match post_balance_diff {
                                                BalanceDiff::Add(amount) => format!("+{amount}"),
                                                BalanceDiff::Sub(amount) => format!("-{amount}"),
                                            };
                                            let data_note = if post_data.is_some() {
                                                "data updated"
                                            } else {
                                                "data unchanged"
                                            };
                                            view! {
                                                <div class="resolution-item">
                                                    "by "
                                                    <A href=format!("/account/{program_str}")>
                                                        <span class="hash">{program_str}</span>
                                                    </A>
                                                    <span class="nonce">
                                                        ": balance " {balance_delta} ", "
                                                        {data_note}
                                                    </span>
                                                </div>
                                            }
                                        })
                                        .collect::<Vec<_>>()}
                                </div>
                            </div>
                        }
                            .into_any()
                    }
                })
                .collect::<Vec<_>>()}
        </div>
    }
}
