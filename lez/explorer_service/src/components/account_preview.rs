use indexer_service_protocol::{AccountId, AccountSummary};
use leptos::prelude::*;
use leptos_router::components::A;

/// Account preview component
#[component]
pub fn AccountPreview(account_id: AccountId, account: AccountSummary) -> impl IntoView {
    let account_id_str = account_id.to_string();

    view! {
        <div class="account-preview">
            <A href=format!("/account/{}", account_id_str) attr:class="account-preview-link">
                <div class="account-preview-header">
                    <div class="account-id">
                        <span class="label">"Account "</span>
                        <span class="value hash">{account_id_str.clone()}</span>
                    </div>
                </div>
                {move || {
                    let AccountSummary {
                        nonce,
                        balance,
                        actor_states,
                    } = &account;
                    let balance = balance
                        .map_or_else(|| "<malformed>".to_owned(), |balance| balance.to_string());
                    let actor_states_len = actor_states.len();
                    let actor_states_bytes: u64 = actor_states.iter().map(|actor_state| actor_state.len).sum();
                    view! {
                        <div class="account-preview-body">
                            <div class="account-field">
                                <span class="field-label">"Balance: "</span>
                                <span class="field-value">{balance}</span>
                            </div>
                            <div class="account-field">
                                <span class="field-label">"Nonce: "</span>
                                <span class="field-value">{nonce.to_string()}</span>
                            </div>
                            <div class="account-field">
                                <span class="field-label">"Actor states: "</span>
                                <span class="field-value">
                                    {format!("{actor_states_len} programs, {actor_states_bytes} bytes total")}
                                </span>
                            </div>
                        </div>
                    }
                    .into_any()
                }}

            </A>
        </div>
    }
}
