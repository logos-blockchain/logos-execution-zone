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
                        shards,
                    } = &account;
                    let balance = balance
                        .map_or_else(|| "<malformed>".to_owned(), |balance| balance.to_string());
                    let shards_len = shards.len();
                    let shards_bytes: u64 = shards.iter().map(|shard| shard.len).sum();
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
                                <span class="field-label">"Shards: "</span>
                                <span class="field-value">
                                    {format!("{shards_len} programs, {shards_bytes} bytes total")}
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
