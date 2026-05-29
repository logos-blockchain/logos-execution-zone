use indexer_service_protocol::{Account, AccountId};
use leptos::prelude::*;
use leptos_router::components::A;

/// Account preview component
#[component]
pub fn AccountPreview(account_id: AccountId, account: Account) -> impl IntoView {
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
                    let Account { program_owner, balance, data, nonce } = &account;
                    let program_id = program_owner.to_string();
                    view! {
                        <div class="account-preview-body">
                            <div class="account-field">
                                <span class="field-label">"Balance: "</span>
                                <span class="field-value">{balance.to_string()}</span>
                            </div>
                            <div class="account-field">
                                <span class="field-label">"Program: "</span>
                                <span class="field-value hash">{program_id}</span>
                            </div>
                            <div class="account-field">
                                <span class="field-label">"Nonce: "</span>
                                <span class="field-value">{nonce.to_string()}</span>
                            </div>
                            <div class="account-field">
                                <span class="field-label">"Data: "</span>
                                <span class="field-value">
                                    {format!("{} bytes", data.0.len())}
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
