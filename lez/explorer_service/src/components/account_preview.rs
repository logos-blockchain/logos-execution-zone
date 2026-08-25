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
                    let Account { nonce, slots } = &account;
                    view! {
                        <div class="account-preview-body">
                            <div class="account-field">
                                <span class="field-label">"Nonce: "</span>
                                <span class="field-value">{nonce.to_string()}</span>
                            </div>
                            {slots
                                .iter()
                                .map(|(program_id, slot)| {
                                    view! {
                                        <div class="account-field">
                                            <span class="field-label hash">
                                                {program_id.to_string()}
                                            </span>
                                            <span class="field-value">{slot.balance.to_string()}</span>
                                            <span class="field-value">
                                                {format!("{} bytes", slot.data.0.len())}
                                            </span>
                                        </div>
                                    }
                                })
                                .collect::<Vec<_>>()}
                        </div>
                    }
                    .into_any()
                }}

            </A>
        </div>
    }
}
