use std::str::FromStr as _;

use indexer_service_protocol::{Account, AccountId};
use leptos::prelude::*;
use leptos_router::hooks::use_params_map;

use crate::{api, components::TransactionPreview};

/// Account page component
#[component]
pub fn AccountPage() -> impl IntoView {
    let params = use_params_map();
    let (tx_offset, set_tx_offset) = signal(0_u64);
    let (all_transactions, set_all_transactions) = signal(Vec::new());
    let (is_loading, set_is_loading) = signal(false);
    let (has_more, set_has_more) = signal(true);
    let tx_limit = 10_u64;

    // Parse account ID from URL params
    let account_id = move || {
        let account_id_str = params.read().get("id").unwrap_or_default();
        AccountId::from_str(&account_id_str).ok()
    };

    // Load account data
    let account_resource = Resource::new(account_id, |acc_id_opt| async move {
        match acc_id_opt {
            Some(acc_id) => api::get_account(acc_id).await,
            None => Err(leptos::prelude::ServerFnError::ServerError(
                "Invalid account ID".to_owned(),
            )),
        }
    });

    // Load initial transactions
    let transactions_resource = Resource::new(account_id, move |acc_id_opt| async move {
        match acc_id_opt {
            Some(acc_id) => api::get_transactions_by_account(acc_id, 0, tx_limit).await,
            None => Err(leptos::prelude::ServerFnError::ServerError(
                "Invalid account ID".to_owned(),
            )),
        }
    });

    // Update all_transactions when initial load completes
    Effect::new(move || {
        if let Some(Ok(txs)) = transactions_resource.get() {
            set_all_transactions.set(txs.clone());
            set_has_more.set(
                u64::try_from(txs.len()).expect("Transaction count should fit in u64") == tx_limit,
            );
        }
    });

    // Load more transactions handler
    let load_more = move |_| {
        let Some(acc_id) = account_id() else {
            return;
        };

        set_is_loading.set(true);
        let current_offset = tx_offset.get().saturating_add(tx_limit);
        set_tx_offset.set(current_offset);

        leptos::task::spawn_local(async move {
            match api::get_transactions_by_account(acc_id, current_offset, tx_limit).await {
                Ok(new_txs) => {
                    let txs_count =
                        u64::try_from(new_txs.len()).expect("Transaction count should fit in u64");
                    set_all_transactions.update(|txs| txs.extend(new_txs));
                    set_has_more.set(txs_count == tx_limit);
                }
                Err(e) => {
                    log::error!("Failed to load more transactions: {e}");
                }
            }
            set_is_loading.set(false);
        });
    };

    view! {
        <div class="account-page">
            <Suspense fallback=move || view! { <div class="loading">"Loading account..."</div> }>
                {move || {
                    account_resource
                        .get()
                        .map(|result| match result {
                            Ok(acc) => {
                                let Account {
                                    program_owner,
                                    balance,
                                    data,
                                    nonce,
                                } = acc;

                                let acc_id = account_id().expect("Account ID should be set");
                                let account_id_str = acc_id.to_string();
                                let program_id = program_owner.to_string();
                                let balance_str = balance.to_string();
                                let nonce_str = nonce.to_string();
                                let data_len = data.0.len();
                                view! {
                                    <div class="account-detail">
                                        <div class="page-header">
                                            <h1>"Account"</h1>
                                        </div>

                                        <div class="account-info">
                                            <h2>"Account Information"</h2>
                                            <div class="info-grid">
                                                <div class="info-row">
                                                    <span class="info-label">"Account ID:"</span>
                                                    <span class="info-value hash">{account_id_str}</span>
                                                </div>
                                                <div class="info-row">
                                                    <span class="info-label">"Balance:"</span>
                                                    <span class="info-value">{balance_str}</span>
                                                </div>
                                                <div class="info-row">
                                                    <span class="info-label">"Program Owner:"</span>
                                                    <span class="info-value hash">{program_id}</span>
                                                </div>
                                                <div class="info-row">
                                                    <span class="info-label">"Nonce:"</span>
                                                    <span class="info-value">{nonce_str}</span>
                                                </div>
                                                <div class="info-row">
                                                    <span class="info-label">"Data:"</span>
                                                    <span class="info-value">{format!("{data_len} bytes")}</span>
                                                </div>
                                            </div>
                                        </div>

                                        <div class="account-transactions">
                                            <h2>"Transactions"</h2>
                                            <Suspense fallback=move || {
                                                view! { <div class="loading">"Loading transactions..."</div> }
                                            }>
                                                {move || {
                                                    transactions_resource
                                                        .get()
                                                        .map(|load_tx_result| match load_tx_result {
                                                            Ok(_) => {
                                                                let txs = all_transactions.get();
                                                                if txs.is_empty() {
                                                                    view! {
                                                                        <div class="no-transactions">
                                                                            "No transactions found"
                                                                        </div>
                                                                    }
                                                                        .into_any()
                                                                } else {
                                                                    view! {
                                                                        <div>
                                                                            <div class="transactions-list">
                                                                                {txs
                                                                                    .into_iter()
                                                                                    .map(|tx| {
                                                                                        view! { <TransactionPreview transaction=tx /> }
                                                                                    })
                                                                                    .collect::<Vec<_>>()}
                                                                            </div>
                                                                            {move || {
                                                                                if has_more.get() {
                                                                                    view! {
                                                                                        <button
                                                                                            class="load-more-button"
                                                                                            on:click=load_more
                                                                                            disabled=move || is_loading.get()
                                                                                        >
                                                                                            {move || {
                                                                                                if is_loading.get() {
                                                                                                    "Loading..."
                                                                                                } else {
                                                                                                    "Load More"
                                                                                                }
                                                                                            }}

                                                                                        </button>
                                                                                    }
                                                                                        .into_any()
                                                                                } else {
                                                                                    ().into_any()
                                                                                }
                                                                            }}

                                                                        </div>
                                                                    }
                                                                        .into_any()
                                                                }
                                                            }
                                                            Err(e) => {
                                                                view! {
                                                                    <div class="error">
                                                                        {format!("Failed to load transactions: {e}")}
                                                                    </div>
                                                                }
                                                                    .into_any()
                                                            }
                                                        })
                                                }}
                                            </Suspense>
                                        </div>
                                    </div>
                                }
                                    .into_any()
                            }
                            Err(e) => {
                                view! {
                                    <div class="error-page">
                                        <h1>"Error"</h1>
                                        <p>{format!("Failed to load account: {e}")}</p>
                                    </div>
                                }
                                    .into_any()
                            }
                        })
                }}
            </Suspense>
        </div>
    }
}
