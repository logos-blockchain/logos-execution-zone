use std::str::FromStr as _;

use indexer_service_protocol::{HashType, Transaction};
use leptos::prelude::*;
use leptos_router::hooks::use_params_map;

use crate::{
    api,
    components::{PrivacyPreservingTxDetails, PublicTxDetails},
};

/// Transaction page component
#[component]
pub fn TransactionPage() -> impl IntoView {
    let params = use_params_map();

    let transaction_resource = Resource::new(
        move || {
            let s = params.read().get("hash")?;
            HashType::from_str(&s).ok()
        },
        |hash_opt| async move {
            match hash_opt {
                Some(hash) => api::get_transaction(hash).await,
                None => Err(leptos::prelude::ServerFnError::ServerError(
                    "Invalid transaction hash".to_owned(),
                )),
            }
        },
    );

    view! {
        <div class="transaction-page">
            <Suspense fallback=move || view! { <div class="loading">"Loading transaction..."</div> }>
                {move || {
                    transaction_resource
                        .get()
                        .map(|result| match result {
                            Ok(tx) => {
                                let tx_hash = tx.hash().to_string();
                                let tx_type = match &tx {
                                    Transaction::Public(_) => "Public Transaction",
                                    Transaction::PrivacyPreserving(_) => "Privacy-Preserving Transaction",
                                };
                                view! {
                                    <div class="transaction-detail">
                                        <div class="page-header">
                                            <h1>"Transaction"</h1>
                                        </div>

                                        <div class="transaction-info">
                                            <h2>"Transaction Information"</h2>
                                            <div class="info-grid">
                                                <div class="info-row">
                                                    <span class="info-label">"Hash:"</span>
                                                    <span class="info-value hash">{tx_hash}</span>
                                                </div>
                                                <div class="info-row">
                                                    <span class="info-label">"Type:"</span>
                                                    <span class="info-value">{tx_type}</span>
                                                </div>
                                            </div>
                                        </div>

                                        {
                                            match tx {
                                                Transaction::Public(ptx) => {
                                                    view! { <PublicTxDetails tx=ptx /> }.into_any()
                                                }
                                                Transaction::PrivacyPreserving(pptx) => {
                                                    view! { <PrivacyPreservingTxDetails tx=pptx /> }.into_any()
                                                }
                                            }
                                        }

                                    </div>
                                }
                                    .into_any()
                            }
                            Err(e) => {
                                view! {
                                    <div class="error-page">
                                        <h1>"Error"</h1>
                                        <p>{format!("Failed to load transaction: {e}")}</p>
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
