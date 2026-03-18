use std::str::FromStr as _;

use indexer_service_protocol::{
    HashType, PrivacyPreservingMessage, PrivacyPreservingTransaction, ProgramDeploymentMessage,
    ProgramDeploymentTransaction, PublicMessage, PublicTransaction, Transaction, WitnessSet,
};
use itertools::{EitherOrBoth, Itertools as _};
use leptos::prelude::*;
use leptos_router::{components::A, hooks::use_params_map};

use crate::api;

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
                                    Transaction::ProgramDeployment(_) => "Program Deployment Transaction",
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
                                    let PublicTransaction {
                                        hash: _,
                                        message,
                                        witness_set,
                                    } = ptx;
                                    let PublicMessage {
                                        program_id,
                                        account_ids,
                                        nonces,
                                        instruction_data,
                                    } = message;
                                    let WitnessSet {
                                        signatures_and_public_keys,
                                        proof,
                                    } = witness_set;

                                    let program_id_str = program_id.to_string();
                                    let proof_len = proof.0.len();
                                    let signatures_count = signatures_and_public_keys.len();

                                    view! {
                                        <div class="transaction-details">
                                            <h2>"Public Transaction Details"</h2>
                                            <div class="info-grid">
                                                <div class="info-row">
                                                    <span class="info-label">"Program ID:"</span>
                                                    <span class="info-value hash">{program_id_str}</span>
                                                </div>
                                                <div class="info-row">
                                                    <span class="info-label">"Instruction Data:"</span>
                                                    <span class="info-value">
                                                        {format!("{} u32 values", instruction_data.len())}
                                                    </span>
                                                </div>
                                                <div class="info-row">
                                                    <span class="info-label">"Proof Size:"</span>
                                                    <span class="info-value">{format!("{proof_len} bytes")}</span>
                                                </div>
                                                <div class="info-row">
                                                    <span class="info-label">"Signatures:"</span>
                                                    <span class="info-value">{signatures_count.to_string()}</span>
                                                </div>
                                            </div>

                                            <h3>"Accounts"</h3>
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
                                        </div>
                                    }
                                        .into_any()
                                }
                                Transaction::PrivacyPreserving(pptx) => {
                                    let PrivacyPreservingTransaction {
                                        hash: _,
                                        message,
                                        witness_set,
                                    } = pptx;
                                    let PrivacyPreservingMessage {
                                        public_account_ids,
                                        nonces,
                                        public_post_states: _,
                                        encrypted_private_post_states,
                                        new_commitments,
                                        new_nullifiers,
                                    } = message;
                                    let WitnessSet {
                                        signatures_and_public_keys: _,
                                        proof,
                                    } = witness_set;

                                    let proof_len = proof.0.len();
                                    view! {
                                        <div class="transaction-details">
                                            <h2>"Privacy-Preserving Transaction Details"</h2>
                                            <div class="info-grid">
                                                <div class="info-row">
                                                    <span class="info-label">"Public Accounts:"</span>
                                                    <span class="info-value">
                                                        {public_account_ids.len().to_string()}
                                                    </span>
                                                </div>
                                                <div class="info-row">
                                                    <span class="info-label">"New Commitments:"</span>
                                                    <span class="info-value">{new_commitments.len().to_string()}</span>
                                                </div>
                                                <div class="info-row">
                                                    <span class="info-label">"Nullifiers:"</span>
                                                    <span class="info-value">{new_nullifiers.len().to_string()}</span>
                                                </div>
                                                <div class="info-row">
                                                    <span class="info-label">"Encrypted States:"</span>
                                                    <span class="info-value">
                                                        {encrypted_private_post_states.len().to_string()}
                                                    </span>
                                                </div>
                                                <div class="info-row">
                                                    <span class="info-label">"Proof Size:"</span>
                                                    <span class="info-value">{format!("{proof_len} bytes")}</span>
                                                </div>
                                            </div>

                                            <h3>"Public Accounts"</h3>
                                            <div class="accounts-list">
                                                {public_account_ids
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
                                        </div>
                                    }
                                        .into_any()
                                }
                                Transaction::ProgramDeployment(pdtx) => {
                                    let ProgramDeploymentTransaction {
                                        hash: _,
                                        message,
                                    } = pdtx;
                                    let ProgramDeploymentMessage { bytecode } = message;

                                    let bytecode_len = bytecode.len();
                                    view! {
                                        <div class="transaction-details">
                                            <h2>"Program Deployment Transaction Details"</h2>
                                            <div class="info-grid">
                                                <div class="info-row">
                                                    <span class="info-label">"Bytecode Size:"</span>
                                                    <span class="info-value">
                                                        {format!("{bytecode_len} bytes")}
                                                    </span>
                                                </div>
                                            </div>
                                        </div>
                                    }
                                        .into_any()
                                }
                            }}

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
