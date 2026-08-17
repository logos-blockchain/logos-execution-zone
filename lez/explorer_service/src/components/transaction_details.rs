use indexer_service_protocol::{
    PrivacyPreservingMessage, PrivacyPreservingTransaction, ProgramDeploymentMessage,
    ProgramDeploymentTransaction, PublicMessage, PublicTransaction, WitnessSet,
};
use leptos::prelude::*;

use super::AccountNonceList;

/// Public transaction details component
#[component]
pub fn PublicTxDetails(tx: PublicTransaction) -> impl IntoView {
    let PublicTransaction {
        hash: _,
        message,
        witness_set,
    } = tx;
    let PublicMessage {
        program_id,
        account_ids,
        nonces,
        instruction_data,
        payer,
        gas_limit,
        tip,
        max_fee,
    } = message;
    let WitnessSet {
        signatures_and_public_keys,
        proof,
    } = witness_set;

    let program_id_str = program_id.to_string();
    let proof_len = proof.map_or(0, |p| p.0.len());
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
                <div class="info-row">
                    <span class="info-label">"Fee Payer:"</span>
                    <span class="info-value hash">{payer.to_string()}</span>
                </div>
                <div class="info-row">
                    <span class="info-label">"Gas Limit / Tip / Max Fee:"</span>
                    <span class="info-value">
                        {format!("{gas_limit} / {tip} / {max_fee}")}
                    </span>
                </div>
            </div>

            <h3>"Accounts"</h3>
            <AccountNonceList account_ids=account_ids nonces=nonces />
        </div>
    }
}

/// Privacy-preserving transaction details component
#[component]
pub fn PrivacyPreservingTxDetails(tx: PrivacyPreservingTransaction) -> impl IntoView {
    let PrivacyPreservingTransaction {
        hash: _,
        message,
        witness_set,
    } = tx;
    let PrivacyPreservingMessage {
        public_actions,
        nonces,
        private_actions,
        block_validity_window,
        timestamp_validity_window,
    } = message;
    let private_action_count = private_actions.len();
    let public_account_ids: Vec<_> = public_actions
        .into_iter()
        .map(|action| action.account_id)
        .collect();
    let public_account_count = public_account_ids.len();
    let WitnessSet {
        signatures_and_public_keys: _,
        proof,
    } = witness_set;
    let proof_len = proof.map_or(0, |p| p.0.len());

    view! {
        <div class="transaction-details">
            <h2>"Privacy-Preserving Transaction Details"</h2>
            <div class="info-grid">
                <div class="info-row">
                    <span class="info-label">"Public Accounts:"</span>
                    <span class="info-value">
                        {public_account_count.to_string()}
                    </span>
                </div>
                <div class="info-row">
                    <span class="info-label">"Private Actions:"</span>
                    <span class="info-value">{private_action_count.to_string()}</span>
                </div>
                <div class="info-row">
                    <span class="info-label">"Proof Size:"</span>
                    <span class="info-value">{format!("{proof_len} bytes")}</span>
                </div>
                <div class="info-row">
                    <span class="info-label">"Block Validity Window:"</span>
                    <span class="info-value">{block_validity_window.to_string()}</span>
                </div>
                <div class="info-row">
                    <span class="info-label">"Timestamp Validity Window:"</span>
                    <span class="info-value">{timestamp_validity_window.to_string()}</span>
                </div>
            </div>

            <h3>"Public Accounts"</h3>
            <AccountNonceList account_ids=public_account_ids nonces=nonces />
        </div>
    }
}

/// Program deployment transaction details component
#[component]
pub fn ProgramDeploymentTxDetails(tx: ProgramDeploymentTransaction) -> impl IntoView {
    let ProgramDeploymentTransaction { hash: _, message } = tx;
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
}
