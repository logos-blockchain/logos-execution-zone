use indexer_service_protocol::{
    BoundaryStep, PrivacyPreservingMessage, PrivacyPreservingTransaction, PublicExecutionContext,
    PublicMessage, PublicTransaction, TransactionEntry, WitnessSet,
};
use leptos::prelude::*;

use super::ActorList;

/// Public transaction details component
#[component]
pub fn PublicTxDetails(tx: PublicTransaction) -> impl IntoView {
    let PublicTransaction {
        hash: _,
        message,
        witness_set,
    } = tx;
    let PublicMessage {
        root,
        public_actors,
        nonces,
        fee,
        identities: _,
    } = message;
    let WitnessSet {
        signatures_and_public_keys,
        proof,
    } = witness_set;

    let (program_id_str, message_str, root_actors) = match root {
        TransactionEntry::Call { to, message: data } => (
            to.program_account_id.to_string(),
            format!("{} bytes", data.len()),
            vec![to],
        ),
        TransactionEntry::Cast(id) => ("None (receipt)".to_owned(), id.to_string(), Vec::new()),
    };
    let proof_len = proof.map_or(0, |p| p.0.len());
    let signatures_count = signatures_and_public_keys.len();
    let signer_nonces_str = nonces
        .iter()
        .map(ToString::to_string)
        .collect::<Vec<_>>()
        .join(", ");
    let (fee_payer_str, fee_amounts_str) = fee.map_or_else(
        || ("None (exempt)".to_owned(), "None (exempt)".to_owned()),
        |fee| {
            (
                fee.payer.to_string(),
                format!("{} / {} / {}", fee.gas_limit, fee.tip, fee.max_fee),
            )
        },
    );

    view! {
        <div class="transaction-details">
            <h2>"Public Transaction Details"</h2>
            <div class="info-grid">
                <div class="info-row">
                    <span class="info-label">"Program ID:"</span>
                    <span class="info-value hash">{program_id_str}</span>
                </div>
                <div class="info-row">
                    <span class="info-label">"Message:"</span>
                    <span class="info-value">{message_str}</span>
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
                    <span class="info-value hash">{fee_payer_str}</span>
                </div>
                <div class="info-row">
                    <span class="info-label">"Gas Limit / Tip / Max Fee:"</span>
                    <span class="info-value">{fee_amounts_str}</span>
                </div>
                <div class="info-row">
                    <span class="info-label">"Signer Nonces:"</span>
                    <span class="info-value">{signer_nonces_str}</span>
                </div>
            </div>

            <h3>"Root Actor"</h3>
            <ActorList actors=root_actors />

            <h3>"Public Actors"</h3>
            <ActorList actors=public_actors />
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
        context,
        boundary,
        casts: _,
        entry: _,
        nonces,
        private_actions,
        block_validity_window,
        timestamp_validity_window,
        identities: _,
    } = message;
    let PublicExecutionContext {
        actors: public_actors,
        authorized_accounts,
    } = context;
    let private_action_count = private_actions.len();
    let public_actor_count = public_actors.len();
    let authorized_count = authorized_accounts.len();
    let steps_str = boundary
        .iter()
        .map(|step| match step {
            BoundaryStep::CallPublic(_) => "CallPublic",
            BoundaryStep::EnterPrivate(_) => "EnterPrivate",
            BoundaryStep::LeavePrivate => "LeavePrivate",
            BoundaryStep::ReturnPublic => "ReturnPublic",
        })
        .collect::<Vec<_>>()
        .join(", ");
    // The public actors the private execution called, and those that called into it.
    let mut delivery_receivers = Vec::new();
    let mut assumption_senders = Vec::new();
    for step in boundary {
        match step {
            BoundaryStep::CallPublic(delivery) => delivery_receivers.push(delivery.envelope.to),
            BoundaryStep::EnterPrivate(assumption) => {
                assumption_senders.push(assumption.envelope.source);
            }
            BoundaryStep::LeavePrivate | BoundaryStep::ReturnPublic => {}
        }
    }
    let signer_nonces_str = nonces
        .iter()
        .map(ToString::to_string)
        .collect::<Vec<_>>()
        .join(", ");
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
                    <span class="info-label">"Public Actors:"</span>
                    <span class="info-value">{public_actor_count.to_string()}</span>
                </div>
                <div class="info-row">
                    <span class="info-label">"Authorized Accounts:"</span>
                    <span class="info-value">{authorized_count.to_string()}</span>
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
                <div class="info-row">
                    <span class="info-label">"Signer Nonces:"</span>
                    <span class="info-value">{signer_nonces_str}</span>
                </div>
                <div class="info-row">
                    <span class="info-label">"Boundary Steps:"</span>
                    <span class="info-value">{steps_str}</span>
                </div>
            </div>

            <h3>"Declared Public Actors"</h3>
            <ActorList actors=public_actors />

            <h3>"Boundary Public Deliveries"</h3>
            <ActorList actors=delivery_receivers />

            <h3>"Boundary Assumptions"</h3>
            <ActorList actors=assumption_senders />
        </div>
    }
}
