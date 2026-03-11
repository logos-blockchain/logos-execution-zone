use indexer_service_protocol::Transaction;
use leptos::prelude::*;
use leptos_router::components::A;

/// Get transaction type name and CSS class.
const fn transaction_type_info(tx: &Transaction) -> (&'static str, &'static str) {
    match tx {
        Transaction::Public(_) => ("Public", "tx-type-public"),
        Transaction::PrivacyPreserving(_) => ("Privacy-Preserving", "tx-type-private"),
        Transaction::ProgramDeployment(_) => ("Program Deployment", "tx-type-deployment"),
    }
}

/// Transaction preview component
#[component]
#[expect(
    clippy::needless_pass_by_value,
    reason = "Leptos component props are passed by value by framework convention"
)]
pub fn TransactionPreview(transaction: Transaction) -> impl IntoView {
    let hash = transaction.hash();
    let hash_str = hash.to_string();
    let (type_name, type_class) = transaction_type_info(&transaction);

    // Get additional metadata based on transaction type
    let metadata = match &transaction {
        Transaction::Public(tx) => {
            let indexer_service_protocol::PublicTransaction {
                hash: _,
                message,
                witness_set: _,
            } = tx;
            format!("{} accounts involved", message.account_ids.len())
        }
        Transaction::PrivacyPreserving(tx) => {
            let indexer_service_protocol::PrivacyPreservingTransaction {
                hash: _,
                message,
                witness_set: _,
            } = tx;
            format!(
                "{} public accounts, {} commitments",
                message.public_account_ids.len(),
                message.new_commitments.len()
            )
        }
        Transaction::ProgramDeployment(tx) => {
            let indexer_service_protocol::ProgramDeploymentTransaction { hash: _, message } = tx;
            format!("{} bytes", message.bytecode.len())
        }
    };

    view! {
        <div class="transaction-preview">
            <A href=format!("/transaction/{}", hash_str) attr:class="transaction-preview-link">
                <div class="transaction-preview-header">
                    <div class="tx-id">
                        <span class="label">"Transaction"</span>
                    </div>
                    <div class=format!("tx-type {}", type_class)>
                        {type_name}
                    </div>
                </div>
                <div class="transaction-preview-body">
                    <div class="tx-hash">
                        <span class="field-label">"Hash: "</span>
                        <span class="field-value hash">{hash_str}</span>
                    </div>
                    <div class="tx-metadata">
                        {metadata}
                    </div>
                </div>
            </A>
        </div>
    }
}
