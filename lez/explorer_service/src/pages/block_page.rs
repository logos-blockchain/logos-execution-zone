use std::str::FromStr as _;

use indexer_service_protocol::{BedrockStatus, Block, BlockBody, BlockHeader, BlockId, HashType};
use leptos::prelude::*;
use leptos_router::{components::A, hooks::use_params_map};

use crate::{api, components::TransactionPreview, format_utils};

#[derive(Clone, PartialEq, Eq)]
enum BlockIdOrHash {
    BlockId(BlockId),
    Hash(HashType),
}

/// Block page component
#[component]
pub fn BlockPage() -> impl IntoView {
    let params = use_params_map();

    let block_resource = Resource::new(
        move || {
            let id_str = params.read().get("id").unwrap_or_default();

            // Try to parse as block ID (number)
            if let Ok(block_id) = id_str.parse::<BlockId>() {
                return Some(BlockIdOrHash::BlockId(block_id));
            }

            // Try to parse as block hash (hex string)
            if let Ok(hash) = HashType::from_str(&id_str) {
                return Some(BlockIdOrHash::Hash(hash));
            }

            None
        },
        |block_id_or_hash| async move {
            match block_id_or_hash {
                Some(BlockIdOrHash::BlockId(id)) => api::get_block_by_id(id).await,
                Some(BlockIdOrHash::Hash(hash)) => api::get_block_by_hash(hash).await,
                None => Err(leptos::prelude::ServerFnError::ServerError(
                    "Invalid block ID or hash".to_owned(),
                )),
            }
        },
    );

    view! {
        <div class="block-page">
            <Suspense fallback=move || view! { <div class="loading">"Loading block..."</div> }>
                {move || {
                    block_resource
                        .get()
                        .map(|result| match result {
                            Ok(blk) => {
                                let Block {
                                    header: BlockHeader {
                                        block_id,
                                        prev_block_hash,
                                        hash,
                                        timestamp,
                                        signature,
                                    },
                                    body: BlockBody {
                                        transactions,
                                    },
                                    bedrock_status,
                                    bedrock_parent_id: _,
                                } = blk;

                                let hash_str = hash.to_string();
                                let prev_hash = prev_block_hash.to_string();
                                let timestamp_str = format_utils::format_timestamp(timestamp);
                                let signature_str = signature.to_string();
                                let status = match &bedrock_status {
                                    BedrockStatus::Pending => "Pending",
                                    BedrockStatus::Safe => "Safe",
                                    BedrockStatus::Finalized => "Finalized",
                                };
                    view! {
                        <div class="block-detail">
                            <div class="page-header">
                                <h1>"Block " {block_id.to_string()}</h1>
                            </div>

                            <div class="block-info">
                                <h2>"Block Information"</h2>
                                <div class="info-grid">
                                    <div class="info-row">
                                        <span class="info-label">"Block ID: "</span>
                                        <span class="info-value">{block_id.to_string()}</span>
                                    </div>
                                    <div class="info-row">
                                        <span class="info-label">"Hash: "</span>
                                        <span class="info-value hash">{hash_str}</span>
                                    </div>
                                    <div class="info-row">
                                        <span class="info-label">"Previous Block Hash: "</span>
                                        <A href=format!("/block/{}", prev_hash) attr:class="info-value hash">
                                            {prev_hash}
                                        </A>
                                    </div>
                                    <div class="info-row">
                                        <span class="info-label">"Timestamp: "</span>
                                        <span class="info-value">{timestamp_str}</span>
                                    </div>
                                    <div class="info-row">
                                        <span class="info-label">"Status: "</span>
                                        <span class="info-value">{status}</span>
                                    </div>
                                    <div class="info-row">
                                        <span class="info-label">"Signature: "</span>
                                        <span class="info-value hash signature">{signature_str}</span>
                                    </div>
                                    <div class="info-row">
                                        <span class="info-label">"Transaction Count: "</span>
                                        <span class="info-value">{transactions.len().to_string()}</span>
                                    </div>
                                </div>
                            </div>

                            <div class="block-transactions">
                                <h2>"Transactions"</h2>
                                {if transactions.is_empty() {
                                    view! { <div class="no-transactions">"No transactions"</div> }
                                        .into_any()
                                } else {
                                    view! {
                                        <div class="transactions-list">
                                            {transactions
                                                .into_iter()
                                                .map(|tx| view! { <TransactionPreview transaction=tx /> })
                                                .collect::<Vec<_>>()}
                                        </div>
                                    }
                                        .into_any()
                                }}

                            </div>
                        </div>
                    }
                        .into_any()
                            }
                            Err(e) => {
                                view! {
                                    <div class="error-page">
                                        <h1>"Error"</h1>
                                        <p>{format!("Failed to load block: {e}")}</p>
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
