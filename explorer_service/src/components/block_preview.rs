use indexer_service_protocol::{BedrockStatus, Block, BlockBody, BlockHeader};
use leptos::prelude::*;
use leptos_router::components::A;

use crate::format_utils;

/// Get CSS class for bedrock status.
const fn status_class(status: &BedrockStatus) -> &'static str {
    match status {
        BedrockStatus::Pending => "status-pending",
        BedrockStatus::Safe => "status-safe",
        BedrockStatus::Finalized => "status-finalized",
    }
}

/// Block preview component
#[component]
pub fn BlockPreview(block: Block) -> impl IntoView {
    let Block {
        header:
            BlockHeader {
                block_id,
                prev_block_hash,
                hash,
                timestamp,
                signature: _,
            },
        body: BlockBody { transactions },
        bedrock_status,
        bedrock_parent_id: _,
    } = block;

    let tx_count = transactions.len();

    let hash_str = hash.to_string();
    let prev_hash_str = prev_block_hash.to_string();
    let time_str = format_utils::format_timestamp(timestamp);
    let status_str = match &bedrock_status {
        BedrockStatus::Pending => "Pending",
        BedrockStatus::Safe => "Safe",
        BedrockStatus::Finalized => "Finalized",
    };

    view! {
        <div class="block-preview">
            <A href=format!("/block/{}", block_id) attr:class="block-preview-link">
                <div class="block-preview-header">
                    <div class="block-id">
                        <span class="label">"Block "</span>
                        <span class="value">{block_id}</span>
                    </div>
                    <div class=format!("block-status {}", status_class(&bedrock_status))>
                        {status_str}
                    </div>
                </div>
                <div class="block-preview-body">
                    <div class="block-field">
                        <span class="field-label">"Hash: "</span>
                        <span class="field-value hash">{hash_str}</span>
                    </div>
                    <div class="block-field">
                        <span class="field-label">"Previous: "</span>
                        <span class="field-value hash">{prev_hash_str}</span>
                    </div>
                    <div class="block-field">
                        <span class="field-label">"Timestamp: "</span>
                        <span class="field-value">{time_str}</span>
                    </div>
                    <div class="block-field">
                        <span class="field-label">"Transactions: "</span>
                        <span class="field-value">{tx_count}</span>
                    </div>
                </div>
            </A>
        </div>
    }
}
