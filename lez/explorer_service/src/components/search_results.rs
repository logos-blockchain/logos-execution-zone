use leptos::prelude::*;

use super::{AccountPreview, BlockPreview, TransactionPreview};
use crate::api::SearchResults;

/// Search results view component
#[component]
pub fn SearchResultsView(results: SearchResults) -> impl IntoView {
    let SearchResults {
        blocks,
        transactions,
        accounts,
    } = results;
    let has_results = !blocks.is_empty() || !transactions.is_empty() || !accounts.is_empty();

    view! {
        <div class="search-results">
            <h2>"Search Results"</h2>
            {if has_results {
                view! {
                    <div class="results-container">
                        {if blocks.is_empty() {
                            ().into_any()
                        } else {
                            view! {
                                <div class="results-section">
                                    <h3>"Blocks"</h3>
                                    <div class="results-list">
                                        {blocks
                                            .into_iter()
                                            .map(|block| {
                                                view! { <BlockPreview block=block /> }
                                            })
                                            .collect::<Vec<_>>()}
                                    </div>
                                </div>
                            }
                                .into_any()
                        }}

                        {if transactions.is_empty() {
                            ().into_any()
                        } else {
                            view! {
                                <div class="results-section">
                                    <h3>"Transactions"</h3>
                                    <div class="results-list">
                                        {transactions
                                            .into_iter()
                                            .map(|tx| {
                                                view! { <TransactionPreview transaction=tx /> }
                                            })
                                            .collect::<Vec<_>>()}
                                    </div>
                                </div>
                            }
                                .into_any()
                        }}

                        {if accounts.is_empty() {
                            ().into_any()
                        } else {
                            view! {
                                <div class="results-section">
                                    <h3>"Accounts"</h3>
                                    <div class="results-list">
                                        {accounts
                                            .into_iter()
                                            .map(|(id, account)| {
                                                view! {
                                                    <AccountPreview
                                                        account_id=id
                                                        account=account
                                                    />
                                                }
                                            })
                                            .collect::<Vec<_>>()}
                                    </div>
                                </div>
                            }
                                .into_any()
                        }}

                    </div>
                }
                    .into_any()
            } else {
                    view! { <div class="not-found">"No results found"</div> }
                    .into_any()
            }}
        </div>
    }
}
