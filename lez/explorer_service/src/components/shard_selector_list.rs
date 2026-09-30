use indexer_service_protocol::ProgramShardSelector;
use leptos::prelude::*;
use leptos_router::components::A;

#[component]
pub fn ShardSelectorList(shard_selectors: Vec<ProgramShardSelector>) -> impl IntoView {
    view! {
        <div class="accounts-list">
            {shard_selectors
                .into_iter()
                .map(|shard_selector| {
                    let account_id_str = shard_selector.account_id.to_string();
                    let program_str = shard_selector.program_account_id.to_string();
                    view! {
                        <div class="account-item">
                            <A href=format!("/account/{}", account_id_str)>
                                <span class="hash">{account_id_str}</span>
                            </A>
                            <span class="program">
                                " (program: " <span class="hash">{program_str}</span> ")"
                            </span>
                        </div>
                    }
                })
                .collect::<Vec<_>>()}
        </div>
    }
}
