use indexer_service_protocol::Actor;
use leptos::prelude::*;
use leptos_router::components::A;

#[component]
pub fn ActorList(actors: Vec<Actor>) -> impl IntoView {
    view! {
        <div class="accounts-list">
            {actors
                .into_iter()
                .map(|actor| {
                    let account_id_str = actor.account_id.to_string();
                    let program_str = actor.program_account_id.to_string();
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
