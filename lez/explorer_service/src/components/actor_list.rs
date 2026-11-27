use indexer_service_protocol::{Actor, Authority, DeclaredActor};
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

#[component]
pub fn DeclaredActorList(actors: Vec<DeclaredActor>) -> impl IntoView {
    view! {
        <div class="accounts-list">
            {actors
                .into_iter()
                .map(|DeclaredActor { actor, authority }| {
                    let account_id_str = actor.account_id.to_string();
                    let program_str = actor.program_account_id.to_string();
                    let authority_str = match authority {
                        Authority::Signer => " (signer)",
                        Authority::None => "",
                    };
                    view! {
                        <div class="account-item">
                            <A href=format!("/account/{}", account_id_str)>
                                <span class="hash">{account_id_str}</span>
                            </A>
                            <span class="program">
                                " (program: " <span class="hash">{program_str}</span> ")"
                            </span>
                            <span class="authority">{authority_str}</span>
                        </div>
                    }
                })
                .collect::<Vec<_>>()}
        </div>
    }
}
