use cross_zone_marker_core::{Delivery, inbox_source_marker_account_id};
use lee_core::{
    account::{AccountId, Actor},
    program::{Call, ReceiveInput, Response, write_once},
};
use ping_core::{
    ReceiverConfig, ReceiverMessage, ping_record_pda, ping_record_seed, receiver_config_account_id,
};

lee_core::define_actor_logic!(raw handle_message);

fn handle_message(input: &ReceiveInput) -> Response {
    let program = input.receiver.program_account_id;
    if input.receiver.account_id == program && input.from.is_some() {
        let delivery: Delivery = borsh::from_slice(&input.message).expect("a delivery decodes");
        return deliver(input, delivery);
    }
    let message: ReceiverMessage =
        borsh::from_slice(&input.message).expect("message must decode from borsh");
    match message {
        ReceiverMessage::Record { .. } => {
            panic!("Record is only callable by the authorized deliverer (the cross-zone inbox)")
        }
        ReceiverMessage::RecordFrom {
            deliverer,
            src_zone,
            src_account_id,
            payload,
        } => {
            // Only this receiver's own program account forwards a delivery, naming its
            // real sender; anyone else could claim to be the deliverer.
            assert!(
                input.from_own_program(),
                "Record is only callable by the authorized deliverer (the cross-zone inbox)"
            );
            let cfg = decode_config(&input.pre_state);
            assert_eq!(
                deliverer, cfg.deliverer,
                "Record is only callable by the authorized deliverer (the cross-zone inbox)"
            );
            // Which peer sent it is this program's own business.
            let marker = inbox_source_marker_account_id(deliverer, &src_zone, src_account_id);
            assert!(
                cfg.sources.iter().any(|(zone, account_id)| {
                    marker == inbox_source_marker_account_id(cfg.deliverer, zone, *account_id)
                }),
                "Record is only callable for a peer source this receiver authorizes"
            );
            Response::keep_state().send(
                Call::new(
                    Actor::new(ping_record_pda(program), program),
                    &ReceiverMessage::WriteRecord(payload),
                )
                .with_pda_seeds(vec![ping_record_seed()]),
            )
        }
        ReceiverMessage::WriteRecord(payload) => {
            assert!(
                input.from_own_program(),
                "the record is only written by this receiver's config"
            );
            Response::set_state(payload)
        }
        ReceiverMessage::RenounceAuthority { authority, via } => {
            if !at_config(input) {
                return forward_as_authority(
                    input,
                    &ReceiverMessage::RenounceAuthority {
                        authority: input.receiver.account_id,
                        via: input.from.map(|from| from.program_account_id),
                    },
                );
            }
            let mut cfg = decode_config(&input.pre_state);
            assert_authority(
                input,
                &cfg,
                authority,
                via,
                "receiver authority is already renounced",
            );
            cfg.authority = None;
            Response::set_state(cfg.to_bytes())
        }
        ReceiverMessage::UpdateSources {
            authority,
            via,
            sources,
        } => {
            if !at_config(input) {
                return forward_as_authority(
                    input,
                    &ReceiverMessage::UpdateSources {
                        authority: input.receiver.account_id,
                        via: input.from.map(|from| from.program_account_id),
                        sources,
                    },
                );
            }
            let mut cfg = decode_config(&input.pre_state);
            assert_authority(
                input,
                &cfg,
                authority,
                via,
                "receiver sources are fixed at genesis: no authority is configured",
            );
            cfg.sources = sources;
            Response::set_state(cfg.to_bytes())
        }
        ReceiverMessage::InitConfig(config) => {
            assert!(
                input.from.is_none(),
                "InitConfig is a top-level genesis transaction"
            );
            assert!(
                at_config(input),
                "the config account must be the receiver config PDA"
            );
            // Genesis is replayed onto seeded state during multi-sequencer reconstruction, so
            // a written config must already hold exactly this.
            Response::set_state(write_once(&input.pre_state, config.to_bytes()))
        }
    }
}

/// The receiver's program account forwards a delivery to its config, naming the program that
/// sent it.
fn deliver(input: &ReceiveInput, delivery: Delivery) -> Response {
    let Delivery {
        src_zone,
        src_account_id,
        payload,
    } = delivery;
    let ReceiverMessage::Record { payload } =
        borsh::from_slice(&payload).expect("delivery payload must decode from borsh")
    else {
        panic!("a delivery to ping_receiver must carry a Record");
    };
    let program = input.receiver.program_account_id;
    Response::keep_state().call(
        Actor::new(receiver_config_account_id(program), program),
        &ReceiverMessage::RecordFrom {
            deliverer: input
                .from
                .expect("a delivery has a sender")
                .program_account_id,
            src_zone,
            src_account_id,
            payload,
        },
    )
}

/// The authority's own actor vouches that the authority authorized the change and names the
/// program that reached it; which account the authority has to be, and whether that program may
/// act, are the config's own answer and are checked there.
fn forward_as_authority(input: &ReceiveInput, message: &ReceiverMessage) -> Response {
    assert!(
        input.is_authorized,
        "the configured authority must authorize a change"
    );
    let program = input.receiver.program_account_id;
    Response::keep_state().call(
        Actor::new(receiver_config_account_id(program), program),
        message,
    )
}

fn at_config(input: &ReceiveInput) -> bool {
    input.receiver.account_id == receiver_config_account_id(input.receiver.program_account_id)
}

fn decode_config(pre_state: &[u8]) -> ReceiverConfig {
    ReceiverConfig::from_bytes(pre_state).expect("config account holds a receiver config")
}

fn assert_authority(
    input: &ReceiveInput,
    cfg: &ReceiverConfig,
    authority: AccountId,
    via: Option<AccountId>,
    unset: &str,
) {
    // This program sends a change only from the authority's own actor, after the authority
    // authorized it, filling `authority` from that receiver and `via` from its sender's program; so
    // both are the runtime's word rather than a sender's claim.
    assert!(
        input.from_own_program(),
        "a change is only forwarded by the authority's own actor"
    );
    // See `ReceiverConfig::governance` for why the governance escape hatch exists.
    assert!(
        via.is_none() || via == cfg.governance,
        "the authority acts at top level, or through the configured governance program"
    );
    let Some(expected) = cfg.authority else {
        panic!("{unset}");
    };
    assert_eq!(
        authority, expected,
        "the signing account must be the configured authority"
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    const INBOX: AccountId = AccountId::new([1; 32]);
    const SOURCE: AccountId = AccountId::new([9; 32]);
    const AUTHORITY: AccountId = AccountId::new([5; 32]);
    const GOVERNANCE: AccountId = AccountId::new([6; 32]);
    const ZONE: ZoneId = [7; 32];

    fn config() -> ReceiverConfig {
        ReceiverConfig {
            deliverer: INBOX,
            governance: Some(GOVERNANCE),
            authority: Some(AUTHORITY),
            sources: vec![(ZONE, SOURCE)],
        }
    }

    fn marker() -> AccountId {
        inbox_source_marker_account_id(INBOX, &ZONE, SOURCE)
    }

    #[test]
    fn an_authorized_source_delivered_by_the_inbox_is_accepted() {
        assert_eq!(
            apply(
                Effect::AcceptDelivery {
                    caller: INBOX,
                    marker: marker()
                },
                &config().to_bytes()
            ),
            None
        );
    }

    #[test]
    #[should_panic(expected = "only callable by the authorized deliverer")]
    fn a_caller_that_is_not_the_deliverer_is_refused() {
        apply(
            Effect::AcceptDelivery {
                caller: AccountId::new([2; 32]),
                marker: marker(),
            },
            &config().to_bytes(),
        );
    }

    #[test]
    #[should_panic(expected = "only callable for a peer source this receiver authorizes")]
    fn a_marker_for_an_unauthorized_source_is_refused() {
        apply(
            Effect::AcceptDelivery {
                caller: INBOX,
                marker: inbox_source_marker_account_id(INBOX, &ZONE, AccountId::new([4; 32])),
            },
            &config().to_bytes(),
        );
    }

    #[test]
    fn the_configured_authority_may_replace_the_sources() {
        let updated = apply(
            Effect::UpdateSources {
                caller: None,
                authority: AUTHORITY,
                sources: vec![],
            },
            &config().to_bytes(),
        )
        .expect("the config is written");
        assert_eq!(
            ReceiverConfig::from_bytes(&updated)
                .expect("the config decodes")
                .sources,
            vec![]
        );
    }

    #[test]
    #[should_panic(expected = "second account must be the configured authority")]
    fn another_account_cannot_replace_the_sources() {
        apply(
            Effect::UpdateSources {
                caller: None,
                authority: AccountId::new([3; 32]),
                sources: vec![],
            },
            &config().to_bytes(),
        );
    }

    #[test]
    #[should_panic(expected = "through the configured governance program")]
    fn another_program_cannot_act_for_the_authority() {
        apply(
            Effect::UpdateSources {
                caller: Some(AccountId::new([8; 32])),
                authority: AUTHORITY,
                sources: vec![],
            },
            &config().to_bytes(),
        );
    }

    #[test]
    fn renouncing_clears_the_authority() {
        let updated = apply(
            Effect::RenounceAuthority {
                caller: Some(GOVERNANCE),
                authority: AUTHORITY,
            },
            &config().to_bytes(),
        )
        .expect("the config is written");
        let cfg = ReceiverConfig::from_bytes(&updated).expect("the config decodes");
        assert_eq!(cfg.authority, None);
        assert_eq!(cfg.sources, config().sources);
    }

    #[test]
    #[should_panic(expected = "receiver authority is already renounced")]
    fn a_renounced_authority_cannot_be_renounced_again() {
        let mut cfg = config();
        cfg.authority = None;
        apply(
            Effect::RenounceAuthority {
                caller: None,
                authority: AUTHORITY,
            },
            &cfg.to_bytes(),
        );
    }

    #[test]
    fn an_identical_reinit_is_a_no_op_rewrite() {
        assert_eq!(
            apply(Effect::InitConfig(config()), &config().to_bytes()),
            Some(config().to_bytes())
        );
    }

    #[test]
    #[should_panic(expected = "shard already holds different data")]
    fn a_reinit_with_different_contents_is_refused() {
        let mut other = config();
        other.sources = vec![];
        apply(Effect::InitConfig(other), &config().to_bytes());
    }
}
