use cross_zone_marker_core::{Delivery, inbox_source_marker_account_id};
use lee_core::{
    account::{AccountId, Actor},
    program::{Call, Origin, ReceiveInput, Response, run_actor_with, write_once},
};
use ping_core::{ReceiverConfig, ReceiverMessage, ping_record_pda, receiver_config_account_id};

fn main() {
    run_actor_with(receive)
}

fn receive(input: &ReceiveInput) -> Response {
    let program = input.receiver.program_account_id;
    if input.receiver.account_id == program && input.origin_program().is_some() {
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
            Response::keep().send(Call::new(
                Actor::new(ping_record_pda(program), program),
                &ReceiverMessage::WriteRecord(payload),
            ))
        }
        ReceiverMessage::WriteRecord(payload) => {
            assert!(
                input.from_own_program(),
                "the record is only written by this receiver's config"
            );
            Response::write(payload)
        }
        ReceiverMessage::RenounceAuthority { authority, via } => {
            if !at_config(input) {
                return forward_as_authority(
                    input,
                    &ReceiverMessage::RenounceAuthority {
                        authority: input.receiver.account_id,
                        via: input.origin_program(),
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
            Response::write(cfg.to_bytes())
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
                        via: input.origin_program(),
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
            Response::write(cfg.to_bytes())
        }
        ReceiverMessage::InitConfig(config) => {
            assert!(
                matches!(input.origin, Origin::Root),
                "InitConfig is a top-level genesis transaction"
            );
            assert!(
                at_config(input),
                "the config account must be the receiver config PDA"
            );
            // Genesis is replayed onto seeded state during multi-sequencer reconstruction, so
            // a written config must already hold exactly this.
            Response::write(write_once(&input.pre_state, config.to_bytes()))
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
    Response::keep().send(Call::new(
        Actor::new(receiver_config_account_id(program), program),
        &ReceiverMessage::RecordFrom {
            deliverer: input.origin_program().expect("a delivery has a sender"),
            src_zone,
            src_account_id,
            payload,
        },
    ))
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
    Response::keep().send(Call::new(
        Actor::new(receiver_config_account_id(program), program),
        message,
    ))
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
    // authorized it, filling `authority` from that receiver and `via` from its origin; so both
    // are the runtime's word rather than a sender's claim.
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
    use borsh::BorshSerialize;
    use lee_core::{
        account::ActorState,
        program::{Action, Transition},
    };
    use ping_core::ZoneId;

    use super::*;

    const RECEIVER: AccountId = AccountId::new([4; 32]);
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

    fn actor(account_id: AccountId) -> Actor {
        Actor::new(account_id, RECEIVER)
    }

    fn config_actor() -> Actor {
        actor(receiver_config_account_id(RECEIVER))
    }

    fn run(
        receiver: Actor,
        origin: Origin,
        is_authorized: bool,
        pre: Vec<u8>,
        message: &impl BorshSerialize,
    ) -> Transition {
        let input = ReceiveInput {
            receiver,
            origin,
            is_authorized,
            pre_state: ActorState::try_from(pre).unwrap(),
            message: borsh::to_vec(message).unwrap(),
        };
        receive(&input).into_transition(input)
    }

    fn at_config(origin: Origin, pre: &ReceiverConfig, message: &ReceiverMessage) -> Transition {
        run(config_actor(), origin, false, pre.to_bytes(), message)
    }

    fn record_from(deliverer: AccountId, src_account_id: AccountId) -> ReceiverMessage {
        ReceiverMessage::RecordFrom {
            deliverer,
            src_zone: ZONE,
            src_account_id,
            payload: b"ping".to_vec(),
        }
    }

    fn to_config(message: &ReceiverMessage) -> Call {
        Call::new(config_actor(), message)
    }

    // The authority's actor receives `message` from `origin`; the config then receives what it
    // forwards, as the driver would deliver it.
    fn through_authority(
        origin: Origin,
        is_authorized: bool,
        message: &ReceiverMessage,
    ) -> Transition {
        let entry = run(actor(AUTHORITY), origin, is_authorized, Vec::new(), message);
        let [forwarded] =
            <[Action; 1]>::try_from(entry.response.sends).expect("one forwarded change");
        let Action::Call(Call {
            to, message: data, ..
        }) = forwarded
        else {
            panic!("the forwarded change is an inline call");
        };
        assert_eq!(to, config_actor());
        at_config(
            Origin::Program(RECEIVER),
            &config(),
            &borsh::from_slice(&data).expect("the forwarded change decodes"),
        )
    }

    fn update(authority: AccountId, via: Option<AccountId>) -> ReceiverMessage {
        ReceiverMessage::UpdateSources {
            authority,
            via,
            sources: vec![],
        }
    }

    fn renounce(via: Option<AccountId>) -> ReceiverMessage {
        ReceiverMessage::RenounceAuthority {
            authority: AUTHORITY,
            via,
        }
    }

    fn written_config(transition: &Transition) -> ReceiverConfig {
        ReceiverConfig::from_bytes(
            transition
                .response
                .post_state
                .as_ref()
                .expect("the config is written"),
        )
        .expect("the config decodes")
    }

    #[test]
    fn a_delivery_is_forwarded_with_its_deliverer() {
        let delivery = Delivery {
            src_zone: ZONE,
            src_account_id: SOURCE,
            payload: borsh::to_vec(&ReceiverMessage::Record {
                payload: b"ping".to_vec(),
            })
            .unwrap(),
        };
        let transition = run(
            actor(RECEIVER),
            Origin::Program(INBOX),
            false,
            Vec::new(),
            &delivery,
        );

        assert_eq!(transition.response.post_state, None);
        assert_eq!(
            transition.response.sends,
            vec![to_config(&record_from(INBOX, SOURCE)).into()]
        );
    }

    #[test]
    #[should_panic(expected = "only callable by the authorized deliverer")]
    fn a_record_sent_directly_is_refused() {
        let _transition = run(
            actor(RECEIVER),
            Origin::Root,
            false,
            Vec::new(),
            &ReceiverMessage::Record {
                payload: b"ping".to_vec(),
            },
        );
    }

    #[test]
    fn an_authorized_source_delivered_by_the_inbox_is_accepted() {
        let transition = at_config(
            Origin::Program(RECEIVER),
            &config(),
            &record_from(INBOX, SOURCE),
        );

        assert_eq!(transition.response.post_state, None);
        assert_eq!(
            transition.response.sends,
            vec![
                Call::new(
                    actor(ping_record_pda(RECEIVER)),
                    &ReceiverMessage::WriteRecord(b"ping".to_vec()),
                )
                .into()
            ]
        );
    }

    #[test]
    #[should_panic(expected = "only callable by the authorized deliverer")]
    fn a_record_claimed_from_outside_the_receiver_is_refused() {
        let _transition = at_config(Origin::Root, &config(), &record_from(INBOX, SOURCE));
    }

    #[test]
    #[should_panic(expected = "only callable by the authorized deliverer")]
    fn a_caller_that_is_not_the_deliverer_is_refused() {
        let _transition = at_config(
            Origin::Program(RECEIVER),
            &config(),
            &record_from(AccountId::new([2; 32]), SOURCE),
        );
    }

    #[test]
    #[should_panic(expected = "only callable for a peer source this receiver authorizes")]
    fn a_marker_for_an_unauthorized_source_is_refused() {
        let _transition = at_config(
            Origin::Program(RECEIVER),
            &config(),
            &record_from(INBOX, AccountId::new([4; 32])),
        );
    }

    #[test]
    #[should_panic(expected = "the record is only written by this receiver's config")]
    fn a_record_write_from_another_program_is_refused() {
        let _transition = run(
            actor(ping_record_pda(RECEIVER)),
            Origin::Program(AccountId::new([3; 32])),
            false,
            Vec::new(),
            &ReceiverMessage::WriteRecord(b"ping".to_vec()),
        );
    }

    #[test]
    fn the_authority_forwards_a_change_naming_itself() {
        let transition = run(
            actor(AUTHORITY),
            Origin::Root,
            true,
            Vec::new(),
            &update(AccountId::new([3; 32]), Some(GOVERNANCE)),
        );

        assert_eq!(
            transition.response.sends,
            vec![to_config(&update(AUTHORITY, None)).into()]
        );
    }

    // A signed authority does not make any program its governance.
    #[test]
    #[should_panic(expected = "the authority acts at top level")]
    fn a_change_entered_from_another_program_is_refused() {
        let _transition = through_authority(
            Origin::Program(AccountId::new([3; 32])),
            true,
            &renounce(None),
        );
    }

    #[test]
    fn the_configured_authority_may_replace_the_sources() {
        let transition = at_config(
            Origin::Program(RECEIVER),
            &config(),
            &update(AUTHORITY, None),
        );
        assert_eq!(written_config(&transition).sources, vec![]);
    }

    #[test]
    #[should_panic(expected = "must be the configured authority")]
    fn another_account_cannot_replace_the_sources() {
        let other = AccountId::new([3; 32]);
        let _transition = at_config(Origin::Program(RECEIVER), &config(), &update(other, None));
    }

    #[test]
    #[should_panic(expected = "through the configured governance program")]
    fn another_program_cannot_act_for_the_authority() {
        let _transition = at_config(
            Origin::Program(RECEIVER),
            &config(),
            &update(AUTHORITY, Some(AccountId::new([8; 32]))),
        );
    }

    #[test]
    #[should_panic(expected = "a change is only forwarded by the authority's own actor")]
    fn the_governance_program_cannot_reach_the_config_past_the_authority() {
        let _transition = at_config(
            Origin::Program(GOVERNANCE),
            &config(),
            &update(AUTHORITY, Some(GOVERNANCE)),
        );
    }

    // The driver authorizes the authority's actor for the governance program only when it
    // sends with the seed that derives the authority.
    #[test]
    fn governance_granting_the_authoritys_seed_acts_through_its_actor() {
        let transition = through_authority(
            Origin::Program(GOVERNANCE),
            true,
            &update(AUTHORITY, Some(GOVERNANCE)),
        );
        assert_eq!(written_config(&transition).sources, vec![]);
    }

    #[test]
    #[should_panic(expected = "the configured authority must authorize a change")]
    fn governance_without_the_authoritys_seed_is_refused() {
        let _transition = through_authority(
            Origin::Program(GOVERNANCE),
            false,
            &update(AUTHORITY, Some(GOVERNANCE)),
        );
    }

    #[test]
    fn renouncing_clears_the_authority() {
        let transition = at_config(
            Origin::Program(RECEIVER),
            &config(),
            &renounce(Some(GOVERNANCE)),
        );
        let cfg = written_config(&transition);
        assert_eq!(cfg.authority, None);
        assert_eq!(cfg.sources, config().sources);
    }

    #[test]
    #[should_panic(expected = "receiver authority is already renounced")]
    fn a_renounced_authority_cannot_be_renounced_again() {
        let mut cfg = config();
        cfg.authority = None;
        let _transition = at_config(Origin::Program(RECEIVER), &cfg, &renounce(None));
    }

    #[test]
    fn an_identical_reinit_is_a_no_op_rewrite() {
        let transition = at_config(
            Origin::Root,
            &config(),
            &ReceiverMessage::InitConfig(config()),
        );
        assert_eq!(written_config(&transition), config());
    }

    #[test]
    #[should_panic(expected = "InitConfig is a top-level genesis transaction")]
    fn an_init_from_another_program_is_refused() {
        let _transition = at_config(
            Origin::Program(INBOX),
            &config(),
            &ReceiverMessage::InitConfig(config()),
        );
    }

    #[test]
    #[should_panic(expected = "shard already holds different data")]
    fn a_reinit_with_different_contents_is_refused() {
        let mut other = config();
        other.sources = vec![];
        let _transition = at_config(Origin::Root, &config(), &ReceiverMessage::InitConfig(other));
    }
}
