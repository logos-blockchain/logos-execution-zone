use cross_zone_marker_core::{Delivery, inbox_source_marker_account_id};
use lee_core::{
    account::{AccountId, Actor},
    program::{Envelope, Origin, ReceiveInput, Response, run_actor_with, write_once},
};
use wrapped_token_core::{
    MAX_MINT_AMOUNT, Message, SourceEntry, WrappedTokenConfig, ZoneId, balance_bytes,
    config_account_id, holding_account_id, read_balance,
};

fn main() {
    run_actor_with(receive)
}

fn receive(input: &ReceiveInput) -> Response {
    let program = input.receiver.program_account_id;
    if input.receiver.account_id == program && input.origin_program().is_some() {
        let delivery: Delivery = borsh::from_slice(&input.message).expect("a delivery decodes");
        return deliver(input, delivery);
    }
    let message: Message =
        borsh::from_slice(&input.message).expect("message must decode from borsh");
    match message {
        Message::Mint { .. } => {
            panic!("Mint is only callable by the authorized minter (the cross-zone inbox)")
        }
        Message::MintFrom {
            deliverer,
            src_zone,
            src_account_id,
            recipient,
            amount,
        } => {
            // Both inputs to the authorization come from the delivery itself: the deliverer is
            // the runtime's authenticated origin, forwarded only by this token's own program
            // account, and the source is what the inbox bound to the message.
            assert!(
                input.from_own_program(),
                "Mint is only callable by the authorized minter (the cross-zone inbox)"
            );
            assert!(
                amount <= MAX_MINT_AMOUNT,
                "mint amount exceeds the per-mint cap"
            );
            let mut cfg = decode_config(&input.pre_data);
            mint_source(&mut cfg, deliverer, &src_zone, src_account_id, amount);
            Response::write(cfg.to_bytes()).send(Envelope::new(
                Actor::new(holding_account_id(program, &recipient), program),
                &Message::Credit(amount),
            ))
        }
        // The backstop against accumulation, which the per-mint cap does not bound.
        Message::Credit(amount) => {
            assert!(
                input.from_own_program(),
                "a credit is only sent by this token's config"
            );
            Response::write(
                balance_bytes(
                    read_balance(&input.pre_data)
                        .checked_add(amount)
                        .expect("wrapped-token balance overflow"),
                )
                .to_vec(),
            )
        }
        Message::InitConfig(config) => {
            assert!(
                matches!(input.origin, Origin::Root),
                "InitConfig is a top-level genesis transaction"
            );
            assert!(
                at_config(input),
                "the receiver must be the wrapped-token config PDA"
            );
            // A written shard must already hold exactly this configuration rather than being
            // refused.
            Response::write(write_once(&input.pre_data, config.to_bytes()))
        }
        Message::RenounceAuthority { authority, via } => {
            if !at_config(input) {
                return forward_as_authority(
                    input,
                    &Message::RenounceAuthority {
                        authority: input.receiver.account_id,
                        via: input.origin_program(),
                    },
                    "the configured authority must authorize renouncing it",
                );
            }
            let mut cfg = decode_config(&input.pre_data);
            assert_authority(
                input,
                &cfg,
                authority,
                via,
                "wrapped-token authority is already renounced",
            );
            cfg.authority = None;
            Response::write(cfg.to_bytes())
        }
        Message::UpdateSources {
            authority,
            via,
            sources,
        } => {
            if !at_config(input) {
                return forward_as_authority(
                    input,
                    &Message::UpdateSources {
                        authority: input.receiver.account_id,
                        via: input.origin_program(),
                        sources,
                    },
                    "the configured authority must authorize a source change",
                );
            }
            let mut cfg = decode_config(&input.pre_data);
            assert_authority(
                input,
                &cfg,
                authority,
                via,
                "wrapped-token sources are fixed at genesis: no authority is configured",
            );
            // Mint advances the first matching entry, so a duplicated pair would split
            // one source's policy across entries an auditor reads as two.
            for (index, policy) in sources.iter().enumerate() {
                assert!(
                    !sources[..index].iter().any(|other| {
                        other.src_zone == policy.src_zone
                            && other.src_account_id == policy.src_account_id
                    }),
                    "UpdateSources lists the same source twice"
                );
            }

            // The counter is the guest's, never the caller's: a kept source carries its
            // spent allowance over, so an update cannot reset it, and a source removed
            // and later re-added starts at zero.
            let previous = core::mem::take(&mut cfg.sources);
            cfg.sources = sources
                .into_iter()
                .map(|policy| SourceEntry {
                    minted: previous
                        .iter()
                        .find(|entry| {
                            entry.policy.src_zone == policy.src_zone
                                && entry.policy.src_account_id == policy.src_account_id
                        })
                        .map_or(0, |entry| entry.minted),
                    policy,
                })
                .collect();
            Response::write(cfg.to_bytes())
        }
    }
}

/// The token's program account forwards a delivery to its config, naming the program that
/// sent it.
fn deliver(input: &ReceiveInput, delivery: Delivery) -> Response {
    let Delivery {
        src_zone,
        src_account_id,
        payload,
    } = delivery;
    let Message::Mint { recipient, amount } =
        borsh::from_slice(&payload).expect("delivery payload must decode from borsh")
    else {
        panic!("a delivery to wrapped_token must carry a Mint");
    };
    let program = input.receiver.program_account_id;
    Response::keep().send(Envelope::new(
        Actor::new(config_account_id(program), program),
        &Message::MintFrom {
            deliverer: input.origin_program().expect("a delivery has a sender"),
            src_zone,
            src_account_id,
            recipient,
            amount,
        },
    ))
}

/// The authority's own actor vouches that the authority authorized the change and names the
/// program that reached it; whether that program may act, and who the authority is, stay the
/// config's own answer.
fn forward_as_authority(input: &ReceiveInput, message: &Message, unsigned: &str) -> Response {
    assert!(input.is_authorized, "{unsigned}");
    let program = input.receiver.program_account_id;
    Response::keep().send(Envelope::new(
        Actor::new(config_account_id(program), program),
        message,
    ))
}

fn at_config(input: &ReceiveInput) -> bool {
    input.receiver.account_id == config_account_id(input.receiver.program_account_id)
}

fn decode_config(pre_data: &[u8]) -> WrappedTokenConfig {
    WrappedTokenConfig::from_bytes(pre_data).expect("config account holds a wrapped-token config")
}

fn assert_authority(
    input: &ReceiveInput,
    cfg: &WrappedTokenConfig,
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
    // See `WrappedTokenConfig::governance` for why the governance escape hatch exists.
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

fn mint_source(
    cfg: &mut WrappedTokenConfig,
    deliverer: AccountId,
    src_zone: &ZoneId,
    src_account_id: AccountId,
    amount: u128,
) {
    // The config PDA is genesis-seeded with the authorized minter (the cross-zone
    // inbox). Pin the deliverer to it, since the guest cannot import the inbox id.
    assert_eq!(
        deliverer, cfg.minter,
        "Mint is only callable by the authorized minter (the cross-zone inbox)"
    );
    // The inbox vouches only that the message arrived; which peer sent it is this
    // token's own business, and unbacked value is what gets minted if it takes
    // anyone's word for it. The marker's address is the source, so re-deriving it
    // from an authorized pair is the whole check.
    let marker = inbox_source_marker_account_id(deliverer, src_zone, src_account_id);
    let minter = cfg.minter;
    let source = cfg
        .sources
        .iter_mut()
        .find(|entry| {
            marker
                == inbox_source_marker_account_id(
                    minter,
                    &entry.policy.src_zone,
                    entry.policy.src_account_id,
                )
        })
        .expect("Mint is only callable for a peer source this token authorizes");
    // A breach fails the whole delivery, so the message stays undelivered and can be
    // redelivered after a cap raise.
    let minted = source
        .minted
        .checked_add(amount)
        .expect("source mint total overflow");
    if let Some(cap) = source.policy.mint_cap {
        assert!(minted <= cap, "mint exceeds this source's lifetime cap");
    }
    source.minted = minted;
}

#[cfg(test)]
mod tests {
    use borsh::BorshSerialize;
    use lee_core::{account::ShardData, program::Transition};
    use wrapped_token_core::SourcePolicy;

    use super::*;

    const WRAPPED_ID: AccountId = AccountId::new([9; 32]);
    const MINTER: AccountId = AccountId::new([1; 32]);
    const GOVERNANCE: AccountId = AccountId::new([2; 32]);
    const AUTHORITY: AccountId = AccountId::new([5; 32]);
    const STRANGER: AccountId = AccountId::new([0xAA; 32]);
    const ZONE_A: [u8; 32] = [7; 32];
    const ZONE_B: [u8; 32] = [8; 32];
    const PEER_A: AccountId = AccountId::new([3; 32]);
    const PEER_B: AccountId = AccountId::new([4; 32]);
    const RECIPIENT: [u8; 32] = [6; 32];

    fn policy(
        src_zone: [u8; 32],
        src_account_id: AccountId,
        mint_cap: Option<u128>,
    ) -> SourcePolicy {
        SourcePolicy {
            src_zone,
            src_account_id,
            mint_cap,
        }
    }

    fn entry(
        src_zone: [u8; 32],
        src_account_id: AccountId,
        mint_cap: Option<u128>,
        minted: u128,
    ) -> SourceEntry {
        SourceEntry {
            policy: policy(src_zone, src_account_id, mint_cap),
            minted,
        }
    }

    fn config_with(authority: Option<AccountId>, sources: Vec<SourceEntry>) -> WrappedTokenConfig {
        WrappedTokenConfig {
            minter: MINTER,
            governance: Some(GOVERNANCE),
            authority,
            sources,
        }
    }

    fn config() -> WrappedTokenConfig {
        config_with(
            Some(AUTHORITY),
            vec![
                entry(ZONE_A, PEER_A, Some(1_000), 100),
                entry(ZONE_B, PEER_B, None, 0),
            ],
        )
    }

    fn actor(account_id: AccountId) -> Actor {
        Actor::new(account_id, WRAPPED_ID)
    }

    fn config_actor() -> Actor {
        actor(config_account_id(WRAPPED_ID))
    }

    fn holding_actor() -> Actor {
        actor(holding_account_id(WRAPPED_ID, &RECIPIENT))
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
            pre_data: ShardData::try_from(pre).unwrap(),
            message: borsh::to_vec(message).unwrap(),
        };
        receive(&input).into_transition(input)
    }

    fn at_config(origin: Origin, pre: &WrappedTokenConfig, message: &Message) -> Transition {
        run(config_actor(), origin, false, pre.to_bytes(), message)
    }

    fn mint_from(
        deliverer: AccountId,
        src_zone: [u8; 32],
        src_account_id: AccountId,
        amount: u128,
    ) -> Message {
        Message::MintFrom {
            deliverer,
            src_zone,
            src_account_id,
            recipient: RECIPIENT,
            amount,
        }
    }

    fn mint_at_config(message: &Message) -> Transition {
        at_config(Origin::Program(WRAPPED_ID), &config(), message)
    }

    fn written_config(transition: &Transition) -> WrappedTokenConfig {
        WrappedTokenConfig::from_bytes(
            transition
                .post_data
                .as_ref()
                .expect("a wrapped-token config is written"),
        )
        .expect("a config was written")
    }

    fn credit_at_holding(origin: Origin, pre: u128, amount: u128) -> Transition {
        run(
            holding_actor(),
            origin,
            false,
            balance_bytes(pre).to_vec(),
            &Message::Credit(amount),
        )
    }

    fn to_config(message: &Message) -> Envelope {
        Envelope::new(config_actor(), message)
    }

    fn update(authority: AccountId, via: Option<AccountId>) -> Message {
        Message::UpdateSources {
            authority,
            via,
            sources: vec![],
        }
    }

    #[test]
    fn a_mint_pins_the_authenticated_caller_and_the_delivered_marker() {
        let delivery = Delivery {
            src_zone: ZONE_A,
            src_account_id: PEER_A,
            payload: borsh::to_vec(&Message::Mint {
                recipient: RECIPIENT,
                amount: 10,
            })
            .unwrap(),
        };
        let transition = run(
            actor(WRAPPED_ID),
            Origin::Program(MINTER),
            false,
            Vec::new(),
            &delivery,
        );

        assert_eq!(transition.post_data, None);
        assert_eq!(
            transition.sends,
            vec![to_config(&mint_from(MINTER, ZONE_A, PEER_A, 10))],
            "the deliverer travels from the runtime's origin, and the config is checked first"
        );
    }

    #[test]
    fn a_mint_advances_only_the_matching_sources_counter() {
        let transition = mint_at_config(&mint_from(MINTER, ZONE_A, PEER_A, 400));

        assert_eq!(
            written_config(&transition).sources,
            vec![
                entry(ZONE_A, PEER_A, Some(1_000), 500),
                entry(ZONE_B, PEER_B, None, 0),
            ]
        );
        assert_eq!(
            transition.sends,
            vec![Envelope::new(holding_actor(), &Message::Credit(400))]
        );
    }

    #[test]
    #[should_panic(expected = "Mint is only callable by the authorized minter")]
    fn a_caller_that_is_not_the_configured_minter_cannot_mint() {
        let _transition = mint_at_config(&mint_from(STRANGER, ZONE_A, PEER_A, 1));
    }

    #[test]
    #[should_panic(expected = "Mint is only callable by the authorized minter")]
    fn a_top_level_mint_is_refused() {
        let _transition = at_config(
            Origin::Root,
            &config(),
            &mint_from(MINTER, ZONE_A, PEER_A, 1),
        );
    }

    #[test]
    #[should_panic(expected = "Mint is only callable for a peer source this token authorizes")]
    fn a_marker_no_authorized_source_derives_cannot_mint() {
        // Unbacked money printing if it were taken on the inbox's word: wrapped tokens have no
        // other backing check anywhere.
        let _transition = mint_at_config(&mint_from(MINTER, ZONE_A, STRANGER, 1));
    }

    #[test]
    #[should_panic(expected = "mint exceeds this source's lifetime cap")]
    fn a_mint_beyond_the_sources_lifetime_cap_is_refused() {
        let _transition = mint_at_config(&mint_from(MINTER, ZONE_A, PEER_A, 901));
    }

    #[test]
    fn an_uncapped_source_mints_freely() {
        let transition = mint_at_config(&mint_from(MINTER, ZONE_B, PEER_B, MAX_MINT_AMOUNT));
        assert_eq!(
            written_config(&transition).sources[1].minted,
            MAX_MINT_AMOUNT
        );
    }

    #[test]
    #[should_panic(expected = "mint amount exceeds the per-mint cap")]
    fn a_mint_above_the_per_mint_cap_is_refused() {
        let _transition = mint_at_config(&mint_from(
            MINTER,
            ZONE_B,
            PEER_B,
            MAX_MINT_AMOUNT.saturating_add(1),
        ));
    }

    #[test]
    fn a_credit_adds_to_the_recipients_balance() {
        let written =
            |pre, amount| credit_at_holding(Origin::Program(WRAPPED_ID), pre, amount).post_data;
        let balance =
            |amount: u128| Some(ShardData::try_from(balance_bytes(amount).to_vec()).unwrap());
        assert_eq!(written(40, 2), balance(42));
        assert_eq!(written(0, 42), balance(42));
    }

    #[test]
    #[should_panic(expected = "wrapped-token balance overflow")]
    fn a_credit_that_overflows_the_holding_is_refused() {
        let _transition = credit_at_holding(Origin::Program(WRAPPED_ID), u128::MAX, 1);
    }

    #[test]
    fn an_update_carries_over_a_kept_sources_counter_and_zeroes_a_re_added_one() {
        let transition = at_config(
            Origin::Program(WRAPPED_ID),
            &config(),
            &Message::UpdateSources {
                authority: AUTHORITY,
                via: None,
                sources: vec![
                    policy(ZONE_A, PEER_A, Some(2_000)),
                    policy(ZONE_A, PEER_B, Some(5)),
                ],
            },
        );
        assert_eq!(
            written_config(&transition).sources,
            vec![
                entry(ZONE_A, PEER_A, Some(2_000), 100),
                entry(ZONE_A, PEER_B, Some(5), 0),
            ]
        );
    }

    #[test]
    #[should_panic(expected = "must be the configured authority")]
    fn an_account_that_is_not_the_authority_cannot_replace_the_sources() {
        // The second independent route to unbounded minting: install a source naming yourself
        // with no cap, then walk into `Mint`.
        let _transition = at_config(
            Origin::Program(WRAPPED_ID),
            &config(),
            &Message::UpdateSources {
                authority: STRANGER,
                via: None,
                sources: vec![policy(ZONE_A, STRANGER, None)],
            },
        );
    }

    #[test]
    #[should_panic(expected = "the authority acts at top level, or through the configured")]
    fn a_program_the_config_does_not_name_cannot_carry_a_governance_call() {
        let _transition = at_config(
            Origin::Program(WRAPPED_ID),
            &config(),
            &update(AUTHORITY, Some(STRANGER)),
        );
    }

    #[test]
    #[should_panic(expected = "wrapped-token sources are fixed at genesis")]
    fn sources_cannot_be_replaced_once_the_authority_is_renounced() {
        let _transition = at_config(
            Origin::Program(WRAPPED_ID),
            &config_with(None, vec![]),
            &Message::UpdateSources {
                authority: AUTHORITY,
                via: None,
                sources: vec![policy(ZONE_A, STRANGER, None)],
            },
        );
    }

    #[test]
    #[should_panic(expected = "UpdateSources lists the same source twice")]
    fn an_update_listing_one_source_twice_is_refused() {
        let _transition = at_config(
            Origin::Program(WRAPPED_ID),
            &config(),
            &Message::UpdateSources {
                authority: AUTHORITY,
                via: None,
                sources: vec![
                    policy(ZONE_A, PEER_A, Some(1)),
                    policy(ZONE_A, PEER_A, Some(2)),
                ],
            },
        );
    }

    #[test]
    #[should_panic(expected = "the configured authority must authorize a source change")]
    fn an_unsigned_source_change_is_refused() {
        let _transition = run(
            actor(AUTHORITY),
            Origin::Root,
            false,
            Vec::new(),
            &update(AUTHORITY, None),
        );
    }

    #[test]
    fn an_update_pins_the_authenticated_caller_and_the_named_authority() {
        let transition = run(
            actor(AUTHORITY),
            Origin::Root,
            true,
            Vec::new(),
            &Message::UpdateSources {
                authority: STRANGER,
                via: Some(GOVERNANCE),
                sources: vec![policy(ZONE_A, PEER_A, None)],
            },
        );
        assert_eq!(
            transition.sends,
            vec![to_config(&Message::UpdateSources {
                authority: AUTHORITY,
                via: None,
                sources: vec![policy(ZONE_A, PEER_A, None)],
            })]
        );
    }

    #[test]
    fn renouncing_clears_the_authority_and_leaves_the_sources_alone() {
        let transition = at_config(
            Origin::Program(WRAPPED_ID),
            &config(),
            &Message::RenounceAuthority {
                authority: AUTHORITY,
                via: None,
            },
        );
        let written = written_config(&transition);
        assert_eq!(written.authority, None);
        assert_eq!(written.sources, config().sources);
    }

    #[test]
    #[should_panic(expected = "wrapped-token authority is already renounced")]
    fn a_second_renounce_is_refused() {
        let _transition = at_config(
            Origin::Program(WRAPPED_ID),
            &config_with(None, vec![]),
            &Message::RenounceAuthority {
                authority: AUTHORITY,
                via: None,
            },
        );
    }

    #[test]
    #[should_panic(expected = "must be the configured authority")]
    fn a_stranger_cannot_renounce_the_authority() {
        let _transition = at_config(
            Origin::Program(WRAPPED_ID),
            &config(),
            &Message::RenounceAuthority {
                authority: STRANGER,
                via: None,
            },
        );
    }

    #[test]
    fn a_first_init_writes_the_config_and_a_replay_is_a_no_op() {
        let init = Message::InitConfig(config());
        let first = run(config_actor(), Origin::Root, false, Vec::new(), &init);
        assert_eq!(written_config(&first), config());
        assert_eq!(
            written_config(&at_config(Origin::Root, &config(), &init)),
            config()
        );
    }

    #[test]
    #[should_panic(expected = "shard already holds different data")]
    fn a_reinit_with_different_contents_is_refused() {
        let _transition = at_config(
            Origin::Root,
            &config(),
            &Message::InitConfig(config_with(Some(STRANGER), vec![])),
        );
    }

    #[test]
    #[should_panic(expected = "InitConfig is a top-level genesis transaction")]
    fn an_inbox_delivered_init_is_refused() {
        let _transition = at_config(
            Origin::Program(MINTER),
            &config(),
            &Message::InitConfig(config()),
        );
    }
}
