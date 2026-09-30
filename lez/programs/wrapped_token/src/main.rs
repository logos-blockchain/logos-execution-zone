use cross_zone_marker_core::inbox_source_marker_account_id;
use lee_core::{
    account::AccountId,
    program::{AccountMeta, Plan, PlanInput, run_program, write_once},
};
use wrapped_token_core::{
    Instruction, MAX_MINT_AMOUNT, SourceEntry, SourcePolicy, WrappedTokenConfig, balance_bytes,
    config_account_id, holding_account_id, read_balance,
};

#[derive(Clone, borsh::BorshSerialize, borsh::BorshDeserialize)]
enum Effect {
    Mint {
        caller_account_id: Option<AccountId>,
        marker: AccountId,
        amount: u128,
    },
    Credit(u128),
    InitConfig(WrappedTokenConfig),
    RenounceAuthority {
        caller_account_id: Option<AccountId>,
        authority: AccountId,
    },
    UpdateSources {
        caller_account_id: Option<AccountId>,
        authority: AccountId,
        sources: Vec<SourcePolicy>,
    },
}

fn main() {
    run_program(plan, apply)
}

#[expect(
    clippy::unnecessary_wraps,
    reason = "run_program's apply returns None to keep a shard"
)]
fn apply(effect: Effect, pre_data: &[u8]) -> Option<Vec<u8>> {
    Some(match effect {
        Effect::Mint {
            caller_account_id,
            marker,
            amount,
        } => mint_source(pre_data, caller_account_id, marker, amount),
        // The backstop against accumulation, which the per-mint cap does not bound.
        Effect::Credit(amount) => balance_bytes(
            read_balance(pre_data)
                .checked_add(amount)
                .expect("wrapped-token balance overflow"),
        )
        .to_vec(),
        // A written shard must already hold exactly this configuration rather than being
        // refused.
        Effect::InitConfig(config_value) => write_once(pre_data, config_value.to_bytes()),
        Effect::RenounceAuthority {
            caller_account_id,
            authority,
        } => {
            let mut cfg = decode_config(pre_data);
            assert_governance_caller(&cfg, caller_account_id);
            let Some(expected) = cfg.authority else {
                panic!("wrapped-token authority is already renounced");
            };
            assert_eq!(
                authority, expected,
                "second account must be the configured authority"
            );

            cfg.authority = None;
            cfg.to_bytes()
        }
        Effect::UpdateSources {
            caller_account_id,
            authority,
            sources,
        } => {
            let mut cfg = decode_config(pre_data);
            assert_governance_caller(&cfg, caller_account_id);
            let Some(expected) = cfg.authority else {
                panic!("wrapped-token sources are fixed at genesis: no authority is configured");
            };
            assert_eq!(
                authority, expected,
                "second account must be the configured authority"
            );

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
            cfg.to_bytes()
        }
    })
}

fn decode_config(pre_data: &[u8]) -> WrappedTokenConfig {
    WrappedTokenConfig::from_bytes(pre_data).expect("config account holds a wrapped-token config")
}

// See `WrappedTokenConfig::governance` for why the chained-caller escape hatch exists.
fn assert_governance_caller(cfg: &WrappedTokenConfig, caller_account_id: Option<AccountId>) {
    assert!(
        caller_account_id.is_none() || caller_account_id == cfg.governance,
        "the authority acts at top level, or through the configured governance program"
    );
}

fn mint_source(
    pre_data: &[u8],
    caller_account_id: Option<AccountId>,
    marker: AccountId,
    amount: u128,
) -> Vec<u8> {
    let mut cfg = decode_config(pre_data);
    // The config PDA is genesis-seeded with the authorized minter (the cross-zone
    // inbox). Pin the caller to it, since the guest cannot import the inbox id.
    assert_eq!(
        caller_account_id,
        Some(cfg.minter),
        "Mint is only callable by the authorized minter (the cross-zone inbox)"
    );
    // The inbox vouches only that the message arrived; which peer sent it is this
    // token's own business, and unbacked value is what gets minted if it takes
    // anyone's word for it. The marker's address is the source, so re-deriving it
    // from an authorized pair is the whole check.
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

    cfg.to_bytes()
}

fn plan(input: &PlanInput, instruction: Instruction) -> Plan {
    match instruction {
        Instruction::Mint { recipient, amount } => mint(input, &recipient, amount),
        Instruction::InitConfig(config) => init_config(input, config),
        Instruction::RenounceAuthority => renounce_authority(input),
        Instruction::UpdateSources { sources } => update_sources(input, sources),
    }
}

fn mint(input: &PlanInput, recipient: &[u8; 32], amount: u128) -> Plan {
    let [marker, config, holding] = <&[AccountMeta; 3]>::try_from(input.accounts.as_slice())
        .expect("Mint requires the source marker, config, and recipient holding accounts");

    assert_eq!(
        config.account_id,
        config_account_id(input.self_account_id),
        "second account must be the wrapped-token config PDA"
    );
    assert_eq!(
        holding.account_id,
        holding_account_id(input.self_account_id, recipient),
        "third account must be the recipient holding PDA"
    );
    assert!(
        amount <= MAX_MINT_AMOUNT,
        "mint amount exceeds the per-mint cap"
    );

    let mut plan = Plan::new(input);
    // Both inputs to the authorization come from the call itself: `caller_account_id` is the
    // runtime's authenticated value, never an instruction field a peer could choose, and the
    // marker is the address the inbox bound to the message's real source.
    plan.effect(
        config,
        &Effect::Mint {
            caller_account_id: input.caller_account_id,
            marker: marker.account_id,
            amount,
        },
    );
    plan.effect(holding, &Effect::Credit(amount));
    plan
}

fn init_config(input: &PlanInput, config_value: WrappedTokenConfig) -> Plan {
    assert!(
        input.caller_account_id.is_none(),
        "InitConfig is a top-level genesis transaction"
    );

    let [config] = <&[AccountMeta; 1]>::try_from(input.accounts.as_slice())
        .expect("InitConfig requires the config account");
    assert_eq!(
        config.account_id,
        config_account_id(input.self_account_id),
        "account must be the wrapped-token config PDA"
    );

    let mut plan = Plan::new(input);
    plan.effect(config, &Effect::InitConfig(config_value));
    plan
}

fn renounce_authority(input: &PlanInput) -> Plan {
    let (config, authority) = governance_accounts(input);
    assert!(
        authority.is_authorized,
        "the configured authority must authorize renouncing it"
    );

    let mut plan = Plan::new(input);
    plan.effect(
        config,
        &Effect::RenounceAuthority {
            caller_account_id: input.caller_account_id,
            authority: authority.account_id,
        },
    );
    plan
}

/// Replaces the authorized sources, if the config names an authority and that
/// account authorized this transaction.
fn update_sources(input: &PlanInput, sources: Vec<SourcePolicy>) -> Plan {
    let (config, authority) = governance_accounts(input);
    assert!(
        authority.is_authorized,
        "the configured authority must authorize a source change"
    );
    // Mint advances the first matching entry, so a duplicated pair would split
    // one source's policy across entries an auditor reads as two.
    for (index, policy) in sources.iter().enumerate() {
        assert!(
            !sources[..index].iter().any(|other| {
                other.src_zone == policy.src_zone && other.src_account_id == policy.src_account_id
            }),
            "UpdateSources lists the same source twice"
        );
    }

    let mut plan = Plan::new(input);
    plan.effect(
        config,
        &Effect::UpdateSources {
            caller_account_id: input.caller_account_id,
            authority: authority.account_id,
            sources,
        },
    );
    plan
}

// Only the check that does not depend on the config's contents lives here; who may call and
// who the authority is stay in the config's `apply`.
fn governance_accounts(input: &PlanInput) -> (&AccountMeta, &AccountMeta) {
    let [config, authority] = <&[AccountMeta; 2]>::try_from(input.accounts.as_slice())
        .expect("this instruction requires exactly the config and authority accounts");
    assert_eq!(
        config.account_id,
        config_account_id(input.self_account_id),
        "first account must be the wrapped-token config PDA"
    );
    (config, authority)
}

#[cfg(test)]
mod tests {
    use lee_core::{account::ShardData, program::ShardEffect};

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

    fn marker_of(inbox: AccountId, src_zone: [u8; 32], src: AccountId) -> AccountId {
        inbox_source_marker_account_id(inbox, &src_zone, src)
    }

    fn shard(bytes: Vec<u8>) -> ShardData {
        ShardData::try_from(bytes).expect("the shard fits")
    }

    #[expect(
        clippy::needless_pass_by_value,
        reason = "callers hand over freshly built pre-states"
    )]
    fn apply_at(pre_data: ShardData, effect: &Effect) -> Vec<u8> {
        apply(effect.clone(), &pre_data).expect("every wrapped-token apply writes")
    }

    fn mint_effect(caller: Option<AccountId>, marker: AccountId, amount: u128) -> Effect {
        Effect::Mint {
            caller_account_id: caller,
            marker,
            amount,
        }
    }

    fn applied_config(pre_data: ShardData, effect: &Effect) -> WrappedTokenConfig {
        WrappedTokenConfig::from_bytes(&apply_at(pre_data, effect)).expect("a config was written")
    }

    fn mint_accounts(marker: AccountId) -> Vec<AccountMeta> {
        vec![
            AccountMeta::native_balance(marker, false),
            AccountMeta::new(config_account_id(WRAPPED_ID), false, WRAPPED_ID),
            AccountMeta::new(
                holding_account_id(WRAPPED_ID, &RECIPIENT),
                false,
                WRAPPED_ID,
            ),
        ]
    }

    fn governance_metas(authority: AccountId, is_authorized: bool) -> Vec<AccountMeta> {
        vec![
            AccountMeta::new(config_account_id(WRAPPED_ID), false, WRAPPED_ID),
            AccountMeta::native_balance(authority, is_authorized),
        ]
    }

    fn plan_for(
        caller_account_id: Option<AccountId>,
        accounts: Vec<AccountMeta>,
        instruction: Instruction,
    ) -> Plan {
        plan(
            &PlanInput {
                self_account_id: WRAPPED_ID,
                caller_account_id,
                accounts,
                instruction_data: borsh::to_vec(&instruction).expect("the instruction serializes"),
            },
            instruction,
        )
    }

    #[test]
    fn a_mint_pins_the_authenticated_caller_and_the_delivered_marker() {
        let marker = marker_of(MINTER, ZONE_A, PEER_A);
        let plan = plan_for(
            Some(MINTER),
            mint_accounts(marker),
            Instruction::Mint {
                recipient: RECIPIENT,
                amount: 10,
            },
        );

        let config_meta = AccountMeta::new(config_account_id(WRAPPED_ID), false, WRAPPED_ID);
        let holding_meta = AccountMeta::new(
            holding_account_id(WRAPPED_ID, &RECIPIENT),
            false,
            WRAPPED_ID,
        );
        assert_eq!(
            plan.output().effects,
            vec![
                ShardEffect::new(&config_meta, &mint_effect(Some(MINTER), marker, 10)),
                ShardEffect::new(&holding_meta, &Effect::Credit(10)),
            ],
            "the caller travels from the runtime's metadata, and the config is checked first"
        );
        assert!(plan.output().chained_calls.is_empty());
    }

    #[test]
    fn a_mint_advances_only_the_matching_sources_counter() {
        let written = applied_config(
            shard(config().to_bytes()),
            &mint_effect(Some(MINTER), marker_of(MINTER, ZONE_A, PEER_A), 400),
        );
        assert_eq!(
            written.sources,
            vec![
                entry(ZONE_A, PEER_A, Some(1_000), 500),
                entry(ZONE_B, PEER_B, None, 0),
            ]
        );
    }

    #[test]
    #[should_panic(expected = "Mint is only callable by the authorized minter")]
    fn a_caller_that_is_not_the_configured_minter_cannot_mint() {
        apply_at(
            shard(config().to_bytes()),
            &mint_effect(Some(STRANGER), marker_of(MINTER, ZONE_A, PEER_A), 1),
        );
    }

    #[test]
    #[should_panic(expected = "Mint is only callable by the authorized minter")]
    fn a_top_level_mint_is_refused() {
        apply_at(
            shard(config().to_bytes()),
            &mint_effect(None, marker_of(MINTER, ZONE_A, PEER_A), 1),
        );
    }

    #[test]
    #[should_panic(expected = "Mint is only callable for a peer source this token authorizes")]
    fn a_marker_no_authorized_source_derives_cannot_mint() {
        // Unbacked money printing if it were taken on the inbox's word: wrapped tokens have no
        // other backing check anywhere.
        apply_at(
            shard(config().to_bytes()),
            &mint_effect(Some(MINTER), marker_of(MINTER, ZONE_A, STRANGER), 1),
        );
    }

    #[test]
    #[should_panic(expected = "Mint is only callable for a peer source this token authorizes")]
    fn a_marker_derived_under_another_inbox_cannot_mint() {
        // The derivation uses the config's own minter, so a marker minted under some other
        // inbox's address space names no source here.
        apply_at(
            shard(config().to_bytes()),
            &mint_effect(Some(MINTER), marker_of(STRANGER, ZONE_A, PEER_A), 1),
        );
    }

    #[test]
    #[should_panic(expected = "mint exceeds this source's lifetime cap")]
    fn a_mint_beyond_the_sources_lifetime_cap_is_refused() {
        apply_at(
            shard(config().to_bytes()),
            &mint_effect(Some(MINTER), marker_of(MINTER, ZONE_A, PEER_A), 901),
        );
    }

    #[test]
    fn an_uncapped_source_mints_freely() {
        let written = applied_config(
            shard(config().to_bytes()),
            &mint_effect(
                Some(MINTER),
                marker_of(MINTER, ZONE_B, PEER_B),
                MAX_MINT_AMOUNT,
            ),
        );
        assert_eq!(written.sources[1].minted, MAX_MINT_AMOUNT);
    }

    #[test]
    #[should_panic(expected = "second account must be the wrapped-token config PDA")]
    fn a_mint_that_names_another_account_as_the_config_is_refused() {
        let mut metas = mint_accounts(marker_of(MINTER, ZONE_A, PEER_A));
        metas[1] = AccountMeta::new(STRANGER, false, WRAPPED_ID);
        let _plan = plan_for(
            Some(MINTER),
            metas,
            Instruction::Mint {
                recipient: RECIPIENT,
                amount: 1,
            },
        );
    }

    #[test]
    #[should_panic(expected = "third account must be the recipient holding PDA")]
    fn a_mint_credited_outside_the_recipients_holding_is_refused() {
        let mut metas = mint_accounts(marker_of(MINTER, ZONE_A, PEER_A));
        metas[2] = AccountMeta::new(STRANGER, false, WRAPPED_ID);
        let _plan = plan_for(
            Some(MINTER),
            metas,
            Instruction::Mint {
                recipient: RECIPIENT,
                amount: 1,
            },
        );
    }

    #[test]
    #[should_panic(expected = "mint amount exceeds the per-mint cap")]
    fn a_mint_above_the_per_mint_cap_is_refused() {
        let _plan = plan_for(
            Some(MINTER),
            mint_accounts(marker_of(MINTER, ZONE_A, PEER_A)),
            Instruction::Mint {
                recipient: RECIPIENT,
                amount: MAX_MINT_AMOUNT.saturating_add(1),
            },
        );
    }

    #[test]
    fn a_credit_adds_to_the_recipients_balance() {
        assert_eq!(
            apply_at(shard(balance_bytes(40).to_vec()), &Effect::Credit(2)),
            balance_bytes(42).to_vec()
        );
        assert_eq!(
            apply_at(ShardData::empty(), &Effect::Credit(42)),
            balance_bytes(42).to_vec()
        );
    }

    #[test]
    #[should_panic(expected = "wrapped-token balance overflow")]
    fn a_credit_that_overflows_the_holding_is_refused() {
        apply_at(shard(balance_bytes(u128::MAX).to_vec()), &Effect::Credit(1));
    }

    #[test]
    fn an_update_carries_over_a_kept_sources_counter_and_zeroes_a_re_added_one() {
        let written = applied_config(
            shard(config().to_bytes()),
            &Effect::UpdateSources {
                caller_account_id: None,
                authority: AUTHORITY,
                sources: vec![
                    policy(ZONE_A, PEER_A, Some(2_000)),
                    policy(ZONE_A, PEER_B, Some(5)),
                ],
            },
        );
        assert_eq!(
            written.sources,
            vec![
                entry(ZONE_A, PEER_A, Some(2_000), 100),
                entry(ZONE_A, PEER_B, Some(5), 0),
            ]
        );
    }

    #[test]
    #[should_panic(expected = "second account must be the configured authority")]
    fn an_account_that_is_not_the_authority_cannot_replace_the_sources() {
        // The second independent route to unbounded minting: install a source naming yourself
        // with no cap, then walk into `Mint`.
        apply_at(
            shard(config().to_bytes()),
            &Effect::UpdateSources {
                caller_account_id: None,
                authority: STRANGER,
                sources: vec![policy(ZONE_A, STRANGER, None)],
            },
        );
    }

    #[test]
    #[should_panic(expected = "the authority acts at top level, or through the configured")]
    fn a_program_the_config_does_not_name_cannot_carry_a_governance_call() {
        apply_at(
            shard(config().to_bytes()),
            &Effect::UpdateSources {
                caller_account_id: Some(STRANGER),
                authority: AUTHORITY,
                sources: vec![],
            },
        );
    }

    #[test]
    #[should_panic(expected = "wrapped-token sources are fixed at genesis")]
    fn sources_cannot_be_replaced_once_the_authority_is_renounced() {
        apply_at(
            shard(config_with(None, vec![]).to_bytes()),
            &Effect::UpdateSources {
                caller_account_id: None,
                authority: AUTHORITY,
                sources: vec![policy(ZONE_A, STRANGER, None)],
            },
        );
    }

    #[test]
    #[should_panic(expected = "UpdateSources lists the same source twice")]
    fn an_update_listing_one_source_twice_is_refused() {
        let _plan = plan_for(
            None,
            governance_metas(AUTHORITY, true),
            Instruction::UpdateSources {
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
        let _plan = plan_for(
            None,
            governance_metas(AUTHORITY, false),
            Instruction::UpdateSources { sources: vec![] },
        );
    }

    #[test]
    fn an_update_pins_the_authenticated_caller_and_the_named_authority() {
        let plan = plan_for(
            Some(GOVERNANCE),
            governance_metas(AUTHORITY, true),
            Instruction::UpdateSources {
                sources: vec![policy(ZONE_A, PEER_A, None)],
            },
        );
        assert_eq!(
            plan.output().effects,
            vec![ShardEffect::new(
                &AccountMeta::new(config_account_id(WRAPPED_ID), false, WRAPPED_ID),
                &Effect::UpdateSources {
                    caller_account_id: Some(GOVERNANCE),
                    authority: AUTHORITY,
                    sources: vec![policy(ZONE_A, PEER_A, None)],
                },
            )]
        );
    }

    #[test]
    fn renouncing_clears_the_authority_and_leaves_the_sources_alone() {
        let written = applied_config(
            shard(config().to_bytes()),
            &Effect::RenounceAuthority {
                caller_account_id: None,
                authority: AUTHORITY,
            },
        );
        assert_eq!(written.authority, None);
        assert_eq!(written.sources, config().sources);
    }

    #[test]
    #[should_panic(expected = "wrapped-token authority is already renounced")]
    fn a_second_renounce_is_refused() {
        apply_at(
            shard(config_with(None, vec![]).to_bytes()),
            &Effect::RenounceAuthority {
                caller_account_id: None,
                authority: AUTHORITY,
            },
        );
    }

    #[test]
    #[should_panic(expected = "second account must be the configured authority")]
    fn a_stranger_cannot_renounce_the_authority() {
        apply_at(
            shard(config().to_bytes()),
            &Effect::RenounceAuthority {
                caller_account_id: None,
                authority: STRANGER,
            },
        );
    }

    #[test]
    fn a_first_init_writes_the_config_and_a_replay_is_a_no_op() {
        assert_eq!(
            apply_at(ShardData::empty(), &Effect::InitConfig(config())),
            config().to_bytes()
        );
        assert_eq!(
            apply_at(shard(config().to_bytes()), &Effect::InitConfig(config())),
            config().to_bytes()
        );
    }

    #[test]
    #[should_panic(expected = "shard already holds different data")]
    fn a_reinit_with_different_contents_is_refused() {
        apply_at(
            shard(config().to_bytes()),
            &Effect::InitConfig(config_with(Some(STRANGER), vec![])),
        );
    }

    #[test]
    #[should_panic(expected = "InitConfig is a top-level genesis transaction")]
    fn an_inbox_delivered_init_is_refused() {
        let _plan = plan_for(
            Some(MINTER),
            vec![AccountMeta::new(
                config_account_id(WRAPPED_ID),
                false,
                WRAPPED_ID,
            )],
            Instruction::InitConfig(config()),
        );
    }
}
