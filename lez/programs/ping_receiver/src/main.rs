use cross_zone_marker_core::inbox_source_marker_account_id;
use lee_core::{
    account::AccountId,
    program::{
        AccountMeta, LeeCall, Plan, ProgramInput, read_lee_call, resolve_keep, resolve_write,
    },
};
use ping_core::{
    ReceiverConfig, ReceiverInstruction, ZoneId, ping_record_pda, receiver_config_account_id,
};

#[derive(borsh::BorshSerialize, borsh::BorshDeserialize)]
enum Effect {
    /// The config decides whether it accepts the deliverer and the claimed peer: without this
    /// the record says only that some program on some configured peer wrote it.
    AcceptDelivery {
        caller: AccountId,
        marker: AccountId,
    },
    /// Leaves the source list fixed for good.
    RenounceAuthority {
        caller: Option<AccountId>,
        authority: AccountId,
    },
    UpdateSources {
        caller: Option<AccountId>,
        authority: AccountId,
        sources: Vec<(ZoneId, AccountId)>,
    },
    InitConfig(ReceiverConfig),
    WriteRecord(Vec<u8>),
}

fn main() {
    match read_lee_call::<ReceiverInstruction>() {
        LeeCall::Execute(input, instruction_data) => execute(&input, instruction_data),
        LeeCall::Resolve(input) => {
            let effect =
                borsh::from_slice(&input.effect_data).expect("ping_receiver wrote its own effect");
            match resolve_effect(effect, &input.pre_data) {
                None => resolve_keep(input),
                Some(data) => {
                    resolve_write(input, data.try_into().expect("data fits in account data"))
                }
            }
        }
    }
}

fn resolve_effect(effect: Effect, pre_data: &[u8]) -> Option<Vec<u8>> {
    match effect {
        Effect::AcceptDelivery { caller, marker } => {
            let cfg = decode_config(pre_data);
            assert_eq!(
                caller, cfg.deliverer,
                "Record is only callable by the authorized deliverer (the cross-zone inbox)"
            );
            // Which peer sent it is this program's own business.
            assert!(
                cfg.sources.iter().any(|(src_zone, src_account_id)| {
                    marker
                        == inbox_source_marker_account_id(cfg.deliverer, src_zone, *src_account_id)
                }),
                "Record is only callable for a peer source this receiver authorizes"
            );
            None
        }
        Effect::RenounceAuthority { caller, authority } => {
            let mut cfg = decode_config(pre_data);
            assert_authority(
                &cfg,
                caller,
                authority,
                "receiver authority is already renounced",
            );
            cfg.authority = None;
            Some(cfg.to_bytes())
        }
        Effect::UpdateSources {
            caller,
            authority,
            sources,
        } => {
            let mut cfg = decode_config(pre_data);
            assert_authority(
                &cfg,
                caller,
                authority,
                "receiver sources are fixed at genesis: no authority is configured",
            );
            cfg.sources = sources;
            Some(cfg.to_bytes())
        }
        Effect::InitConfig(config) => {
            let bytes = config.to_bytes();
            // Genesis is replayed onto seeded state during multi-sequencer reconstruction, so
            // a written config must already hold exactly this.
            if !pre_data.is_empty() {
                assert_eq!(
                    pre_data, bytes,
                    "receiver config already initialized differently"
                );
            }
            Some(bytes)
        }
        Effect::WriteRecord(payload) => Some(payload),
    }
}

fn decode_config(pre_data: &[u8]) -> ReceiverConfig {
    ReceiverConfig::from_bytes(pre_data).expect("config account holds a receiver config")
}

fn assert_authority(
    cfg: &ReceiverConfig,
    caller: Option<AccountId>,
    authority: AccountId,
    unset: &str,
) {
    // See `ReceiverConfig::governance` for why the governance escape hatch exists.
    assert!(
        caller.is_none() || caller == cfg.governance,
        "the authority acts at top level, or through the configured governance program"
    );
    let Some(expected) = cfg.authority else {
        panic!("{unset}");
    };
    assert_eq!(
        authority, expected,
        "second account must be the configured authority"
    );
}

fn execute(input: &ProgramInput<ReceiverInstruction>, instruction_data: Vec<u8>) -> ! {
    match &input.instruction {
        ReceiverInstruction::Record { payload } => {
            let [marker, config, record] = <[_; 3]>::try_from(input.accounts.clone())
                .expect("Record requires the source marker, config, and record accounts");
            assert_config_account(&config, input.self_account_id);
            let Some(caller) = input.caller_account_id else {
                panic!(
                    "Record is only callable by the authorized deliverer (the cross-zone inbox)"
                );
            };
            assert_eq!(
                record.account_id,
                ping_record_pda(input.self_account_id),
                "third account must be the ping record PDA"
            );

            let mut plan = Plan::new(input, instruction_data);
            plan.effect(
                &config,
                &Effect::AcceptDelivery {
                    caller,
                    marker: marker.account_id,
                },
            );
            plan.update(&record, &Effect::WriteRecord(payload.clone()));
            plan.write()
        }
        ReceiverInstruction::RenounceAuthority => {
            let (config, authority) = governance_accounts(input);
            let mut plan = Plan::new(input, instruction_data);
            plan.update(
                &config,
                &Effect::RenounceAuthority {
                    caller: input.caller_account_id,
                    authority: authority.account_id,
                },
            );
            plan.write()
        }
        ReceiverInstruction::UpdateSources { sources } => {
            let (config, authority) = governance_accounts(input);
            let mut plan = Plan::new(input, instruction_data);
            plan.update(
                &config,
                &Effect::UpdateSources {
                    caller: input.caller_account_id,
                    authority: authority.account_id,
                    sources: sources.clone(),
                },
            );
            plan.write()
        }
        ReceiverInstruction::InitConfig(config_value) => {
            assert!(
                input.caller_account_id.is_none(),
                "InitConfig is a top-level genesis transaction"
            );
            let [config] = <[_; 1]>::try_from(input.accounts.clone())
                .expect("InitConfig requires the config account");
            assert_config_account(&config, input.self_account_id);

            let mut plan = Plan::new(input, instruction_data);
            plan.update(&config, &Effect::InitConfig(config_value.clone()));
            plan.write()
        }
    }
}

/// Which account the authority has to be, and who may reach this instruction at all, is the
/// config's own answer and is checked there.
fn governance_accounts(input: &ProgramInput<ReceiverInstruction>) -> (AccountMeta, AccountMeta) {
    let [config, authority] = <[_; 2]>::try_from(input.accounts.clone())
        .expect("this instruction requires exactly the config and authority accounts");
    assert_config_account(&config, input.self_account_id);
    assert!(
        authority.is_authorized,
        "the configured authority must authorize a change"
    );
    (config, authority)
}

fn assert_config_account(config: &AccountMeta, self_account_id: AccountId) {
    assert_eq!(
        config.account_id,
        receiver_config_account_id(self_account_id),
        "the config account must be the receiver config PDA"
    );
    assert_eq!(
        config.program_account_id, self_account_id,
        "the config must be named under this program's shard"
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
            resolve_effect(
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
        resolve_effect(
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
        resolve_effect(
            Effect::AcceptDelivery {
                caller: INBOX,
                marker: inbox_source_marker_account_id(INBOX, &ZONE, AccountId::new([4; 32])),
            },
            &config().to_bytes(),
        );
    }

    #[test]
    fn the_configured_authority_may_replace_the_sources() {
        let updated = resolve_effect(
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
        resolve_effect(
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
        resolve_effect(
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
        let updated = resolve_effect(
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
        resolve_effect(
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
            resolve_effect(Effect::InitConfig(config()), &config().to_bytes()),
            Some(config().to_bytes())
        );
    }

    #[test]
    #[should_panic(expected = "already initialized differently")]
    fn a_reinit_with_different_contents_is_refused() {
        let mut other = config();
        other.sources = vec![];
        resolve_effect(Effect::InitConfig(other), &config().to_bytes());
    }
}
