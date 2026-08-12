use std::collections::HashSet;

use cucumber::gherkin::Step;
use logos_blockchain_key_management_system_service::keys::ED25519_SECRET_KEY_SIZE;

use crate::{
    cucumber::error::StepError,
    tf::{LezSequencerClient, LezSequencerRegistryClient},
};

mod actions;
mod assertions;

/// Committee configuration values parsed from a Cucumber table.
pub(crate) struct CommitteeConfigArguments {
    pub posting_timeframe: u32,
    pub posting_timeout: u32,
    pub withdraw_threshold: u16,
    pub deposit_threshold: u16,
    pub authorized_sequencers: Vec<String>,
}

pub(crate) fn parse_sequencer_registrations(
    step: &Step,
) -> Result<Vec<(String, [u8; ED25519_SECRET_KEY_SIZE])>, StepError> {
    let table = step
        .table
        .as_ref()
        .ok_or_else(|| StepError::InvalidArgument {
            message: "sequencer registration requires a table".to_owned(),
        })?;
    if table.rows.first() != Some(&vec!["alias".to_owned(), "signing_key".to_owned()]) {
        return Err(StepError::InvalidArgument {
            message: "sequencer registration table must use `alias`, `signing_key` headers"
                .to_owned(),
        });
    }
    let mut aliases = HashSet::new();
    table
        .rows
        .iter()
        .skip(1)
        .map(|row| {
            if row.len() != 2 {
                return Err(StepError::InvalidArgument {
                    message: format!(
                        "sequencer registration rows require 2 columns, got {}",
                        row.len()
                    ),
                });
            }
            let alias = row[0].trim().to_owned();
            if alias.is_empty() {
                return Err(StepError::InvalidArgument {
                    message: "sequencer alias cannot be empty".to_owned(),
                });
            }
            if !aliases.insert(alias.clone()) {
                return Err(StepError::InvalidArgument {
                    message: format!("sequencer alias '{alias}' is duplicated"),
                });
            }
            let seed = row[1].trim();
            let seed = seed
                .strip_prefix("0x")
                .or_else(|| seed.strip_prefix("0X"))
                .ok_or_else(|| StepError::InvalidArgument {
                    message: format!("signing key seed '{seed}' must use 0xNN notation"),
                })?;
            let seed =
                u8::from_str_radix(seed, 16).map_err(|_error| StepError::InvalidArgument {
                    message: format!("signing key seed '{}' is not a byte", row[1].trim()),
                })?;
            Ok((alias, [seed; ED25519_SECRET_KEY_SIZE]))
        })
        .collect()
}

pub(crate) fn parse_committee_config(step: &Step) -> Result<CommitteeConfigArguments, StepError> {
    let table = step
        .table
        .as_ref()
        .ok_or_else(|| StepError::InvalidArgument {
            message: "committee configuration requires a table".to_owned(),
        })?;
    let expected = [
        "posting_timeframe",
        "posting_timeout",
        "withdraw_threshold",
        "deposit_threshold",
        "authorized_sequencers",
    ];
    if table.rows.first() != Some(&expected.iter().map(ToString::to_string).collect::<Vec<_>>()) {
        return Err(StepError::InvalidArgument {
            message: "committee configuration table has invalid headers".to_owned(),
        });
    }
    let row = table
        .rows
        .get(1)
        .ok_or_else(|| StepError::InvalidArgument {
            message: "committee configuration requires one data row".to_owned(),
        })?;
    if row.len() != expected.len() || table.rows.len() != 2 {
        return Err(StepError::InvalidArgument {
            message: "committee configuration requires exactly one complete data row".to_owned(),
        });
    }
    let parse_u32 = |value: &str, name: &str| {
        value
            .trim()
            .parse::<u32>()
            .map_err(|_error| StepError::InvalidArgument {
                message: format!("{name} '{value}' is not a u32"),
            })
    };
    let parse_u16 = |value: &str, name: &str| {
        value
            .trim()
            .parse::<u16>()
            .map_err(|_error| StepError::InvalidArgument {
                message: format!("{name} '{value}' is not a u16"),
            })
    };
    let authorized_sequencers = row[4]
        .split(',')
        .map(str::trim)
        .filter(|alias| !alias.is_empty())
        .map(ToOwned::to_owned)
        .collect::<Vec<_>>();
    if authorized_sequencers.is_empty() {
        return Err(StepError::InvalidArgument {
            message: "authorized_sequencers must contain at least one alias".to_owned(),
        });
    }
    Ok(CommitteeConfigArguments {
        posting_timeframe: parse_u32(&row[0], expected[0])?,
        posting_timeout: parse_u32(&row[1], expected[1])?,
        withdraw_threshold: parse_u16(&row[2], expected[2])?,
        deposit_threshold: parse_u16(&row[3], expected[3])?,
        authorized_sequencers,
    })
}

pub(crate) fn require_sequencer(
    registry: &LezSequencerRegistryClient,
    alias: &str,
) -> Result<LezSequencerClient, StepError> {
    registry
        .sequencer(alias)
        .ok_or_else(|| StepError::MissingComponent {
            component: "LezSequencerRegistryClient",
            message: format!("sequencer alias '{alias}' was not started"),
        })
}
