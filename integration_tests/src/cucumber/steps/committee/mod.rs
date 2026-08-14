use std::collections::HashSet;

use cucumber::gherkin::Step;
use logos_blockchain_key_management_system_service::keys::ED25519_SECRET_KEY_SIZE;

use crate::{
    cucumber::error::StepError,
    tf::{LezSequencerClient, LezSequencerRegistryClient},
};

mod actions;
mod assertions;

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

pub(crate) fn parse_committee_config(
    step: &Step,
    leader_alias: &str,
) -> Result<Vec<String>, StepError> {
    let table = step
        .table
        .as_ref()
        .ok_or_else(|| StepError::InvalidArgument {
            message: "committee configuration requires a table".to_owned(),
        })?;
    let expected = ["authorized_sequencers"];
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
    let authorized_sequencers = row[0]
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
    let mut unique_aliases = HashSet::new();
    if authorized_sequencers
        .iter()
        .any(|alias| !unique_aliases.insert(alias))
    {
        return Err(StepError::InvalidArgument {
            message: "authorized_sequencers must not contain duplicate aliases".to_owned(),
        });
    }
    if !authorized_sequencers
        .iter()
        .any(|alias| alias == leader_alias)
    {
        return Err(StepError::InvalidArgument {
            message: format!(
                "committee leader '{leader_alias}' must be included in authorized_sequencers"
            ),
        });
    }
    Ok(authorized_sequencers)
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
