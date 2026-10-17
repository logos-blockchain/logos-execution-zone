//! Signs a committee member's approval of a `system_upgrader` change, offline.
//!
//! Reads `<home>/bedrock_signing_key` (the node's sequencer key) and the zone's channel id from the
//! given sequencer config, and prints the signed approval as hex-encoded borsh, ready to submit to
//! the nodes, and the proposal's hash on stderr, for committee members to compare. Never touches
//! the network, and never creates a key.
//!
//! A `Schedule` must land before its activation height, so its height must lead the chain's tip
//! (`--tip`) by at least `--min-lead` blocks; one that misses it must be signed again at a new
//! height. An approval of a `Schedule` or `Cancel` is useless from that height on, so
//! `--valid-until` defaults to the block before it.

use std::path::PathBuf;

use anyhow::{Result, anyhow, ensure};
use clap::{Parser, Subcommand};
use lee::{AccountId, ProgramId};
use lee_core::BlockId;
use system_upgrader_core::{Approval, Proposal, SequencerKey, SignedApproval, SystemProgramName};

/// Several producer rotations and a reorg's worth of blocks, for a `Schedule` to land in.
const DEFAULT_MIN_LEAD: BlockId = 100;

#[derive(Debug, Parser)]
#[clap(version)]
struct Args {
    #[clap(name = "config")]
    config_path: PathBuf,
    /// Override the config's home directory, matching the sequencer's --home.
    #[clap(long)]
    home: Option<PathBuf>,
    /// The chain's current height.
    #[clap(long)]
    tip: BlockId,
    /// The last block at which the approval may be used. Defaults to the block before the
    /// activation height; required for `install`.
    #[clap(long)]
    valid_until: Option<BlockId>,
    /// The fewest blocks a `Schedule`'s activation height may lead the tip by.
    #[clap(long, default_value_t = DEFAULT_MIN_LEAD)]
    min_lead: BlockId,
    #[clap(subcommand)]
    proposal: ProposalArgs,
}

#[derive(Debug, Subcommand)]
enum ProposalArgs {
    /// Switch `name` to the segment chain at `first_segment`, at block `activation_height`.
    Schedule {
        #[clap(long)]
        name: String,
        #[clap(long)]
        first_segment: AccountId,
        /// The chain's image ID, from a reproducible build, as 64 hex digits.
        #[clap(long, value_parser = parse_image_id)]
        image_id: ProgramId,
        #[clap(long)]
        activation_height: BlockId,
    },
    /// Withdraw `name`'s pending upgrade, if it is exactly this one. Approvals are checked when the
    /// change lands, so a cancel needs the current committee's signatures.
    Cancel {
        #[clap(long)]
        name: String,
        #[clap(long)]
        first_segment: AccountId,
        #[clap(long)]
        activation_height: BlockId,
    },
    /// Deploy a new system program `name` from the segment chain at `first_segment`.
    Install {
        #[clap(long)]
        name: String,
        #[clap(long)]
        first_segment: AccountId,
        /// The chain's image ID, from a reproducible build, as 64 hex digits.
        #[clap(long, value_parser = parse_image_id)]
        image_id: ProgramId,
    },
}

impl ProposalArgs {
    fn proposal(self) -> Result<Proposal> {
        Ok(match self {
            Self::Schedule {
                name,
                first_segment,
                image_id,
                activation_height,
            } => Proposal::Schedule {
                name: parse_name(&name)?,
                first_segment,
                image_id,
                activation_height,
            },
            Self::Cancel {
                name,
                first_segment,
                activation_height,
            } => Proposal::Cancel {
                name: parse_name(&name)?,
                first_segment,
                activation_height,
            },
            Self::Install {
                name,
                first_segment,
                image_id,
            } => Proposal::Install {
                name: parse_name(&name)?,
                first_segment,
                image_id,
            },
        })
    }
}

fn parse_name(name: &str) -> Result<SystemProgramName> {
    ensure!(
        !name.is_empty() && name.len() <= 32,
        "a system program name is 1 to 32 bytes"
    );
    Ok(SystemProgramName::new(name.as_bytes()))
}

/// An image ID as RISC Zero prints a digest: 32 bytes in hex, each word little-endian.
fn parse_image_id(hex: &str) -> Result<ProgramId> {
    let bytes: [u8; 32] = hex::decode(hex)?
        .try_into()
        .map_err(|_bytes| anyhow!("an image ID is 32 bytes"))?;
    let mut image_id = ProgramId::default();
    for (word, chunk) in image_id.iter_mut().zip(bytes.as_chunks::<4>().0) {
        *word = u32::from_le_bytes(*chunk);
    }
    Ok(image_id)
}

/// The `valid_until` to sign, refusing one that is useless or a `Schedule` that can't land in
/// time.
fn valid_until(
    proposal: &Proposal,
    tip: BlockId,
    valid_until: Option<BlockId>,
    min_lead: BlockId,
) -> Result<BlockId> {
    let activation_height = match proposal {
        Proposal::Schedule {
            activation_height, ..
        } => {
            ensure!(
                *activation_height >= tip.saturating_add(min_lead),
                "activation height {activation_height} leads the tip {tip} by less than {min_lead} \
                 blocks"
            );
            Some(*activation_height)
        }
        Proposal::Cancel {
            activation_height, ..
        } => Some(*activation_height),
        Proposal::Install { .. } => None,
    };
    let valid_until = match (valid_until, activation_height) {
        (Some(valid_until), _) => valid_until,
        (None, Some(activation_height)) => activation_height.saturating_sub(1),
        (None, None) => return Err(anyhow!("an install needs --valid-until")),
    };
    if let Some(activation_height) = activation_height {
        ensure!(
            valid_until < activation_height,
            "valid_until {valid_until} isn't before the activation height {activation_height}"
        );
    }
    ensure!(
        valid_until > tip,
        "valid_until {valid_until} has passed at the tip {tip}"
    );
    Ok(valid_until)
}

#[expect(
    clippy::print_stdout,
    clippy::print_stderr,
    reason = "the signed approval on stdout is this binary's output, the proposal hash on stderr \
              is for its operator"
)]
fn main() -> Result<()> {
    let Args {
        config_path,
        home,
        tip,
        valid_until: requested,
        min_lead,
        proposal,
    } = Args::parse();

    let proposal = proposal.proposal()?;
    let valid_until = valid_until(&proposal, tip, requested, min_lead)?;

    let config = sequencer_service::SequencerConfig::from_path(&config_path)?;
    let home = home.unwrap_or(config.home);
    let key = sequencer_core::load_signing_key(&home.join("bedrock_signing_key"))?;
    let channel_id: [u8; 32] = config.bedrock_config.channel_id.into();

    let message = system_upgrader_core::approval_message(channel_id, &proposal, valid_until);
    let signed = SignedApproval {
        proposal,
        approval: Approval {
            signer: SequencerKey::new(key.public_key().to_bytes())
                .ok_or_else(|| anyhow!("the signing key is not a valid sequencer key"))?,
            valid_until,
            signature: key.sign_payload(&message).to_bytes().to_vec(),
        },
    };
    eprintln!("proposal {}", hex::encode(signed.proposal.hash()));
    println!("{}", hex::encode(borsh::to_vec(&signed)?));

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn schedule(activation_height: BlockId) -> Proposal {
        Proposal::Schedule {
            name: SystemProgramName::new(b"clock"),
            first_segment: AccountId::new([1; 32]),
            image_id: [2; 8],
            activation_height,
        }
    }

    fn cancel(activation_height: BlockId) -> Proposal {
        Proposal::Cancel {
            name: SystemProgramName::new(b"clock"),
            first_segment: AccountId::new([1; 32]),
            activation_height,
        }
    }

    #[test]
    fn an_approval_defaults_to_the_block_before_its_height() {
        assert_eq!(valid_until(&schedule(200), 100, None, 100).unwrap(), 199);
        assert_eq!(valid_until(&cancel(200), 190, None, 100).unwrap(), 199);
    }

    #[test]
    fn a_schedule_without_enough_lead_is_refused() {
        assert!(valid_until(&schedule(199), 100, None, 100).is_err());
        assert!(valid_until(&schedule(200), 100, None, 100).is_ok());
    }

    #[test]
    fn a_cancel_needs_no_lead() {
        assert_eq!(valid_until(&cancel(200), 198, None, 100).unwrap(), 199);
    }

    #[test]
    fn a_useless_valid_until_is_refused() {
        assert!(
            valid_until(&schedule(200), 100, Some(200), 100).is_err(),
            "at the height"
        );
        assert!(valid_until(&cancel(200), 199, None, 100).is_err(), "passed");
        let install = Proposal::Install {
            name: SystemProgramName::new(b"clock"),
            first_segment: AccountId::new([1; 32]),
            image_id: [2; 8],
        };
        assert!(valid_until(&install, 100, None, 100).is_err(), "none");
        assert_eq!(valid_until(&install, 100, Some(120), 100).unwrap(), 120);
    }

    #[test]
    fn an_image_id_parses_as_risc_zero_prints_it() {
        let image_id: ProgramId = [1, 2, 3, 4, 5, 6, 7, 0xdead_beef];
        let bytes: Vec<u8> = image_id
            .iter()
            .flat_map(|word| word.to_le_bytes())
            .collect();
        assert_eq!(parse_image_id(&hex::encode(&bytes)).unwrap(), image_id);
        assert!(parse_image_id(&hex::encode(&bytes[1..])).is_err());
    }
}
