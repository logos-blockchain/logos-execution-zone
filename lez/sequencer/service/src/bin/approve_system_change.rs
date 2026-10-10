//! Signs a committee member's approval of a `system_upgrader` change, offline.
//!
//! Reads `<home>/bedrock_signing_key` (the node's sequencer key) and the zone's channel id from the
//! given sequencer config, and prints the signed approval as hex-encoded borsh, ready to submit to
//! the nodes. Never touches the network, and never creates a key.

use std::path::PathBuf;

use anyhow::{Result, ensure};
use clap::{Parser, Subcommand};
use lee::AccountId;
use system_upgrader_core::{Approval, Proposal, SequencerKey, SignedApproval, SystemProgramName};

#[derive(Debug, Parser)]
#[clap(version)]
struct Args {
    #[clap(name = "config")]
    config_path: PathBuf,
    /// Override the config's home directory, matching the sequencer's --home.
    #[clap(long)]
    home: Option<PathBuf>,
    /// The last block at which the approval may be used. Keep it short.
    #[clap(long)]
    valid_until: u64,
    #[clap(subcommand)]
    proposal: ProposalArgs,
}

#[derive(Debug, Subcommand)]
enum ProposalArgs {
    /// Switch `name` to the segment chain at `first_segment`, from block `from_height`.
    Schedule {
        #[clap(long)]
        name: String,
        #[clap(long)]
        first_segment: AccountId,
        #[clap(long)]
        from_height: u64,
    },
    /// Withdraw `name`'s pending upgrade, if it is exactly this one.
    Cancel {
        #[clap(long)]
        name: String,
        #[clap(long)]
        first_segment: AccountId,
        #[clap(long)]
        from_height: u64,
    },
    /// Deploy a new system program `name` from the segment chain at `first_segment`.
    Install {
        #[clap(long)]
        name: String,
        #[clap(long)]
        first_segment: AccountId,
    },
}

impl ProposalArgs {
    fn proposal(self) -> Result<Proposal> {
        Ok(match self {
            Self::Schedule {
                name,
                first_segment,
                from_height,
            } => Proposal::Schedule {
                name: parse_name(&name)?,
                first_segment,
                from_height,
            },
            Self::Cancel {
                name,
                first_segment,
                from_height,
            } => Proposal::Cancel {
                name: parse_name(&name)?,
                first_segment,
                from_height,
            },
            Self::Install {
                name,
                first_segment,
            } => Proposal::Install {
                name: parse_name(&name)?,
                first_segment,
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

#[expect(
    clippy::print_stdout,
    reason = "the signed approval on stdout is this binary's output"
)]
fn main() -> Result<()> {
    let Args {
        config_path,
        home,
        valid_until,
        proposal,
    } = Args::parse();

    let config = sequencer_service::SequencerConfig::from_path(&config_path)?;
    let home = home.unwrap_or(config.home);
    let key = sequencer_core::load_signing_key(&home.join("bedrock_signing_key"))?;
    let channel_id: [u8; 32] = config.bedrock_config.channel_id.into();

    let proposal = proposal.proposal()?;
    let message = system_upgrader_core::approval_message(channel_id, &proposal, valid_until);
    let signed = SignedApproval {
        proposal,
        approval: Approval {
            signer: SequencerKey::new(key.public_key().to_bytes())
                .ok_or_else(|| anyhow::anyhow!("the signing key is not a valid sequencer key"))?,
            valid_until,
            signature: key.sign_payload(&message).to_bytes().to_vec(),
        },
    };
    println!("{}", hex::encode(borsh::to_vec(&signed)?));

    Ok(())
}
