use std::path::PathBuf;

use anyhow::{Context as _, Result, bail};
use clap::Subcommand;
use lee::AccountId;

use crate::{
    WalletCore,
    account::AccountIdWithPrivacy,
    cli::{CliAccountMention, SubcommandReturnValue, WalletSubcommand},
    program_facades::program_loader::ProgramLoader,
};

/// Represents CLI subcommand for interacting with `program_loader` (deploying and updating
/// programs stored as a linked, arbitrarily-addressed segment chain).
///
/// Every account (header, each segment) is an explicit argument — this never generates keys on
/// its own. Create them first with `wallet account new public --label ...`.
#[derive(Subcommand, Debug, Clone)]
pub enum ProgramLoaderSubcommand {
    /// Write one bytecode segment. Low-level primitive: `Deploy`/`Update` handle a whole
    /// program's segments in one call.
    NewSegment {
        /// The (unclaimed) account to write the segment to.
        #[arg(long)]
        target: CliAccountMention,
        /// File containing this segment's raw bytecode chunk.
        #[arg(long)]
        bytecode_file: PathBuf,
        /// The next segment in the chain, if any (chains are linked tail-to-head, so this must
        /// already exist).
        #[arg(long)]
        next_segment: Option<AccountId>,
    },
    /// Create a new program header pointing at an already-uploaded segment chain. Low-level
    /// primitive: `Deploy` handles segment upload + header creation together.
    UploadHeader {
        /// The (unclaimed) account to write the header to.
        #[arg(long)]
        target: CliAccountMention,
        /// The first segment of the chain this header should point at. The rest of the chain is
        /// resolved automatically by following `next_segment` over the network.
        #[arg(long)]
        first_segment: AccountId,
        /// Whether the deployed program self-declares as immutable (not protocol-enforced).
        #[arg(long)]
        immutable: bool,
    },
    /// Rewrite an existing header to point at a different (already-uploaded) segment chain.
    /// Low-level primitive: `Update` handles segment upload + header rewrite together.
    UpdateHeader {
        /// The existing header account. Must already be authorized by this wallet.
        #[arg(long)]
        header: CliAccountMention,
        /// The first segment of the new chain this header should point at.
        #[arg(long)]
        first_segment: AccountId,
        /// Whether the deployed program self-declares as immutable (not protocol-enforced).
        #[arg(long)]
        immutable: bool,
    },
    /// Deploy a new program: chunk `elf`, upload one segment per account in `segments` (in
    /// order), then create `header` pointing at the resulting chain.
    ///
    /// The number of `segments` must exactly match the number of chunks `elf` splits into.
    Deploy {
        /// Path to the program's compiled ELF binary.
        #[arg(long)]
        elf: PathBuf,
        /// The (unclaimed) account to create the header at.
        #[arg(long)]
        header: CliAccountMention,
        /// The (unclaimed) accounts to write segments to, in chain order (first chunk first).
        #[arg(long, num_args = 1..)]
        segments: Vec<CliAccountMention>,
        /// Whether the deployed program self-declares as immutable (not protocol-enforced).
        #[arg(long)]
        immutable: bool,
    },
    /// Update an existing program in place: chunk `elf`, upload a fresh set of segments (segments
    /// are write-once, so a new chain is always created), then rewrite `header` to point at it.
    ///
    /// The number of `segments` must exactly match the number of chunks `elf` splits into.
    Update {
        /// Path to the program's new compiled ELF binary.
        #[arg(long)]
        elf: PathBuf,
        /// The existing header account. Must already be authorized by this wallet.
        #[arg(long)]
        header: CliAccountMention,
        /// The (unclaimed) accounts to write the new segments to, in chain order.
        #[arg(long, num_args = 1..)]
        segments: Vec<CliAccountMention>,
        /// Whether the deployed program self-declares as immutable (not protocol-enforced).
        #[arg(long)]
        immutable: bool,
    },
}

impl ProgramLoaderSubcommand {
    async fn handle_new_segment(
        target: CliAccountMention,
        bytecode_file: PathBuf,
        next_segment: Option<AccountId>,
        wallet_core: &WalletCore,
    ) -> Result<SubcommandReturnValue> {
        let target_id = resolve_public(&target, wallet_core)?;
        let bytecode = std::fs::read(&bytecode_file).with_context(|| {
            format!("failed to read segment bytecode at {}", bytecode_file.display())
        })?;

        let tx_hash = ProgramLoader(wallet_core)
            .new_segment(target_id, bytecode, next_segment)
            .await?;

        println!("Segment uploaded at {target_id}");
        wallet_core
            .poll_and_finalize_public_transaction(tx_hash)
            .await
    }

    async fn handle_upload_header(
        target: CliAccountMention,
        first_segment: AccountId,
        immutable: bool,
        wallet_core: &WalletCore,
    ) -> Result<SubcommandReturnValue> {
        let target_id = resolve_public(&target, wallet_core)?;
        let chain = ProgramLoader(wallet_core).resolve_chain(first_segment).await?;

        let tx_hash = ProgramLoader(wallet_core)
            .upload_header(target_id, first_segment, &chain, immutable)
            .await?;

        println!("Header uploaded at {target_id}");
        wallet_core
            .poll_and_finalize_public_transaction(tx_hash)
            .await
    }

    async fn handle_update_header(
        header: CliAccountMention,
        first_segment: AccountId,
        immutable: bool,
        wallet_core: &WalletCore,
    ) -> Result<SubcommandReturnValue> {
        let header_id = resolve_public(&header, wallet_core)?;
        let chain = ProgramLoader(wallet_core).resolve_chain(first_segment).await?;

        let tx_hash = ProgramLoader(wallet_core)
            .update_header(header_id, first_segment, &chain, immutable)
            .await?;

        println!("Header {header_id} updated");
        wallet_core
            .poll_and_finalize_public_transaction(tx_hash)
            .await
    }

    async fn handle_deploy(
        elf: PathBuf,
        header: CliAccountMention,
        segments: Vec<CliAccountMention>,
        immutable: bool,
        wallet_core: &WalletCore,
    ) -> Result<SubcommandReturnValue> {
        let header_id = resolve_public(&header, wallet_core)?;
        let segment_ids = segments
            .iter()
            .map(|mention| resolve_public(mention, wallet_core))
            .collect::<Result<Vec<_>>>()?;
        let bytecode = std::fs::read(&elf)
            .with_context(|| format!("failed to read program binary at {}", elf.display()))?;

        let account_id = ProgramLoader(wallet_core)
            .deploy(header_id, &segment_ids, bytecode, immutable)
            .await?;

        println!("Program deployed. Header account id: {account_id}");
        Ok(SubcommandReturnValue::RegisterAccount { account_id })
    }

    async fn handle_update(
        elf: PathBuf,
        header: CliAccountMention,
        segments: Vec<CliAccountMention>,
        immutable: bool,
        wallet_core: &WalletCore,
    ) -> Result<SubcommandReturnValue> {
        let header_id = resolve_public(&header, wallet_core)?;
        let segment_ids = segments
            .iter()
            .map(|mention| resolve_public(mention, wallet_core))
            .collect::<Result<Vec<_>>>()?;
        let bytecode = std::fs::read(&elf)
            .with_context(|| format!("failed to read program binary at {}", elf.display()))?;

        ProgramLoader(wallet_core)
            .update(header_id, &segment_ids, bytecode, immutable)
            .await?;

        println!("Program {header_id} updated");
        Ok(SubcommandReturnValue::RegisterAccount {
            account_id: header_id,
        })
    }
}

impl WalletSubcommand for ProgramLoaderSubcommand {
    async fn handle_subcommand(
        self,
        wallet_core: &mut WalletCore,
    ) -> Result<SubcommandReturnValue> {
        match self {
            Self::NewSegment {
                target,
                bytecode_file,
                next_segment,
            } => Self::handle_new_segment(target, bytecode_file, next_segment, wallet_core).await,
            Self::UploadHeader {
                target,
                first_segment,
                immutable,
            } => Self::handle_upload_header(target, first_segment, immutable, wallet_core).await,
            Self::UpdateHeader {
                header,
                first_segment,
                immutable,
            } => Self::handle_update_header(header, first_segment, immutable, wallet_core).await,
            Self::Deploy {
                elf,
                header,
                segments,
                immutable,
            } => Self::handle_deploy(elf, header, segments, immutable, wallet_core).await,
            Self::Update {
                elf,
                header,
                segments,
                immutable,
            } => Self::handle_update(elf, header, segments, immutable, wallet_core).await,
        }
    }
}

fn resolve_public(mention: &CliAccountMention, wallet_core: &WalletCore) -> Result<AccountId> {
    match mention.resolve(wallet_core.storage())? {
        AccountIdWithPrivacy::Public(account_id) => Ok(account_id),
        AccountIdWithPrivacy::Private(_) => {
            bail!("program_loader accounts must be public, not private")
        }
    }
}
