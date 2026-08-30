use anyhow::{Context as _, Result, bail};
use common::HashType;
use lee::{AccountId, program::Program};
use lee_core::program::PROGRAM_LOADER_ACCOUNT_ID;
use program_loader_core::{Instruction, MAX_SEGMENT_DATA_LEN};

use crate::{AccountIdentity, ExecutionFailureKind, WalletCore};

/// Facade for `program_loader`'s `NewSegment`/`UploadHeader`/`UpdateHeader` instructions.
///
/// Every account (segment, header) is caller-supplied — no key generation happens here. Callers
/// create accounts first via the ordinary `account new public` flow, the same way every other
/// program-facing command takes accounts as `AccountId`s rather than conjuring them.
pub struct ProgramLoader<'wallet>(pub &'wallet WalletCore);

impl ProgramLoader<'_> {
    /// Writes one bytecode segment at `target` (must already be a default/unclaimed account,
    /// signed for by `target`'s own key). `next_segment`, if present, must already hold a valid
    /// segment — chains are always linked tail-to-head.
    pub async fn new_segment(
        &self,
        target: AccountId,
        bytecode: Vec<u8>,
        next_segment: Option<AccountId>,
    ) -> Result<HashType, ExecutionFailureKind> {
        let instruction = Instruction::NewSegment {
            bytecode,
            next_segment,
        };
        let instruction_data =
            Program::serialize_instruction(instruction).expect("Instruction should serialize");

        let mut accounts = vec![AccountIdentity::Public(target)];
        accounts.extend(next_segment.map(AccountIdentity::PublicNoSign));

        self.0
            .send_pub_tx_to_account(accounts, instruction_data, PROGRAM_LOADER_ACCOUNT_ID)
            .await
    }

    /// Creates a new program header at `target` (must already be a default/unclaimed account,
    /// signed for by `target`'s own key) pointing at `chain` — the entire segment chain, in link
    /// order, starting at `first_segment`. `image_id` is always recomputed from the chain by
    /// `program_loader`, never trusted from the caller.
    pub async fn upload_header(
        &self,
        target: AccountId,
        first_segment: AccountId,
        chain: &[AccountId],
        immutable: bool,
    ) -> Result<HashType, ExecutionFailureKind> {
        let instruction = Instruction::UploadHeader {
            first_segment,
            immutable,
        };
        let instruction_data =
            Program::serialize_instruction(instruction).expect("Instruction should serialize");

        let mut accounts = vec![AccountIdentity::Public(target)];
        accounts.extend(chain.iter().copied().map(AccountIdentity::PublicNoSign));

        self.0
            .send_pub_tx_to_account(accounts, instruction_data, PROGRAM_LOADER_ACCOUNT_ID)
            .await
    }

    /// Rewrites an existing header at `header` — an ordinary `is_authorized`-gated data
    /// mutation, so `header`'s own (still-authorized) key must sign. Same chain/`image_id`
    /// handling as [`Self::upload_header`].
    pub async fn update_header(
        &self,
        header: AccountId,
        first_segment: AccountId,
        chain: &[AccountId],
        immutable: bool,
    ) -> Result<HashType, ExecutionFailureKind> {
        let instruction = Instruction::UpdateHeader {
            first_segment,
            immutable,
        };
        let instruction_data =
            Program::serialize_instruction(instruction).expect("Instruction should serialize");

        let mut accounts = vec![AccountIdentity::Public(header)];
        accounts.extend(chain.iter().copied().map(AccountIdentity::PublicNoSign));

        self.0
            .send_pub_tx_to_account(accounts, instruction_data, PROGRAM_LOADER_ACCOUNT_ID)
            .await
    }

    /// Chunks `bytecode` into `segments.len()` pieces (must match exactly — this never
    /// auto-generates or drops segment accounts) and uploads them tail-to-head, one signed
    /// `NewSegment` transaction per chunk, waiting for each to land before submitting the next
    /// (a `NewSegment`'s optional `next_segment` pre_state must already exist on-chain). Then
    /// uploads `header` pointing at the resulting chain. Returns the header's `AccountId`.
    pub async fn deploy(
        &self,
        header: AccountId,
        segments: &[AccountId],
        bytecode: Vec<u8>,
        immutable: bool,
    ) -> Result<AccountId> {
        self.upload_segments_and_header(header, segments, bytecode, immutable, false)
            .await?;
        Ok(header)
    }

    /// Like [`Self::deploy`], but signs the final step with `UpdateHeader` against an existing
    /// header account instead of claiming a new one. Segments are always freshly uploaded —
    /// segments are write-once, so there's no reuse of a prior chain.
    pub async fn update(
        &self,
        header: AccountId,
        segments: &[AccountId],
        bytecode: Vec<u8>,
        immutable: bool,
    ) -> Result<()> {
        self.upload_segments_and_header(header, segments, bytecode, immutable, true)
            .await
    }

    async fn upload_segments_and_header(
        &self,
        header: AccountId,
        segments: &[AccountId],
        bytecode: Vec<u8>,
        immutable: bool,
        update_existing_header: bool,
    ) -> Result<()> {
        if bytecode.is_empty() {
            bail!("program bytecode must not be empty");
        }
        let chunks: Vec<&[u8]> = bytecode.chunks(MAX_SEGMENT_DATA_LEN).collect();
        if chunks.len() != segments.len() {
            return Err(ExecutionFailureKind::SegmentCountMismatch {
                expected: chunks.len(),
                actual: segments.len(),
            }
            .into());
        }

        for i in (0..chunks.len()).rev() {
            let next_segment = segments.get(i + 1).copied();
            let tx_hash = self
                .new_segment(segments[i], chunks[i].to_vec(), next_segment)
                .await
                .with_context(|| format!("failed to upload segment {i}"))?;
            self.0
                .poll_and_finalize_public_transaction(tx_hash)
                .await
                .with_context(|| format!("segment {i} transaction did not finalize"))?;
        }

        let first_segment = segments[0];
        let tx_hash = if update_existing_header {
            self.update_header(header, first_segment, segments, immutable)
                .await
                .context("failed to update header")?
        } else {
            self.upload_header(header, first_segment, segments, immutable)
                .await
                .context("failed to upload header")?
        };
        self.0
            .poll_and_finalize_public_transaction(tx_hash)
            .await
            .context("header transaction did not finalize")?;

        Ok(())
    }

    /// Walks a segment chain from `first_segment` via the network, following `next_segment`
    /// until `None`. Used by the standalone `UploadHeader`/`UpdateHeader` entry points, which
    /// only take `first_segment` from the caller rather than the whole chain (unlike
    /// [`Self::deploy`]/[`Self::update`], which already have it from their own `segments` arg).
    pub async fn resolve_chain(&self, first_segment: AccountId) -> Result<Vec<AccountId>> {
        let mut chain = Vec::new();
        let mut next = Some(first_segment);
        while let Some(id) = next {
            let account = self
                .0
                .get_account_public(id)
                .await
                .with_context(|| format!("failed to fetch segment account {id}"))?;
            let segment = program_loader_core::ProgramSegment::try_from(&account.data)
                .map_err(|_| anyhow::anyhow!("account {id} does not hold a valid program segment"))?;
            chain.push(id);
            next = segment.next_segment;
        }
        Ok(chain)
    }
}
