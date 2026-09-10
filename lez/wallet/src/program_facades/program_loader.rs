use anyhow::{Context as _, Result, bail};
use common::HashType;
use lee::{AccountId, program::Program};
use lee_core::program::PROGRAM_LOADER_ACCOUNT_ID;
use program_loader_core::{Instruction, MAX_PROGRAM_SEGMENTS, MAX_SEGMENT_DATA_LEN};

use crate::{AccountIdentity, ExecutionFailureKind, WalletCore};

/// Facade for `program_loader`'s `WriteSegment`/`CreateHeader`/`UpdateHeader` instructions.
///
/// Every account (segment, header) is caller-supplied — no key generation happens here. Callers
/// create accounts first via the ordinary `account new public` flow, the same way every other
/// program-facing command takes accounts as `AccountId`s rather than conjuring them.
pub struct ProgramLoader<'wallet>(pub &'wallet WalletCore);

impl ProgramLoader<'_> {
    /// Sends a `program_loader` instruction over `accounts`, paid by `payer` if given.
    ///
    /// A deploy's account list holds nothing but the brand-new accounts it is claiming, so there
    /// is never a funded account for self-pay to find: `payer` names a separately-funded account
    /// that co-signs without joining the instruction's account list (see
    /// [`WalletCore::send_pub_tx_with_pre_check`]).
    async fn send(
        &self,
        accounts: Vec<AccountIdentity>,
        instruction_data: lee_core::program::InstructionData,
        payer: Option<AccountId>,
    ) -> Result<HashType, ExecutionFailureKind> {
        self.0
            .send_pub_tx_paid_by(accounts, instruction_data, PROGRAM_LOADER_ACCOUNT_ID, payer)
            .await
    }

    /// Writes one bytecode segment at `target` (must already be a default/unclaimed account,
    /// signed for by `target`'s own key — writing an unowned account's data is itself the claim,
    /// so no separate authorization is required). `next_segment`, if present, must already hold a
    /// valid segment — chains are always linked tail-to-head. See [`Self::send`] for `payer`.
    pub async fn write_segment(
        &self,
        target: AccountId,
        bytecode: Vec<u8>,
        next_segment: Option<AccountId>,
        payer: Option<AccountId>,
    ) -> Result<HashType, ExecutionFailureKind> {
        if let Some(next_segment_id) = next_segment {
            let next_segment_acc = self
                .0
                .get_account_public(next_segment_id)
                .await
                .map_err(ExecutionFailureKind::SequencerError)?;
            if next_segment_acc.program_owner != PROGRAM_LOADER_ACCOUNT_ID
                || program_loader_core::ProgramSegment::from_bytes(&next_segment_acc.data).is_none()
            {
                return Err(ExecutionFailureKind::AccountDataError(next_segment_id));
            }
        }

        let instruction = Instruction::WriteSegment {
            bytecode,
            next_segment,
        };
        let instruction_data =
            Program::serialize_instruction(instruction).expect("Instruction should serialize");

        let mut accounts = vec![AccountIdentity::Public(target)];
        accounts.extend(next_segment.map(AccountIdentity::PublicNoSign));

        self.send(accounts, instruction_data, payer).await
    }

    /// Creates a new program header at `target` (must already be a default/unclaimed account,
    /// signed for by `target`'s own key). The header stores only the id of the chain's head
    /// segment account; `chain_segment_ids` (head included) lets `program_loader` verify the
    /// chain and derive `image_id` itself. See [`Self::send`] for `payer`.
    pub async fn create_header(
        &self,
        target: AccountId,
        first_segment: AccountId,
        chain_segment_ids: &[AccountId],
        immutable: bool,
        payer: Option<AccountId>,
    ) -> Result<HashType, ExecutionFailureKind> {
        let instruction = Instruction::CreateHeader {
            first_segment,
            immutable,
        };
        let instruction_data =
            Program::serialize_instruction(instruction).expect("Instruction should serialize");

        let mut accounts = vec![AccountIdentity::Public(target)];
        accounts.extend(
            chain_segment_ids
                .iter()
                .copied()
                .map(AccountIdentity::PublicNoSign),
        );

        self.send(accounts, instruction_data, payer).await
    }

    /// Rewrites an existing header at `header` — an ordinary `is_authorized`-gated data
    /// mutation, so `header`'s own (still-authorized) key must sign. Same
    /// `chain_segment_ids`/`image_id` handling as [`Self::create_header`]; see [`Self::send`] for
    /// `payer`.
    pub async fn update_header(
        &self,
        header: AccountId,
        first_segment: AccountId,
        chain_segment_ids: &[AccountId],
        immutable: bool,
        payer: Option<AccountId>,
    ) -> Result<HashType, ExecutionFailureKind> {
        let instruction = Instruction::UpdateHeader {
            first_segment,
            immutable,
        };
        let instruction_data =
            Program::serialize_instruction(instruction).expect("Instruction should serialize");

        let mut accounts = vec![AccountIdentity::Public(header)];
        accounts.extend(
            chain_segment_ids
                .iter()
                .copied()
                .map(AccountIdentity::PublicNoSign),
        );

        self.send(accounts, instruction_data, payer).await
    }

    /// Chunks `bytecode` into `segments.len()` pieces (must match exactly — this never
    /// auto-generates or drops segment accounts) and uploads them tail-to-head, one signed
    /// `WriteSegment` transaction per chunk, waiting for each to land before submitting the next
    /// (a `WriteSegment`'s optional `next_segment` `pre_state` must already exist on-chain). Then
    /// uploads `header` pointing at the resulting chain. Returns the header's `AccountId`. See
    /// [`Self::send`] for `payer`.
    pub async fn deploy(
        &self,
        header: AccountId,
        segments: &[AccountId],
        bytecode: Vec<u8>,
        immutable: bool,
        payer: Option<AccountId>,
    ) -> Result<AccountId> {
        self.upload_segments_and_header(header, segments, bytecode, immutable, false, payer)
            .await?;
        Ok(header)
    }

    /// Like [`Self::deploy`], but signs the final step with `UpdateHeader` against an existing
    /// header account instead of claiming a new one. Segments are always freshly uploaded —
    /// segments are write-once, so there's no reuse of a prior chain.
    ///
    /// FIXME: the previous chain's segment accounts are never reclaimed, so they accumulate
    /// across updates. Consider addressing alongside resumable uploads.
    pub async fn update(
        &self,
        header: AccountId,
        segments: &[AccountId],
        bytecode: Vec<u8>,
        immutable: bool,
        payer: Option<AccountId>,
    ) -> Result<()> {
        self.upload_segments_and_header(header, segments, bytecode, immutable, true, payer)
            .await
    }

    async fn upload_segments_and_header(
        &self,
        header: AccountId,
        segments: &[AccountId],
        bytecode: Vec<u8>,
        immutable: bool,
        update_existing_header: bool,
        payer: Option<AccountId>,
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

        // FIXME: a partial failure here leaves landed segments claimed and write-once, so
        // retrying with the same `segments` list fails instead of resuming. Consider making this
        // resumable.
        for i in (0..chunks.len()).rev() {
            let next_segment = segments.get(i.saturating_add(1)).copied();
            let tx_hash = self
                .write_segment(segments[i], chunks[i].to_vec(), next_segment, payer)
                .await
                .with_context(|| format!("failed to upload segment {i}"))?;
            self.0
                .poll_and_finalize_public_transaction(tx_hash)
                .await
                .with_context(|| format!("segment {i} transaction did not finalize"))?;
        }

        let first_segment = segments[0];
        let tx_hash = if update_existing_header {
            self.update_header(header, first_segment, segments, immutable, payer)
                .await
                .context("failed to update header")?
        } else {
            self.create_header(header, first_segment, segments, immutable, payer)
                .await
                .context("failed to create header")?
        };
        self.0
            .poll_and_finalize_public_transaction(tx_hash)
            .await
            .context("header transaction did not finalize")?;

        Ok(())
    }

    /// Walks a segment chain from `first_segment` via the network, following `next_segment`
    /// until `None`. Used by the standalone `CreateHeader`/`UpdateHeader` entry points, which
    /// only take `first_segment` from the caller rather than the whole chain (unlike
    /// [`Self::deploy`]/[`Self::update`], which already have it from their own `segments` arg).
    pub async fn resolve_chain(&self, first_segment: AccountId) -> Result<Vec<AccountId>> {
        let mut chain = Vec::new();
        let mut next = Some(first_segment);
        while let Some(id) = next {
            if chain.len() >= MAX_PROGRAM_SEGMENTS {
                bail!(
                    "segment chain from {first_segment} did not terminate within \
                     {MAX_PROGRAM_SEGMENTS} hops"
                );
            }
            let account = self
                .0
                .get_account_public(id)
                .await
                .with_context(|| format!("failed to fetch segment account {id}"))?;
            let segment = program_loader_core::ProgramSegment::from_bytes(&account.data)
                .with_context(|| format!("account {id} does not hold a valid program segment"))?;
            chain.push(id);
            next = segment.next_segment;
        }
        Ok(chain)
    }
}
