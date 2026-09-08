use anyhow::{Context as _, Result, bail};
use common::HashType;
use lee::{AccountId, ProgramShardSelector, PublicKey, Signature, program::Program};
use lee_core::program::PROGRAM_LOADER_ACCOUNT_ID;
use program_loader_core::{Instruction, MAX_PROGRAM_SEGMENTS, MAX_SEGMENT_DATA_LEN};

use crate::{
    AccountIdentity, AccountMention, DEFAULT_GAS_LIMIT, DEFAULT_MAX_FEE, ExecutionFailureKind,
    WalletCore, account_manager::AccountManager,
};

/// Facade for `program_loader`'s `WriteSegment`/`CreateHeader`/`UpdateHeader` instructions.
///
/// Every account (segment, header) is caller-supplied — no key generation happens here. Callers
/// create accounts first via the ordinary `account new public` flow, the same way every other
/// program-facing command takes accounts as `AccountId`s rather than conjuring them.
pub struct ProgramLoader<'wallet>(pub &'wallet WalletCore);

impl ProgramLoader<'_> {
    /// Sends a `program_loader` instruction over `accounts`, paid by `payer` if given.
    ///
    /// An explicit payer adds a signature and nonce without changing the loader's account list.
    /// With no payer, [`WalletCore::send_pub_tx`] selects a payer from the signing accounts.
    async fn send(
        &self,
        accounts: Vec<AccountMention>,
        instruction_data: lee_core::program::InstructionData,
        payer: Option<AccountId>,
    ) -> Result<HashType, ExecutionFailureKind> {
        let Some(payer) = payer else {
            return self
                .0
                .send_pub_tx(accounts, instruction_data, PROGRAM_LOADER_ACCOUNT_ID)
                .await;
        };

        if accounts.iter().any(|mention| mention.identity.is_private()) {
            return Err(ExecutionFailureKind::TransactionBuildError(
                lee::error::LeeError::InvalidInput(
                    "Private accounts are not allowed in public transactions".to_owned(),
                ),
            ));
        }

        let acc_manager = AccountManager::new(self.0, accounts).await?;
        let shard_selectors = acc_manager.shard_selectors();
        let mut nonces = acc_manager.public_account_nonces();

        let payer_account = self
            .0
            .get_account_view(ProgramShardSelector::balance_only(payer))
            .await
            .map_err(ExecutionFailureKind::SequencerError)?;
        let payer_key = self
            .0
            .get_account_public_signing_key(payer)
            .ok_or_else(|| {
                ExecutionFailureKind::TransactionBuildError(lee::error::LeeError::InvalidInput(
                    "Fee payer's signing key is not held by this wallet".to_owned(),
                ))
            })?;
        // Appended last, after every regular signer `sign_message` produces — nonces and
        // signatures must line up positionally (see `AccountManager::public_account_nonces`).
        nonces.push(payer_account.nonce);

        let message = lee::public_transaction::Message::new_preserialized(
            PROGRAM_LOADER_ACCOUNT_ID,
            shard_selectors,
            nonces,
            instruction_data,
            Some(lee::FeeDeclaration::new(
                payer,
                DEFAULT_GAS_LIMIT,
                0,
                DEFAULT_MAX_FEE,
            )),
        );

        let message_hash = message.hash();
        let mut signatures_public_keys = acc_manager
            .sign_message(message_hash)
            .map_err(ExecutionFailureKind::SignError)?;
        signatures_public_keys.push((
            Signature::new(payer_key, &message_hash),
            PublicKey::new_from_private_key(payer_key),
        ));
        let witness_set =
            lee::public_transaction::WitnessSet::from_raw_parts(signatures_public_keys);

        let tx = lee::public_transaction::PublicTransaction::new(message, witness_set);
        self.0.submit_public_transaction(tx).await
    }

    /// Writes one bytecode segment to `target`'s empty loader shard.
    /// `next_segment`, if given, must already contain a valid segment.
    /// See [`Self::send`] for `payer`.
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
                .get_account_view(ProgramShardSelector::new(
                    next_segment_id,
                    PROGRAM_LOADER_ACCOUNT_ID,
                ))
                .await
                .map_err(ExecutionFailureKind::SequencerError)?;
            if program_loader_core::ProgramSegment::from_bytes(
                next_segment_acc.data.shard(PROGRAM_LOADER_ACCOUNT_ID),
            )
            .is_none()
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

        let mut accounts =
            vec![AccountIdentity::Public(target).select_program_shard(PROGRAM_LOADER_ACCOUNT_ID)];
        accounts.extend(next_segment.map(|id| {
            AccountIdentity::PublicNoSign(id).select_program_shard(PROGRAM_LOADER_ACCOUNT_ID)
        }));

        self.send(accounts, instruction_data, payer).await
    }

    /// Creates a program header in `target`'s empty loader shard.
    /// `chain_segment_ids` lists the chain in order, including `first_segment`,
    /// so the loader can verify it and compute the image ID. See [`Self::send`] for `payer`.
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

        let mut accounts =
            vec![AccountIdentity::Public(target).select_program_shard(PROGRAM_LOADER_ACCOUNT_ID)];
        accounts.extend(chain_segment_ids.iter().copied().map(|id| {
            AccountIdentity::PublicNoSign(id).select_program_shard(PROGRAM_LOADER_ACCOUNT_ID)
        }));

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

        let mut accounts =
            vec![AccountIdentity::Public(header).select_program_shard(PROGRAM_LOADER_ACCOUNT_ID)];
        accounts.extend(chain_segment_ids.iter().copied().map(|id| {
            AccountIdentity::PublicNoSign(id).select_program_shard(PROGRAM_LOADER_ACCOUNT_ID)
        }));

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

        // FIXME: Resume after a partial upload; retrying the same segments currently fails.
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
                .get_account_view(ProgramShardSelector::new(id, PROGRAM_LOADER_ACCOUNT_ID))
                .await
                .with_context(|| format!("failed to fetch segment account {id}"))?;
            let segment = program_loader_core::ProgramSegment::from_bytes(
                account.data.shard(PROGRAM_LOADER_ACCOUNT_ID),
            )
            .with_context(|| format!("account {id} does not hold a valid program segment"))?;
            chain.push(id);
            next = segment.next_segment;
        }
        Ok(chain)
    }
}
