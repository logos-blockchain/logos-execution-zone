use borsh::{BorshDeserialize, BorshSerialize};
pub use lee_core::program::{PdaSeed, ProgramData, UNFINALIZED_IMAGE_ID};
use lee_core::{
    account::{Account, AccountId, AccountWithMetadata, Data},
    program::{AccountPostState, Claim, DEFAULT_PROGRAM_OWNER, ProgramId},
};

const DEPLOY_HEADER_SEED_DOMAIN_SEPARATOR: AccountId =
    AccountId::new(*b"/LEZ/v0.3/LoaderDeployHeaderSeed");
const DEPLOY_SEGMENT_SEED_DOMAIN_SEPARATOR: AccountId =
    AccountId::new(*b"/LEZ/v0.3/LoaderDeploySegmentSee");

/// The RISC0 platform/syscall kernel every guest in this codebase runs under.
///
/// A function of the RISC0 toolchain version (pinned via `Justfile`'s
/// `RISC0_DOCKER_CONTAINER_TAG`), not of any individual program. Verified byte-identical across
/// every guest artifact currently built in this repo, so a `Deploy`'s `user_elf` never needs to
/// carry it: `execute_deploy` assumes this exact kernel and reconstructs the full two-ELF binary
/// from it, rather than storing (and transmitting) ~32KB of fully redundant bytes on every single
/// deployment.
const KERNEL_ELF: &[u8] = include_bytes!("kernel.bin");

/// Max bytes of `user_elf` one segment account's `Data` may hold.
///
/// Comfortably under `DATA_MAX_LENGTH` (100 KiB), with headroom for future per-segment framing;
/// yields 4-6 segments for a typical 340-490 KB `user_elf`.
pub const MAX_SEGMENT_DATA_LEN: usize = 96 * 1024;

#[derive(BorshSerialize, BorshDeserialize)]
pub enum Instruction {
    /// Deploys or upgrades a program, in whole or in part: writes the bytecode segments this
    /// transaction's `raw_payload` covers, each claimed (or, for an upgrade, overwritten) as a
    /// PDA of the loader, and — for a brand-new program, delivered in one self-contained
    /// transaction — its `ProgramData` header too. One or more `Deploy`s (each covering a
    /// contiguous range of segments) complete a deployment or an upgrade; a non-self-contained
    /// one always needs a following [`Instruction::Finalize`] before the program is
    /// dispatchable again.
    ///
    /// The bytecode itself travels via the dispatching message's `raw_payload`, not this
    /// instruction.
    ///
    /// Required accounts, in order:
    /// - The target `ProgramData` header PDA account (`Account::default()` for a program's very
    ///   first `Deploy`, or its already-existing header for any later batch, continuation, or
    ///   upgrade)
    /// - Unless this transaction is both self-contained *and* the program's very first `Deploy`: an
    ///   account matching the authority that must sign this write, `is_authorized`
    /// - The target segment PDA accounts this transaction covers (`first_segment, first_segment+1,
    ///   ...`), in order — each `Account::default()` for a program's first deploy, or (for an
    ///   upgrade) either `Account::default()` or already-populated
    Deploy {
        /// The program's genesis identity — `Some` only on a program's very first `Deploy`
        /// (when the header doesn't exist yet, so there's nowhere else to read it from), and
        /// `None` on every later batch, continuation, or upgrade. The native logic *never*
        /// trusts a caller's own claim about a program's genesis pair once its header already
        /// exists — it reads `ProgramData::genesis_image_id`/`genesis_update_auth` straight out
        /// of the header's own account data instead, so there's no way for a transaction to even
        /// declare a wrong or stale genesis pair for an existing program.
        genesis: Option<Genesis>,
        /// `segment_number` of this transaction's first segment (0-indexed); its remaining
        /// segment accounts are `first_segment, first_segment+1, ...` in order.
        first_segment: u32,
        /// Total segment count as of *this* write. Caller-declared: a transaction covering only
        /// part of the program can't derive it from its own fragment. Must be identical across
        /// every batch of one write (initial deploy or upgrade); may differ from the program's
        /// previous `segment_count` on an upgrade that grows or shrinks the bytecode.
        segment_count: u32,
    },
    /// Reconstructs the program from all of its current segments (`0..segment_count`, per the
    /// header), recomputes the real `image_id`, and writes it as `ProgramData::current_image_id`
    /// — the only way back to a dispatchable program once any [`Instruction::Deploy`] batch has
    /// left it at the `UNFINALIZED_IMAGE_ID` sentinel (an in-progress initial deploy, or any
    /// upgrade at all). Bumps `ProgramData::program_version` by one.
    ///
    /// Required accounts, in order: the header (must already exist and hold
    /// `UNFINALIZED_IMAGE_ID` — nothing to finalize otherwise), an account matching the header's
    /// *current* `update_auth`, `is_authorized`, then every segment `0..segment_count` in order.
    Finalize,
    /// Changes `ProgramData::update_auth` to `new_update_auth`. Never touches
    /// `genesis_update_auth` (so PDA addresses are unaffected by any number of rotations),
    /// `current_image_id`, or `program_version` (rotation is an authority change, not a bytecode
    /// change).
    ///
    /// Required accounts, in order: the header (must already exist), an account matching the
    /// header's *current* `update_auth`, `is_authorized`, and — only when `new_update_auth` is
    /// `Some` — an account matching it, also `is_authorized`.
    RotateUpdateAuth {
        /// `Some` for a normal co-signed handoff (both the current and the new authority must
        /// sign, so authority can never be pointed at an account nobody actually controls).
        /// `None` deliberately and permanently renounces upgrade authority — a one-way
        /// transition to immutable, requiring only the current authority's signature, since
        /// there's no new account to co-sign on the other end.
        new_update_auth: Option<AccountId>,
    },
}

/// A program's genesis identity — the address-derivation salt fixed forever at its first
/// `Deploy`.
#[derive(Clone, Copy, BorshSerialize, BorshDeserialize)]
pub struct Genesis {
    pub image_id: ProgramId,
    /// `None` means immutable from birth.
    pub update_auth: Option<AccountId>,
}

/// One account a `Deploy` writes: the `AccountId` it lives at, the `PdaSeed` that derives (and
/// claims) it, and the raw bytes that belong in its `Data`.
pub struct PlannedAccount {
    pub account_id: AccountId,
    pub seed: PdaSeed,
    pub data: Vec<u8>,
}

/// The full account-level shape of a deployed program: its header plus, in order, every bytecode
/// segment.
pub struct DeployPlan {
    pub header: PlannedAccount,
    pub segments: Vec<PlannedAccount>,
}

/// Extracts the program-specific `user_elf` out of a full two-ELF `ProgramBinary` blob.
///
/// `full_binary` is the format `Program::elf()` returns for every program in this codebase — the
/// inverse of [`reconstruct_program_binary`]. What a `Deploy`'s `raw_payload` should carry.
pub fn extract_user_elf(full_binary: &[u8]) -> anyhow::Result<Vec<u8>> {
    Ok(risc0_binfmt::ProgramBinary::decode(full_binary)?
        .user_elf
        .to_vec())
}

/// Rebuilds the full two-ELF `ProgramBinary` blob from just a `user_elf`, assuming [`KERNEL_ELF`].
///
/// The inverse of [`extract_user_elf`]. Byte-identical to the original full binary as long as it
/// was built with the same RISC0 toolchain (true for anything actually deployable on this
/// network, since the kernel is what makes an ELF executable here at all).
#[must_use]
pub fn reconstruct_program_binary(user_elf: &[u8]) -> Vec<u8> {
    risc0_binfmt::ProgramBinary::new(user_elf, KERNEL_ELF).encode()
}

/// Recomputes the real `image_id` for `user_elf` under the assumed [`KERNEL_ELF`].
///
/// The same derivation [`execute_deploy`]/[`finalize`] use to fix a program's identity — shared
/// here so callers (and tests) never have to duplicate this logic.
pub fn compute_image_id(user_elf: &[u8]) -> anyhow::Result<ProgramId> {
    Ok(risc0_binfmt::ProgramBinary::new(user_elf, KERNEL_ELF)
        .compute_image_id()?
        .into())
}

/// Derives the PDA seed for a deployed program's `ProgramData` header account.
///
/// Combines the program's genesis identity (`genesis_image_id`), `segment_number` (always `0`
/// for a header — unrelated to how many bytecode segments the program's data spans; kept as a
/// parameter only because it shares this shape with [`segment_pda_seed`]), and
/// `genesis_update_auth` — included so multiple independent deployments of identical bytecode
/// land at distinct accounts instead of colliding. Fixed forever once a program's header is
/// created; never re-derived from its *current* `image_id`/`update_auth`, which may change
/// across upgrades.
///
/// Domain-separated from other PDA-seed derivations in the codebase, including
/// [`segment_pda_seed`], so a header seed can never collide with a segment seed (or
/// anything else) even when the input triple coincides.
#[must_use]
pub fn header_pda_seed(
    genesis_image_id: ProgramId,
    segment_number: u32,
    genesis_update_auth: Option<AccountId>,
) -> PdaSeed {
    deploy_seed(
        DEPLOY_HEADER_SEED_DOMAIN_SEPARATOR,
        genesis_image_id,
        segment_number,
        genesis_update_auth,
    )
}

/// Derives the PDA seed for a deployed program's bytecode segment account.
///
/// Same inputs (and the same genesis-not-current caveat) as [`header_pda_seed`],
/// domain-separated so the two never collide. Kept as a distinct account from the header
/// specifically so that authenticating a program's identity (e.g. for privacy-preserving proof
/// verification) never has to touch its bytecode: the only account-authentication primitive
/// available is whole-account equality, so what's bundled into one account sets the floor for how
/// cheap that authentication can be.
#[must_use]
pub fn segment_pda_seed(
    genesis_image_id: ProgramId,
    segment_number: u32,
    genesis_update_auth: Option<AccountId>,
) -> PdaSeed {
    deploy_seed(
        DEPLOY_SEGMENT_SEED_DOMAIN_SEPARATOR,
        genesis_image_id,
        segment_number,
        genesis_update_auth,
    )
}

fn deploy_seed(
    domain_separator: AccountId,
    genesis_image_id: ProgramId,
    segment_number: u32,
    genesis_update_auth: Option<AccountId>,
) -> PdaSeed {
    use risc0_zkvm::sha::{Impl, Sha256 as _};

    let mut bytes = [0_u8; 32 + 32 + 4 + 32];
    bytes[0..32].copy_from_slice(domain_separator.as_ref());
    let image_id_bytes: &[u8] =
        bytemuck::try_cast_slice(&genesis_image_id).expect("ProgramId should be castable to &[u8]");
    bytes[32..64].copy_from_slice(image_id_bytes);
    bytes[64..68].copy_from_slice(&segment_number.to_le_bytes());
    // `None` (immutable) canonicalizes to AccountId::default()'s bytes for hashing purposes —
    // that value is already a pure "no owner" sentinel elsewhere in this codebase, never a
    // realistically-derived real account, so this introduces no meaningful collision risk.
    bytes[68..].copy_from_slice(genesis_update_auth.unwrap_or_default().as_ref());

    PdaSeed::new(
        Impl::hash_bytes(&bytes)
            .as_bytes()
            .try_into()
            .expect("Hash output must be exactly 32 bytes long"),
    )
}

#[must_use]
pub fn header_account_id(
    loader_account_id: AccountId,
    genesis_image_id: ProgramId,
    segment_number: u32,
    genesis_update_auth: Option<AccountId>,
) -> AccountId {
    AccountId::for_public_pda(
        &loader_account_id,
        &header_pda_seed(genesis_image_id, segment_number, genesis_update_auth),
    )
}

#[must_use]
pub fn segment_account_id(
    loader_account_id: AccountId,
    genesis_image_id: ProgramId,
    segment_number: u32,
    genesis_update_auth: Option<AccountId>,
) -> AccountId {
    AccountId::for_public_pda(
        &loader_account_id,
        &segment_pda_seed(genesis_image_id, segment_number, genesis_update_auth),
    )
}

/// Plans the account shape for one batch of a (possibly multi-transaction) deploy or upgrade.
///
/// Builds the header (unchanged formula — always `segment_number` 0, independent of
/// `segment_count`, so [`immutable_deploy_account_id`] stays stable regardless of how a deploy is
/// batched) plus `batch_user_elf` chunked at [`MAX_SEGMENT_DATA_LEN`], numbered `first_segment,
/// first_segment+1, ...`. `genesis_image_id`/`genesis_update_auth` are always the program's
/// genesis pair — this function only computes *addresses* (and the segment byte chunks), never
/// the header's current-state fields, since those depend on whether the header already exists.
///
/// `segment_count` is the *total* as of this write, not just this batch. [`plan_deploy`] is the
/// single-batch (whole program, `first_segment` 0) special case of this — the single source of
/// truth both [`execute_deploy`] and `V03State::insert_program` build from, so live deploys and
/// genesis-seeded programs can never diverge on chunk boundaries, ordering, or PDA derivation.
#[must_use]
pub fn plan_deploy_range(
    loader_account_id: AccountId,
    genesis_image_id: ProgramId,
    segment_count: u32,
    genesis_update_auth: Option<AccountId>,
    first_segment: u32,
    batch_user_elf: &[u8],
) -> DeployPlan {
    let header_seed = header_pda_seed(genesis_image_id, 0, genesis_update_auth);
    let header = PlannedAccount {
        account_id: AccountId::for_public_pda(&loader_account_id, &header_seed),
        seed: header_seed,
        // Only used by the fresh-header path in `execute_deploy` and by `V03State::insert_program`
        // — filled in with the real current-state fields there. Placeholder shape here just so
        // `PlannedAccount::data` always exists for the header like it does for a segment; not
        // meant to be written verbatim by an upgrade/continuation batch.
        data: Vec::new(),
    };

    // An empty program still needs exactly one (empty) segment to exist — but only when this
    // batch is the whole thing; an empty *partial* batch is a caller error execute_deploy's own
    // non-empty-batch assertion rejects, not something to paper over here.
    let chunks: Vec<&[u8]> =
        if batch_user_elf.is_empty() && first_segment == 0 && segment_count <= 1 {
            vec![&[]]
        } else {
            batch_user_elf.chunks(MAX_SEGMENT_DATA_LEN).collect()
        };

    let segments = chunks
        .into_iter()
        .enumerate()
        .map(|(i, chunk)| {
            let segment_number = first_segment
                .checked_add(u32::try_from(i).expect("segment index fits in u32"))
                .expect("segment number fits in u32");
            let seed = segment_pda_seed(genesis_image_id, segment_number, genesis_update_auth);
            PlannedAccount {
                account_id: AccountId::for_public_pda(&loader_account_id, &seed),
                seed,
                data: chunk.to_vec(),
            }
        })
        .collect();

    DeployPlan { header, segments }
}

/// Computes the account shape (header + N bytecode segments) for deploying the whole of `user_elf`
/// at `genesis_image_id` under `genesis_update_auth` in a single, self-contained batch.
#[must_use]
pub fn plan_deploy(
    loader_account_id: AccountId,
    genesis_image_id: ProgramId,
    genesis_update_auth: Option<AccountId>,
    user_elf: &[u8],
) -> DeployPlan {
    let segment_count = segment_count_for(user_elf);
    plan_deploy_range(
        loader_account_id,
        genesis_image_id,
        segment_count,
        genesis_update_auth,
        0,
        user_elf,
    )
}

/// Computes the total segment count deploying `user_elf` would require.
///
/// At [`MAX_SEGMENT_DATA_LEN`], without building the full plan — what the first transaction of a
/// multi-transaction deploy needs to declare before the whole program exists on chain.
#[must_use]
pub fn segment_count_for(user_elf: &[u8]) -> u32 {
    let n = if user_elf.is_empty() {
        1
    } else {
        user_elf.len().div_ceil(MAX_SEGMENT_DATA_LEN)
    };
    u32::try_from(n).expect("segment count fits in u32")
}

/// The dispatch address a program with `image_id` lives at once deployed via a single-transaction
/// `Deploy` with no upgrade authority.
///
/// `segment_number` 0, `update_auth` `None`. What every genesis-seeded builtin, and any immutable
/// (non-upgradeable) `Deploy`, dispatches at. For an upgradeable program this is **not** the
/// dispatch address.
#[must_use]
pub fn immutable_deploy_account_id(image_id: ProgramId) -> AccountId {
    header_account_id(
        lee_core::program::PROGRAM_LOADER_ACCOUNT_ID,
        image_id,
        0,
        None,
    )
}

fn decode_header(account: &Account) -> ProgramData {
    ProgramData::try_from(&account.data).expect("existing header account holds a valid ProgramData")
}

/// Passes a signer-only account (never written to, only authenticated) through to its
/// post-state. Its nonce gets bumped just by signing (independent of this program), so once it's
/// ever acted as a signer it's no longer `Account::default()` — left unclaimed, that combination
/// (non-default account, default owner) is permanently rejected by `validate_execution` on any
/// later transaction that reuses it. Claiming it under the loader on its first use avoids that;
/// later transactions then see it already loader-owned and just pass it through unchanged.
fn pass_through_signer(target: &AccountWithMetadata) -> AccountPostState {
    if target.account.program_owner == DEFAULT_PROGRAM_OWNER {
        AccountPostState::new_claimed(target.account.clone(), Claim::Authorized)
    } else {
        AccountPostState::new(target.account.clone())
    }
}

/// Executes one `Deploy` transaction — a whole deployment or upgrade in one shot, or one batch of
/// a multi-transaction one.
///
/// `genesis` must be `Some` if and only if the header doesn't exist yet (a program's very first
/// `Deploy`). Once a header exists, its own stored `genesis_image_id`/`genesis_update_auth` are
/// used for every address computation instead — nothing about a program's genesis identity is
/// ever taken from a caller's declaration once there's a header to read it from.
///
/// Whether this transaction needs a real, checked authorization depends on two things: whether it
/// delivers the *whole* program in one shot (`first_segment == 0` and `user_elf_batch` covers all
/// `segment_count` segments — "self-contained"), and whether the header already exists:
///
/// - **Self-contained *and* the header doesn't exist yet (a brand-new program)**: no signature
///   required. `user_elf_batch` is independently decoded and its real `image_id` recomputed
///   (combined with the assumed [`KERNEL_ELF`]) and checked against the declared one right here.
///   The header is written with `genesis_image_id`/`genesis_update_auth` equal to the declared
///   values, `current_image_id` set directly to the verified real `image_id`, and `program_version`
///   `1`.
/// - **Everything else** (a partial batch of a brand-new deploy, or *any* write once the header
///   already exists): self-verification can't establish authorization to overwrite whatever's
///   already there, so a real signer is always required. That authority is this instruction's own
///   declared genesis `update_auth` if the header doesn't exist yet, or the header's *current*
///   `ProgramData::update_auth` otherwise — either way it must be `Some`, since a program with no
///   authority at all (immutable from birth or by renouncement) can never be written to again.
///   `current_image_id` is left at (or reset to) [`UNFINALIZED_IMAGE_ID`]; a [`finalize`] is
///   required afterward.
///
/// Segment targets: for a brand-new header, every target in this batch must be
/// `Account::default()` — a program's very first deploy only ever claims fresh accounts, never
/// overwrites. Once the header already exists, a segment target may be either
/// `Account::default()` (this upgrade grew the segment count) or already-populated (this upgrade
/// is overwriting it) — both are fine, since authorization was already established above.
///
/// Called natively from dispatch's `PROGRAM_LOADER_ACCOUNT_ID` shortcut — `Deploy` has no guest
/// binary of its own.
#[must_use]
pub fn execute_deploy(
    self_account_id: AccountId,
    pre_states: &[AccountWithMetadata],
    user_elf_batch: &[u8],
    genesis: Option<Genesis>,
    segment_count: u32,
    first_segment: u32,
) -> Vec<AccountPostState> {
    let (header_target, rest) = pre_states
        .split_first()
        .expect("Deploy requires at least a header account");
    let header_is_fresh = header_target.account == Account::default();

    let existing = (!header_is_fresh).then(|| decode_header(&header_target.account));
    let (genesis_image_id, genesis_update_auth) = match (header_is_fresh, genesis, &existing) {
        (true, Some(g), _) => (g.image_id, g.update_auth),
        (false, None, Some(existing)) => (existing.genesis_image_id, existing.genesis_update_auth),
        (true, None, _) => {
            panic!("a program's first Deploy must declare its genesis identity")
        }
        (false, Some(_), _) => {
            panic!(
                "a Deploy for an already-existing program must not declare a genesis identity - \
                 it's read from the header itself"
            )
        }
        (false, None, None) => {
            unreachable!("existing is always Some when header_is_fresh is false")
        }
    };

    let plan = plan_deploy_range(
        self_account_id,
        genesis_image_id,
        segment_count,
        genesis_update_auth,
        first_segment,
        user_elf_batch,
    );
    assert_eq!(
        header_target.account_id, plan.header.account_id,
        "wrong deployment target account"
    );
    let batch_end = first_segment
        .checked_add(u32::try_from(plan.segments.len()).expect("segment count fits in u32"))
        .expect("no overflow");
    assert!(
        batch_end <= segment_count,
        "Deploy batch runs past the declared segment_count"
    );
    let is_complete = first_segment == 0 && batch_end == segment_count;

    let fast_path_real_image_id = (header_is_fresh && is_complete).then(|| {
        let real_image_id = compute_image_id(user_elf_batch)
            .expect("user_elf must decode as a valid RISC0 program binary");
        assert_eq!(
            genesis_image_id, real_image_id,
            "declared image_id does not match the submitted bytecode"
        );
        real_image_id
    });

    let (update_auth_target, segment_targets) = if fast_path_real_image_id.is_some() {
        (None, rest)
    } else {
        let current_update_auth = if header_is_fresh {
            genesis_update_auth
        } else {
            existing
                .as_ref()
                .expect("existing is always Some when header_is_fresh is false")
                .update_auth
        };
        let required_signer = current_update_auth.expect(
            "a non-self-contained Deploy requires a real update_auth - an immutable program (no \
             upgrade authority, from birth or by renouncement) can only ever be deployed in a \
             single, self-contained transaction",
        );
        let (update_auth_target, segment_targets) = rest.split_first().expect(
            "a non-self-contained Deploy requires an update_auth signer account after the header",
        );
        assert_eq!(
            update_auth_target.account_id, required_signer,
            "second account of a non-self-contained Deploy must be the current update_auth account"
        );
        assert!(
            update_auth_target.is_authorized,
            "a non-self-contained Deploy requires update_auth's signature"
        );
        (Some(update_auth_target), segment_targets)
    };

    assert!(
        !plan.segments.is_empty(),
        "Deploy batch must include at least one segment"
    );
    assert_eq!(
        segment_targets.len(),
        plan.segments.len(),
        "Deploy requires exactly one target account per segment in this batch"
    );

    for (target, planned) in segment_targets.iter().zip(&plan.segments) {
        assert_eq!(
            target.account_id, planned.account_id,
            "wrong deployment target account"
        );
        assert!(
            !header_is_fresh || target.account == Account::default(),
            "a fresh program's segments must all be untouched"
        );
    }

    // pre_states/post_states are matched positionally, so an update_auth signer slot present in
    // pre_states must get a matching entry here too.
    let update_auth_post_state = update_auth_target.map(pass_through_signer);

    let header_post_state = if header_is_fresh {
        let (current_image_id, program_version) = fast_path_real_image_id
            .map_or((UNFINALIZED_IMAGE_ID, 0), |real_image_id| {
                (real_image_id, 1)
            });
        let header_data = ProgramData {
            genesis_image_id,
            genesis_update_auth,
            current_image_id,
            segment_count,
            update_auth: genesis_update_auth,
            program_version,
        };
        AccountPostState::new_claimed(
            Account {
                data: Data::from(&header_data),
                ..Account::default()
            },
            Claim::Pda(plan.header.seed),
        )
    } else {
        let header_data = ProgramData {
            segment_count,
            current_image_id: UNFINALIZED_IMAGE_ID,
            ..existing.expect("existing is always Some when header_is_fresh is false")
        };
        AccountPostState::new(Account {
            data: Data::from(&header_data),
            ..header_target.account.clone()
        })
    };

    std::iter::once(header_post_state)
        .chain(update_auth_post_state)
        .chain(
            segment_targets
                .iter()
                .zip(&plan.segments)
                .map(|(target, planned)| {
                    let data = Data::try_from(planned.data.clone())
                        .expect("elf chunk must fit under DATA_MAX_LENGTH");
                    if target.account == Account::default() {
                        AccountPostState::new_claimed(
                            Account {
                                data,
                                ..Account::default()
                            },
                            Claim::Pda(planned.seed),
                        )
                    } else {
                        // An upgrade overwriting an already-populated segment: keep the existing
                        // (already-loader-owned) account, just replace its data.
                        AccountPostState::new(Account {
                            data,
                            ..target.account.clone()
                        })
                    }
                }),
        )
        .collect()
}

/// Executes a `Finalize` transaction.
///
/// Reconstructs the program from all of its current segments, recomputes the real `image_id`, and
/// writes it as `ProgramData::current_image_id`, bumping `program_version`.
///
/// `pre_states`: the header (must already exist and hold `UNFINALIZED_IMAGE_ID` — nothing to
/// finalize otherwise), an account matching the header's *current* `update_auth`, `is_authorized`,
/// then every segment `0..segment_count` in order, each already-populated.
///
/// Called natively from dispatch's `PROGRAM_LOADER_ACCOUNT_ID` shortcut, same as
/// [`execute_deploy`].
#[must_use]
pub fn finalize(
    self_account_id: AccountId,
    pre_states: &[AccountWithMetadata],
) -> Vec<AccountPostState> {
    let (header_target, rest) = pre_states
        .split_first()
        .expect("Finalize requires at least a header account");
    assert_ne!(
        header_target.account,
        Account::default(),
        "Finalize requires an already-deployed header"
    );
    let existing = decode_header(&header_target.account);
    assert_eq!(
        existing.current_image_id, UNFINALIZED_IMAGE_ID,
        "nothing to finalize - this program's image_id is already established"
    );

    let (update_auth_target, segment_targets) = rest
        .split_first()
        .expect("Finalize requires an update_auth signer account after the header");
    let required_signer = existing.update_auth.expect(
        "an unfinalized header always has a real update_auth - an immutable program finalizes \
         atomically inside execute_deploy, never partially",
    );
    assert_eq!(
        update_auth_target.account_id, required_signer,
        "second account of Finalize must be the current update_auth account"
    );
    assert!(
        update_auth_target.is_authorized,
        "Finalize requires update_auth's signature"
    );

    let loader_id = self_account_id;
    assert_eq!(
        u32::try_from(segment_targets.len()).expect("segment count fits in u32"),
        existing.segment_count,
        "Finalize requires exactly one target account per segment the header declares"
    );
    let mut user_elf = Vec::new();
    for (segment_number, target) in segment_targets.iter().enumerate() {
        let segment_number = u32::try_from(segment_number).expect("segment number fits in u32");
        let expected_account_id = segment_account_id(
            loader_id,
            existing.genesis_image_id,
            segment_number,
            existing.genesis_update_auth,
        );
        assert_eq!(
            target.account_id, expected_account_id,
            "wrong segment target account"
        );
        assert_ne!(
            target.account,
            Account::default(),
            "every segment must already be deployed before finalizing"
        );
        user_elf.extend_from_slice(&target.account.data);
    }

    let real_image_id = compute_image_id(&user_elf)
        .expect("segments must reconstruct to a valid RISC0 program binary");

    let update_auth_post_state = pass_through_signer(update_auth_target);
    let header_post_state = AccountPostState::new(Account {
        data: Data::from(&ProgramData {
            current_image_id: real_image_id,
            program_version: existing
                .program_version
                .checked_add(1)
                .expect("program_version overflow"),
            ..existing
        }),
        ..header_target.account.clone()
    });
    let segment_post_states = segment_targets
        .iter()
        .map(|target| AccountPostState::new(target.account.clone()));

    std::iter::once(header_post_state)
        .chain(std::iter::once(update_auth_post_state))
        .chain(segment_post_states)
        .collect()
}

/// Executes a `RotateUpdateAuth` transaction: changes `ProgramData::update_auth` to
/// `new_update_auth`. `genesis_update_auth`, `current_image_id`, and `program_version` are
/// untouched.
///
/// `pre_states`: the header (must already exist and hold a real, `Some` `update_auth` — there's
/// no authority to rotate away from otherwise), an account matching that current `update_auth`,
/// `is_authorized`, then — only when `new_update_auth` is `Some` — an account matching it, also
/// `is_authorized`. A `None` `new_update_auth` renounces authority for good and needs only the
/// current authority's signature, since there's no new account to co-sign on the other end.
///
/// Called natively from dispatch's `PROGRAM_LOADER_ACCOUNT_ID` shortcut, same as
/// [`execute_deploy`].
#[must_use]
pub fn rotate_update_auth(
    pre_states: &[AccountWithMetadata],
    new_update_auth: Option<AccountId>,
) -> Vec<AccountPostState> {
    let (header_target, rest) = pre_states
        .split_first()
        .expect("RotateUpdateAuth requires at least a header account");
    assert_ne!(
        header_target.account,
        Account::default(),
        "RotateUpdateAuth requires an already-deployed header"
    );
    let existing = decode_header(&header_target.account);
    let required_current_signer = existing
        .update_auth
        .expect("RotateUpdateAuth requires an existing update_auth to rotate away from");

    let (current_auth_target, rest) = rest
        .split_first()
        .expect("RotateUpdateAuth requires an update_auth signer account after the header");
    assert_eq!(
        current_auth_target.account_id, required_current_signer,
        "second account of RotateUpdateAuth must be the current update_auth account"
    );
    assert!(
        current_auth_target.is_authorized,
        "RotateUpdateAuth requires the current update_auth's signature"
    );

    let new_auth_post_state = new_update_auth.map_or_else(
        || {
            assert!(
                rest.is_empty(),
                "renouncing update_auth (new_update_auth: None) takes only the header and the \
                 current update_auth, no third account"
            );
            None
        },
        |new_update_auth| {
            let [new_auth_target] = rest else {
                panic!(
                    "RotateUpdateAuth to a real new_update_auth requires exactly the header, the \
                     current update_auth, and the new update_auth"
                );
            };
            assert_eq!(
                new_auth_target.account_id, new_update_auth,
                "third account of RotateUpdateAuth must be the proposed new update_auth account"
            );
            assert!(
                new_auth_target.is_authorized,
                "RotateUpdateAuth requires the proposed new update_auth's signature too"
            );
            Some(pass_through_signer(new_auth_target))
        },
    );

    let header_post_state = AccountPostState::new(Account {
        data: Data::from(&ProgramData {
            update_auth: new_update_auth,
            ..existing
        }),
        ..header_target.account.clone()
    });

    std::iter::once(header_post_state)
        .chain(std::iter::once(pass_through_signer(current_auth_target)))
        .chain(new_auth_post_state)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    const IMAGE_ID: ProgramId = [1, 2, 3, 4, 5, 6, 7, 8];
    const LOADER_ID: AccountId = AccountId::new([9; 32]);
    const REAL_UPDATE_AUTH: AccountId = AccountId::new([42; 32]);
    const OTHER_UPDATE_AUTH: AccountId = AccountId::new([43; 32]);

    #[expect(
        clippy::unnecessary_wraps,
        reason = "mirrors Instruction::Deploy's genesis: Option<Genesis> field"
    )]
    fn genesis(image_id: ProgramId, update_auth: Option<AccountId>) -> Option<Genesis> {
        Some(Genesis {
            image_id,
            update_auth,
        })
    }

    fn plan_for(len: usize) -> DeployPlan {
        let user_elf = vec![0xAB_u8; len];
        plan_deploy(LOADER_ID, IMAGE_ID, None, &user_elf)
    }

    #[test]
    fn one_chunk_just_under_the_boundary() {
        let plan = plan_for(MAX_SEGMENT_DATA_LEN - 1);
        assert_eq!(plan.segments.len(), 1);
        assert_eq!(plan.segments[0].data.len(), MAX_SEGMENT_DATA_LEN - 1);
    }

    #[test]
    fn one_chunk_exactly_at_the_boundary() {
        let plan = plan_for(MAX_SEGMENT_DATA_LEN);
        assert_eq!(plan.segments.len(), 1);
        assert_eq!(plan.segments[0].data.len(), MAX_SEGMENT_DATA_LEN);
    }

    #[test]
    fn exact_multiple_does_not_leave_a_trailing_empty_chunk() {
        let plan = plan_for(2 * MAX_SEGMENT_DATA_LEN);
        assert_eq!(plan.segments.len(), 2);
        assert!(
            plan.segments
                .iter()
                .all(|s| s.data.len() == MAX_SEGMENT_DATA_LEN)
        );
    }

    #[test]
    fn remainder_gets_its_own_chunk() {
        let plan = plan_for(2 * MAX_SEGMENT_DATA_LEN + 1);
        assert_eq!(plan.segments.len(), 3);
        assert_eq!(plan.segments[2].data.len(), 1);
    }

    #[test]
    fn empty_elf_still_produces_one_segment() {
        let plan = plan_for(0);
        assert_eq!(plan.segments.len(), 1);
        assert!(plan.segments[0].data.is_empty());
    }

    #[test]
    fn segments_concatenate_back_to_the_original_bytes() {
        for len in [
            0,
            1,
            MAX_SEGMENT_DATA_LEN - 1,
            MAX_SEGMENT_DATA_LEN,
            2 * MAX_SEGMENT_DATA_LEN,
            2 * MAX_SEGMENT_DATA_LEN + 1,
        ] {
            let user_elf = vec![0xCD_u8; len];
            let plan = plan_deploy(LOADER_ID, IMAGE_ID, None, &user_elf);
            let reconstructed: Vec<u8> =
                plan.segments.iter().flat_map(|s| s.data.clone()).collect();
            assert_eq!(reconstructed, user_elf, "mismatch at len={len}");
        }
    }

    #[test]
    fn header_pda_is_independent_of_segment_count() {
        // The header's own address must never depend on how many segments the bytecode needs —
        // that's what keeps `immutable_deploy_account_id` stable across arbitrarily-sized deploys.
        let small = plan_for(1);
        let large = plan_for(5 * MAX_SEGMENT_DATA_LEN);
        assert_eq!(small.header.account_id, large.header.account_id);
    }

    #[test]
    fn plan_deploy_range_batches_reassemble_to_the_same_plan() {
        for total_len in [
            1,
            MAX_SEGMENT_DATA_LEN,
            2 * MAX_SEGMENT_DATA_LEN,
            2 * MAX_SEGMENT_DATA_LEN + 1,
        ] {
            let user_elf: Vec<u8> = (0..total_len)
                .map(|i| {
                    u8::try_from(i.checked_rem(251).expect("nonzero divisor"))
                        .expect("value fits in u8")
                })
                .collect();
            let whole = plan_deploy(LOADER_ID, IMAGE_ID, None, &user_elf);
            let segment_count = u32::try_from(whole.segments.len()).unwrap();

            // Split at every possible boundary into two batches.
            for split in 0..whole.segments.len() {
                let first_len = split
                    .checked_add(1)
                    .expect("split index fits")
                    .min(whole.segments.len());
                let byte_split = whole.segments[..first_len]
                    .iter()
                    .map(|s| s.data.len())
                    .sum();
                let (first_bytes, second_bytes) = user_elf.split_at(byte_split);

                let batch1 =
                    plan_deploy_range(LOADER_ID, IMAGE_ID, segment_count, None, 0, first_bytes);
                let batch2 = plan_deploy_range(
                    LOADER_ID,
                    IMAGE_ID,
                    segment_count,
                    None,
                    u32::try_from(first_len).unwrap(),
                    second_bytes,
                );

                let reassembled: Vec<_> = batch1
                    .segments
                    .iter()
                    .chain(&batch2.segments)
                    .map(|s| s.account_id)
                    .collect();
                let expected: Vec<_> = whole.segments.iter().map(|s| s.account_id).collect();
                assert_eq!(
                    reassembled, expected,
                    "mismatch at total_len={total_len}, split={split}"
                );
                assert_eq!(batch1.header.account_id, whole.header.account_id);
                assert_eq!(batch2.header.account_id, whole.header.account_id);
            }
        }
    }

    fn header_target(plan: &DeployPlan, existing: Account) -> AccountWithMetadata {
        AccountWithMetadata {
            account: existing,
            is_authorized: false,
            account_id: plan.header.account_id,
        }
    }

    fn fresh_segment_targets(plan: &DeployPlan) -> Vec<AccountWithMetadata> {
        plan.segments
            .iter()
            .map(|s| AccountWithMetadata {
                account: Account::default(),
                is_authorized: false,
                account_id: s.account_id,
            })
            .collect()
    }

    fn signer(account_id: AccountId, is_authorized: bool) -> AccountWithMetadata {
        AccountWithMetadata {
            account: Account::default(),
            is_authorized,
            account_id,
        }
    }

    /// Builds the header `Account` as it exists on-chain right after a fresh, non-self-contained
    /// `Deploy` batch claimed it (unfinalized) — mirrors what `validated_state_diff`'s claim
    /// processing actually produces, since `execute_deploy`'s own return value leaves
    /// `program_owner` at the default placeholder.
    fn header_after_claim(loader_id: AccountId, header_data: &ProgramData) -> Account {
        Account {
            program_owner: loader_id,
            data: Data::from(header_data),
            ..Account::default()
        }
    }

    #[test]
    fn execute_deploy_single_batch_still_works() {
        let program = test_programs::claimer();
        let user_elf = extract_user_elf(program.elf()).unwrap();
        let image_id = program.id();

        let plan = plan_deploy(LOADER_ID, image_id, None, &user_elf);
        let segment_count = u32::try_from(plan.segments.len()).unwrap();

        let mut pre_states = vec![header_target(&plan, Account::default())];
        pre_states.extend(fresh_segment_targets(&plan));

        let post_states = execute_deploy(
            LOADER_ID,
            &pre_states,
            &user_elf,
            genesis(image_id, None),
            segment_count,
            0,
        );
        assert_eq!(post_states.len(), 1 + plan.segments.len());
    }

    #[test]
    fn execute_deploy_single_batch_finalizes_atomically() {
        let program = test_programs::claimer();
        let user_elf = extract_user_elf(program.elf()).unwrap();
        let image_id = program.id();
        let plan = plan_deploy(LOADER_ID, image_id, None, &user_elf);
        let segment_count = u32::try_from(plan.segments.len()).unwrap();
        let mut pre_states = vec![header_target(&plan, Account::default())];
        pre_states.extend(fresh_segment_targets(&plan));

        let post_states = execute_deploy(
            LOADER_ID,
            &pre_states,
            &user_elf,
            genesis(image_id, None),
            segment_count,
            0,
        );
        let header_data = ProgramData::try_from(&post_states[0].account().data).unwrap();
        assert_eq!(header_data.genesis_image_id, image_id);
        assert_eq!(header_data.current_image_id, image_id);
        assert_eq!(header_data.program_version, 1);
    }

    #[test]
    fn execute_deploy_single_batch_finalizes_atomically_even_with_real_update_auth() {
        // A self-contained deploy never needs a signature, regardless of what update_auth is
        // declared for future upgradeability.
        let program = test_programs::claimer();
        let user_elf = extract_user_elf(program.elf()).unwrap();
        let image_id = program.id();
        let plan = plan_deploy(LOADER_ID, image_id, Some(REAL_UPDATE_AUTH), &user_elf);
        let segment_count = u32::try_from(plan.segments.len()).unwrap();
        let mut pre_states = vec![header_target(&plan, Account::default())];
        pre_states.extend(fresh_segment_targets(&plan));

        let post_states = execute_deploy(
            LOADER_ID,
            &pre_states,
            &user_elf,
            genesis(image_id, Some(REAL_UPDATE_AUTH)),
            segment_count,
            0,
        );
        let header_data = ProgramData::try_from(&post_states[0].account().data).unwrap();
        assert_eq!(header_data.genesis_update_auth, Some(REAL_UPDATE_AUTH));
        assert_eq!(header_data.update_auth, Some(REAL_UPDATE_AUTH));
        assert_eq!(header_data.current_image_id, image_id);
        assert_eq!(header_data.program_version, 1);
    }

    #[test]
    fn execute_deploy_two_batch_sequence_leaves_it_unfinalized() {
        let program = test_programs::claimer();
        let user_elf = extract_user_elf(program.elf()).unwrap();
        let image_id = program.id();
        let plan = plan_deploy(LOADER_ID, image_id, Some(REAL_UPDATE_AUTH), &user_elf);
        assert!(plan.segments.len() > 1, "need a real multi-segment program");
        let segment_count = u32::try_from(plan.segments.len()).unwrap();
        let split = plan.segments.len().checked_div(2).expect("nonzero divisor");
        let byte_split: usize = plan.segments[..split].iter().map(|s| s.data.len()).sum();
        let (first_bytes, second_bytes) = user_elf.split_at(byte_split);

        // Batch 1: header (fresh) + signer + segments[..split]
        let batch1_plan = plan_deploy_range(
            LOADER_ID,
            image_id,
            segment_count,
            Some(REAL_UPDATE_AUTH),
            0,
            first_bytes,
        );
        let mut pre_states1 = vec![header_target(&batch1_plan, Account::default())];
        pre_states1.push(signer(REAL_UPDATE_AUTH, true));
        pre_states1.extend(fresh_segment_targets(&batch1_plan));
        let post1 = execute_deploy(
            LOADER_ID,
            &pre_states1,
            first_bytes,
            genesis(image_id, Some(REAL_UPDATE_AUTH)),
            segment_count,
            0,
        );
        assert_eq!(post1.len(), 2 + batch1_plan.segments.len());
        let header_data1 = ProgramData::try_from(&post1[0].account().data).unwrap();
        assert_eq!(header_data1.current_image_id, UNFINALIZED_IMAGE_ID);
        assert_eq!(header_data1.program_version, 0);

        let header_after_batch1 = header_after_claim(LOADER_ID, &header_data1);

        // Batch 2: header (already-deployed, unfinalized) + signer + segments[split..]
        let batch2_plan = plan_deploy_range(
            LOADER_ID,
            image_id,
            segment_count,
            Some(REAL_UPDATE_AUTH),
            u32::try_from(split).unwrap(),
            second_bytes,
        );
        let mut pre_states2 = vec![header_target(&batch2_plan, header_after_batch1)];
        pre_states2.push(signer(REAL_UPDATE_AUTH, true));
        pre_states2.extend(fresh_segment_targets(&batch2_plan));
        let post2 = execute_deploy(
            LOADER_ID,
            &pre_states2,
            second_bytes,
            None,
            segment_count,
            u32::try_from(split).unwrap(),
        );
        assert_eq!(post2.len(), 2 + batch2_plan.segments.len());
        let header_data2 = ProgramData::try_from(&post2[0].account().data).unwrap();
        // Still unfinalized after every segment has landed - Finalize is a separate step.
        assert_eq!(header_data2.current_image_id, UNFINALIZED_IMAGE_ID);
    }

    /// Deploys `program` across two batches, so it lands unfinalized, then returns everything
    /// needed to either finalize it or feed it back into another `execute_deploy`/`finalize`/
    /// `rotate_update_auth` call: the plan, the header account as it exists on-chain, and every
    /// segment account as it exists on-chain (all real, populated bytes).
    fn deploy_unfinalized_across_two_batches(
        full_binary: &[u8],
        image_id: ProgramId,
        update_auth: AccountId,
    ) -> (DeployPlan, Account, Vec<Account>) {
        let user_elf = extract_user_elf(full_binary).unwrap();
        let plan = plan_deploy(LOADER_ID, image_id, Some(update_auth), &user_elf);
        assert!(plan.segments.len() > 1, "need a real multi-segment program");
        let segment_count = u32::try_from(plan.segments.len()).unwrap();
        let split = plan.segments.len().checked_div(2).expect("nonzero divisor");
        let byte_split: usize = plan.segments[..split].iter().map(|s| s.data.len()).sum();
        let (first_bytes, second_bytes) = user_elf.split_at(byte_split);

        let batch1_plan = plan_deploy_range(
            LOADER_ID,
            image_id,
            segment_count,
            Some(update_auth),
            0,
            first_bytes,
        );
        let mut pre_states1 = vec![header_target(&batch1_plan, Account::default())];
        pre_states1.push(signer(update_auth, true));
        pre_states1.extend(fresh_segment_targets(&batch1_plan));
        let post1 = execute_deploy(
            LOADER_ID,
            &pre_states1,
            first_bytes,
            genesis(image_id, Some(update_auth)),
            segment_count,
            0,
        );
        let header_data1 = ProgramData::try_from(&post1[0].account().data).unwrap();
        let header_after_batch1 = header_after_claim(LOADER_ID, &header_data1);

        let batch2_plan = plan_deploy_range(
            LOADER_ID,
            image_id,
            segment_count,
            Some(update_auth),
            u32::try_from(split).unwrap(),
            second_bytes,
        );
        let mut pre_states2 = vec![header_target(&batch2_plan, header_after_batch1)];
        pre_states2.push(signer(update_auth, true));
        pre_states2.extend(fresh_segment_targets(&batch2_plan));
        let post2 = execute_deploy(
            LOADER_ID,
            &pre_states2,
            second_bytes,
            None,
            segment_count,
            u32::try_from(split).unwrap(),
        );
        let header_data2 = ProgramData::try_from(&post2[0].account().data).unwrap();
        let header_account = header_after_claim(LOADER_ID, &header_data2);

        let segment_accounts = plan
            .segments
            .iter()
            .map(|s| Account {
                program_owner: LOADER_ID,
                data: Data::try_from(s.data.clone()).unwrap(),
                ..Account::default()
            })
            .collect();

        (plan, header_account, segment_accounts)
    }

    fn finalize_pre_states(
        plan: &DeployPlan,
        header_account: Account,
        segment_accounts: &[Account],
        update_auth: AccountId,
    ) -> Vec<AccountWithMetadata> {
        let mut pre_states = vec![AccountWithMetadata {
            account: header_account,
            is_authorized: false,
            account_id: plan.header.account_id,
        }];
        pre_states.push(signer(update_auth, true));
        pre_states.extend(
            plan.segments
                .iter()
                .zip(segment_accounts)
                .map(|(s, account)| AccountWithMetadata {
                    account: account.clone(),
                    is_authorized: false,
                    account_id: s.account_id,
                }),
        );
        pre_states
    }

    #[test]
    fn finalize_establishes_current_image_id_and_bumps_version() {
        let program = test_programs::claimer();
        let image_id = program.id();
        let (plan, header_account, segment_accounts) =
            deploy_unfinalized_across_two_batches(program.elf(), image_id, REAL_UPDATE_AUTH);

        let finalize_post = finalize(
            LOADER_ID,
            &finalize_pre_states(&plan, header_account, &segment_accounts, REAL_UPDATE_AUTH),
        );
        let finalized_header = ProgramData::try_from(&finalize_post[0].account().data).unwrap();
        assert_eq!(finalized_header.current_image_id, image_id);
        assert_eq!(finalized_header.program_version, 1);
        assert_eq!(finalized_header.genesis_image_id, image_id);
    }

    #[test]
    #[should_panic(expected = "nothing to finalize")]
    fn finalize_rejects_an_already_finalized_program() {
        let program = test_programs::claimer();
        let user_elf = extract_user_elf(program.elf()).unwrap();
        let image_id = program.id();
        let plan = plan_deploy(LOADER_ID, image_id, None, &user_elf);
        let segment_count = u32::try_from(plan.segments.len()).unwrap();

        let mut pre_states = vec![header_target(&plan, Account::default())];
        pre_states.extend(fresh_segment_targets(&plan));
        let deploy_post = execute_deploy(
            LOADER_ID,
            &pre_states,
            &user_elf,
            genesis(image_id, None),
            segment_count,
            0,
        );
        let header_data = ProgramData::try_from(&deploy_post[0].account().data).unwrap();
        let header_account = header_after_claim(LOADER_ID, &header_data);

        let mut finalize_pre_states = vec![AccountWithMetadata {
            account: header_account,
            is_authorized: false,
            account_id: plan.header.account_id,
        }];
        finalize_pre_states.push(signer(AccountId::default(), true));
        finalize_pre_states.extend(plan.segments.iter().map(|s| AccountWithMetadata {
            account: Account {
                program_owner: LOADER_ID,
                data: Data::try_from(s.data.clone()).unwrap(),
                ..Account::default()
            },
            is_authorized: false,
            account_id: s.account_id,
        }));

        #[expect(
            clippy::let_underscore_must_use,
            reason = "should_panic test - the panic is the assertion, return value unused"
        )]
        let _ = finalize(LOADER_ID, &finalize_pre_states);
    }

    /// Deploys `program` in one self-contained transaction with a real `update_auth` — no
    /// signature needed, and already live (`current_image_id` real, `program_version` 1) with no
    /// separate `finalize` required. Returns the plan and the on-chain header/segment accounts.
    fn deploy_and_finalize_in_one_shot(
        full_binary: &[u8],
        image_id: ProgramId,
        update_auth: AccountId,
    ) -> (DeployPlan, Account, Vec<Account>) {
        let user_elf = extract_user_elf(full_binary).unwrap();
        let plan = plan_deploy(LOADER_ID, image_id, Some(update_auth), &user_elf);
        let segment_count = u32::try_from(plan.segments.len()).unwrap();
        let mut pre_states = vec![header_target(&plan, Account::default())];
        pre_states.extend(fresh_segment_targets(&plan));
        let post = execute_deploy(
            LOADER_ID,
            &pre_states,
            &user_elf,
            genesis(image_id, Some(update_auth)),
            segment_count,
            0,
        );
        let header_data = ProgramData::try_from(&post[0].account().data).unwrap();
        assert_eq!(header_data.current_image_id, image_id);
        assert_eq!(header_data.program_version, 1);
        let header_account = header_after_claim(LOADER_ID, &header_data);
        let segment_accounts = plan
            .segments
            .iter()
            .map(|s| Account {
                program_owner: LOADER_ID,
                data: Data::try_from(s.data.clone()).unwrap(),
                ..Account::default()
            })
            .collect();
        (plan, header_account, segment_accounts)
    }

    #[test]
    fn execute_deploy_allows_upgrading_a_finalized_program() {
        let program = test_programs::claimer();
        let image_id = program.id();
        let (plan, live_header_account, segment_accounts) =
            deploy_and_finalize_in_one_shot(program.elf(), image_id, REAL_UPDATE_AUTH);
        let segment_count = u32::try_from(plan.segments.len()).unwrap();

        // Now upgrade: overwrite segment 0 with new bytes, same genesis address, same
        // segment_count. Requires the current update_auth's signature even though it's a
        // single-segment (self-containable-looking) write.
        let new_user_elf: Vec<u8> = vec![0xEE_u8; plan.segments[0].data.len()];
        let mut upgrade_pre_states = vec![AccountWithMetadata {
            account: live_header_account,
            is_authorized: false,
            account_id: plan.header.account_id,
        }];
        upgrade_pre_states.push(signer(REAL_UPDATE_AUTH, true));
        upgrade_pre_states.push(AccountWithMetadata {
            account: segment_accounts[0].clone(),
            is_authorized: false,
            account_id: plan.segments[0].account_id,
        });
        let upgrade_post = execute_deploy(
            LOADER_ID,
            &upgrade_pre_states,
            &new_user_elf,
            None,
            segment_count,
            0,
        );
        let upgraded_header = ProgramData::try_from(&upgrade_post[0].account().data).unwrap();
        // The write resets current_image_id back to the sentinel - a Finalize is required again.
        assert_eq!(upgraded_header.current_image_id, UNFINALIZED_IMAGE_ID);
        // genesis fields and program_version are untouched by a Deploy write - only Finalize
        // bumps program_version.
        assert_eq!(upgraded_header.genesis_image_id, image_id);
        assert_eq!(upgraded_header.program_version, 1);
        assert_eq!(
            upgrade_post[2].account().data.to_vec(),
            new_user_elf,
            "segment 0 must actually be overwritten"
        );
    }

    #[test]
    #[should_panic(expected = "must be the current update_auth account")]
    fn execute_deploy_rejects_upgrading_with_the_wrong_signer() {
        let program = test_programs::claimer();
        let image_id = program.id();
        let (plan, live_header_account, segment_accounts) =
            deploy_and_finalize_in_one_shot(program.elf(), image_id, REAL_UPDATE_AUTH);
        let segment_count = u32::try_from(plan.segments.len()).unwrap();

        let mut upgrade_pre_states = vec![AccountWithMetadata {
            account: live_header_account,
            is_authorized: false,
            account_id: plan.header.account_id,
        }];
        // Wrong signer: OTHER_UPDATE_AUTH is not this program's update_auth.
        upgrade_pre_states.push(signer(OTHER_UPDATE_AUTH, true));
        upgrade_pre_states.push(AccountWithMetadata {
            account: segment_accounts[0].clone(),
            is_authorized: false,
            account_id: plan.segments[0].account_id,
        });
        #[expect(
            clippy::let_underscore_must_use,
            reason = "should_panic test - the panic is the assertion, return value unused"
        )]
        let _ = execute_deploy(
            LOADER_ID,
            &upgrade_pre_states,
            &vec![0xEE_u8; plan.segments[0].data.len()],
            None,
            segment_count,
            0,
        );
    }

    #[test]
    fn rotate_update_auth_changes_current_authority_only() {
        let program = test_programs::claimer();
        let image_id = program.id();
        let (plan, live_header_account, _segment_accounts) =
            deploy_and_finalize_in_one_shot(program.elf(), image_id, REAL_UPDATE_AUTH);
        let header_data_before = ProgramData::try_from(&live_header_account.data).unwrap();

        let rotate_pre_states = vec![
            AccountWithMetadata {
                account: live_header_account,
                is_authorized: false,
                account_id: plan.header.account_id,
            },
            signer(REAL_UPDATE_AUTH, true),
            signer(OTHER_UPDATE_AUTH, true),
        ];
        let rotate_post = rotate_update_auth(&rotate_pre_states, Some(OTHER_UPDATE_AUTH));
        let rotated = ProgramData::try_from(&rotate_post[0].account().data).unwrap();
        assert_eq!(rotated.update_auth, Some(OTHER_UPDATE_AUTH));
        assert_eq!(rotated.genesis_update_auth, Some(REAL_UPDATE_AUTH));
        assert_eq!(rotated.genesis_image_id, image_id);
        assert_eq!(
            rotated.current_image_id,
            header_data_before.current_image_id
        );
        assert_eq!(rotated.program_version, header_data_before.program_version);
    }

    #[test]
    #[should_panic(expected = "requires the current update_auth's signature")]
    fn rotate_update_auth_requires_both_signatures() {
        let program = test_programs::claimer();
        let image_id = program.id();
        let (plan, live_header_account, _segment_accounts) =
            deploy_and_finalize_in_one_shot(program.elf(), image_id, REAL_UPDATE_AUTH);

        let rotate_pre_states = vec![
            AccountWithMetadata {
                account: live_header_account,
                is_authorized: false,
                account_id: plan.header.account_id,
            },
            signer(REAL_UPDATE_AUTH, false), // present, but not signed
            signer(OTHER_UPDATE_AUTH, true),
        ];
        #[expect(
            clippy::let_underscore_must_use,
            reason = "should_panic test - the panic is the assertion, return value unused"
        )]
        let _ = rotate_update_auth(&rotate_pre_states, Some(OTHER_UPDATE_AUTH));
    }

    #[test]
    #[should_panic(expected = "a non-self-contained Deploy requires a real update_auth")]
    fn execute_deploy_rejects_a_partial_batch_with_default_update_auth() {
        let program = test_programs::claimer();
        let user_elf = extract_user_elf(program.elf()).unwrap();
        let image_id = program.id();
        let plan = plan_deploy(LOADER_ID, image_id, None, &user_elf);
        assert!(plan.segments.len() > 1, "need a real multi-segment program");
        let segment_count = u32::try_from(plan.segments.len()).unwrap();
        let split = plan.segments.len() - 1;
        let byte_split: usize = plan.segments[..split].iter().map(|s| s.data.len()).sum();
        let (first_bytes, _second_bytes) = user_elf.split_at(byte_split);

        let batch_plan =
            plan_deploy_range(LOADER_ID, image_id, segment_count, None, 0, first_bytes);
        let mut pre_states = vec![header_target(&batch_plan, Account::default())];
        pre_states.push(signer(AccountId::default(), true));
        pre_states.extend(fresh_segment_targets(&batch_plan));
        #[expect(
            clippy::let_underscore_must_use,
            reason = "should_panic test - the panic is the assertion, return value unused"
        )]
        let _ = execute_deploy(
            LOADER_ID,
            &pre_states,
            first_bytes,
            genesis(image_id, None),
            segment_count,
            0,
        );
    }

    #[test]
    #[should_panic(expected = "requires update_auth's signature")]
    fn execute_deploy_rejects_a_partial_batch_without_update_auths_signature() {
        let program = test_programs::claimer();
        let user_elf = extract_user_elf(program.elf()).unwrap();
        let image_id = program.id();
        let plan = plan_deploy(LOADER_ID, image_id, Some(REAL_UPDATE_AUTH), &user_elf);
        assert!(plan.segments.len() > 1, "need a real multi-segment program");
        let segment_count = u32::try_from(plan.segments.len()).unwrap();
        let split = plan.segments.len() - 1;
        let byte_split: usize = plan.segments[..split].iter().map(|s| s.data.len()).sum();
        let (first_bytes, _second_bytes) = user_elf.split_at(byte_split);

        let batch_plan = plan_deploy_range(
            LOADER_ID,
            image_id,
            segment_count,
            Some(REAL_UPDATE_AUTH),
            0,
            first_bytes,
        );
        let mut pre_states = vec![header_target(&batch_plan, Account::default())];
        pre_states.push(signer(REAL_UPDATE_AUTH, false)); // present, but not signed
        pre_states.extend(fresh_segment_targets(&batch_plan));
        #[expect(
            clippy::let_underscore_must_use,
            reason = "should_panic test - the panic is the assertion, return value unused"
        )]
        let _ = execute_deploy(
            LOADER_ID,
            &pre_states,
            first_bytes,
            genesis(image_id, Some(REAL_UPDATE_AUTH)),
            segment_count,
            0,
        );
    }

    #[test]
    #[should_panic(expected = "runs past the declared segment_count")]
    fn execute_deploy_rejects_batch_past_declared_segment_count() {
        let program = test_programs::claimer();
        let user_elf = extract_user_elf(program.elf()).unwrap();
        let image_id = program.id();
        let real_segment_count = segment_count_for(&user_elf);
        assert!(real_segment_count > 1, "need a real multi-segment program");

        // Declare a segment_count of 1 (too small) while submitting the whole program.
        let plan = plan_deploy_range(LOADER_ID, image_id, 1, None, 0, &user_elf);
        let mut pre_states = vec![header_target(&plan, Account::default())];
        pre_states.extend(fresh_segment_targets(&plan));
        #[expect(
            clippy::let_underscore_must_use,
            reason = "should_panic test - the panic is the assertion, return value unused"
        )]
        let _ = execute_deploy(
            LOADER_ID,
            &pre_states,
            &user_elf,
            genesis(image_id, None),
            1,
            0,
        );
    }

    #[test]
    #[should_panic(expected = "must include at least one segment")]
    fn execute_deploy_rejects_header_only_batch() {
        let plan = plan_deploy_range(LOADER_ID, IMAGE_ID, 2, Some(REAL_UPDATE_AUTH), 2, &[]);
        let mut pre_states = vec![header_target(&plan, Account::default())];
        pre_states.push(signer(REAL_UPDATE_AUTH, true));
        #[expect(
            clippy::let_underscore_must_use,
            reason = "should_panic test - the panic is the assertion, return value unused"
        )]
        let _ = execute_deploy(
            LOADER_ID,
            &pre_states,
            &[],
            genesis(IMAGE_ID, Some(REAL_UPDATE_AUTH)),
            2,
            2,
        );
    }

    #[test]
    #[should_panic(expected = "a fresh program's segments must all be untouched")]
    fn execute_deploy_rejects_rewriting_a_written_segment_during_a_fresh_deploy() {
        let program = test_programs::claimer();
        let user_elf = extract_user_elf(program.elf()).unwrap();
        let image_id = program.id();
        let plan = plan_deploy(LOADER_ID, image_id, None, &user_elf);
        let segment_count = u32::try_from(plan.segments.len()).unwrap();

        let mut pre_states = vec![header_target(&plan, Account::default())];
        // First segment already claimed (non-default), rest fresh - but the header is *also*
        // still Account::default(), which is inconsistent (a fresh header can't have pre-claimed
        // segments) and exactly what this assertion guards against.
        let mut segments = fresh_segment_targets(&plan);
        segments[0].account = Account {
            data: Data::try_from(plan.segments[0].data.clone()).unwrap(),
            ..Account::default()
        };
        pre_states.extend(segments);

        #[expect(
            clippy::let_underscore_must_use,
            reason = "should_panic test - the panic is the assertion, return value unused"
        )]
        let _ = execute_deploy(
            LOADER_ID,
            &pre_states,
            &user_elf,
            genesis(image_id, None),
            segment_count,
            0,
        );
    }

    #[test]
    #[should_panic(expected = "declared image_id does not match the submitted bytecode")]
    fn execute_deploy_rejects_a_complete_batch_with_a_dishonest_image_id() {
        let program = test_programs::claimer();
        let user_elf = extract_user_elf(program.elf()).unwrap();
        let dishonest_image_id = [99, 99, 99, 99, 99, 99, 99, 99];
        let segment_count = segment_count_for(&user_elf);

        let plan = plan_deploy(LOADER_ID, dishonest_image_id, None, &user_elf);
        let mut pre_states = vec![header_target(&plan, Account::default())];
        pre_states.extend(fresh_segment_targets(&plan));

        #[expect(
            clippy::let_underscore_must_use,
            reason = "should_panic test - the panic is the assertion, return value unused"
        )]
        let _ = execute_deploy(
            LOADER_ID,
            &pre_states,
            &user_elf,
            genesis(dishonest_image_id, None),
            segment_count,
            0,
        );
    }

    #[test]
    fn full_round_trip_against_a_real_program() {
        let program = test_programs::claimer();
        let full_binary = program.elf();
        let user_elf = extract_user_elf(full_binary).unwrap();

        let plan = plan_deploy(LOADER_ID, program.id(), None, &user_elf);
        assert!(
            plan.segments.len() > 1,
            "a real program should span multiple segments"
        );

        let reconstructed_user_elf: Vec<u8> =
            plan.segments.iter().flat_map(|s| s.data.clone()).collect();
        assert_eq!(reconstructed_user_elf, user_elf);

        let recomputed_image_id = compute_image_id(&reconstructed_user_elf).unwrap();
        assert_eq!(recomputed_image_id, program.id());

        let full_binary_again = reconstruct_program_binary(&reconstructed_user_elf);
        assert_eq!(full_binary_again, full_binary);
    }
}
