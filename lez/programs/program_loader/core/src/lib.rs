use borsh::{BorshDeserialize, BorshSerialize};
pub use lee_core::program::{PdaSeed, ProgramData};
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
    /// Deploys a program, in whole or in part: writes its `ProgramData` header and the bytecode
    /// segments this transaction's `raw_payload` covers, each claimed as a PDA of the loader.
    /// One or more `Deploy`s (each covering a contiguous range of segments) complete a
    /// deployment — see [`execute_deploy`] for exactly what each transaction requires.
    ///
    /// The bytecode itself travels via the dispatching message's `raw_payload`, not this
    /// instruction — see `Message::raw_payload`'s doc comment for why.
    ///
    /// Required accounts, in order:
    /// - The target `ProgramData` header PDA account (must be `Account::default()`, or already
    ///   exactly this deployment's header — see [`execute_deploy`])
    /// - If this transaction doesn't deliver the whole program in one shot: an account matching
    ///   `update_auth`, signed (`is_authorized`) by its holder
    /// - The target segment PDA accounts this transaction covers (`first_segment, first_segment+1,
    ///   ...`), in order (each must be `Account::default()`)
    Deploy {
        /// Caller-declared identity of the program being deployed. Verified immediately against
        /// the real bytecode when a transaction delivers the whole program in one shot;
        /// otherwise verified lazily by `V03State::get_program` once every segment exists — see
        /// [`execute_deploy`].
        image_id: ProgramId,
        /// Total segment count for the whole deployment. Caller-declared for the same reason as
        /// `image_id`: a transaction covering only part of the program can't derive it from its
        /// own fragment. Must be identical across every transaction in one deployment.
        segment_count: u32,
        /// `segment_number` of this transaction's first segment (0-indexed); its remaining
        /// segment accounts are `first_segment, first_segment+1, ...` in order.
        first_segment: u32,
        /// Distinguishes independent deployments of identical bytecode (same `image_id`) from
        /// one another, so a second deployer never collides with an existing deployment's PDAs.
        /// Also who may redeploy this same slot in the future once upgrade authority is fully
        /// implemented (a future PR), and — already enforced now — who must sign any transaction
        /// that can't verify itself immediately (see [`execute_deploy`]). `AccountId::default()`
        /// means no upgrade authority (immutable); such a program can only be deployed in a
        /// single, self-contained transaction, since there's no key to sign a partial one with.
        update_auth: AccountId,
    },
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
/// The same derivation [`execute_deploy`] uses to fix a program's identity at deploy time —
/// shared here so `V03State::get_program` can independently re-check that reconstructed segments
/// still produce the `image_id` their header claims, without duplicating this logic.
pub fn compute_image_id(user_elf: &[u8]) -> anyhow::Result<ProgramId> {
    Ok(risc0_binfmt::ProgramBinary::new(user_elf, KERNEL_ELF)
        .compute_image_id()?
        .into())
}

/// Derives the PDA seed for a deployed program's `ProgramData` header account.
///
/// Combines the program's content-derived identity (`image_id`), this account's position among
/// the program's segments (`segment_count` — despite sharing a name with `ProgramData`'s segment
/// total, here it's the per-account index, always `0` for a header, see [`plan_deploy`]), and
/// `update_auth` — included so multiple independent deployments of identical bytecode land at
/// distinct accounts instead of colliding.
///
/// Domain-separated from other PDA-seed derivations in the codebase, including
/// [`segment_pda_seed`], so a header seed can never collide with a segment seed (or
/// anything else) even when the input triple coincides.
#[must_use]
pub fn header_pda_seed(image_id: ProgramId, segment_count: u32, update_auth: AccountId) -> PdaSeed {
    pda_seed(
        DEPLOY_HEADER_SEED_DOMAIN_SEPARATOR,
        image_id,
        segment_count,
        update_auth,
    )
}

/// Derives the PDA seed for a deployed program's bytecode segment account.
///
/// Same inputs as [`header_pda_seed`], domain-separated so the two never collide. Kept as a
/// distinct account from the header so identity checks never have to touch bytecode — see
/// `lee_core::program::ProgramData`'s doc for why that separation matters.
#[must_use]
pub fn segment_pda_seed(
    image_id: ProgramId,
    segment_count: u32,
    update_auth: AccountId,
) -> PdaSeed {
    pda_seed(
        DEPLOY_SEGMENT_SEED_DOMAIN_SEPARATOR,
        image_id,
        segment_count,
        update_auth,
    )
}

fn pda_seed(
    domain_separator: AccountId,
    image_id: ProgramId,
    segment_count: u32,
    update_auth: AccountId,
) -> PdaSeed {
    use risc0_zkvm::sha::{Impl, Sha256 as _};

    let mut bytes = [0_u8; 32 + 32 + 4 + 32];
    bytes[0..32].copy_from_slice(domain_separator.as_ref());
    let image_id_bytes: &[u8] =
        bytemuck::try_cast_slice(&image_id).expect("ProgramId should be castable to &[u8]");
    bytes[32..64].copy_from_slice(image_id_bytes);
    bytes[64..68].copy_from_slice(&segment_count.to_le_bytes());
    bytes[68..].copy_from_slice(update_auth.as_ref());

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
    image_id: ProgramId,
    segment_count: u32,
    update_auth: AccountId,
) -> AccountId {
    AccountId::for_public_pda(
        &loader_account_id,
        &header_pda_seed(image_id, segment_count, update_auth),
    )
}

#[must_use]
pub fn segment_account_id(
    loader_account_id: AccountId,
    image_id: ProgramId,
    segment_count: u32,
    update_auth: AccountId,
) -> AccountId {
    AccountId::for_public_pda(
        &loader_account_id,
        &segment_pda_seed(image_id, segment_count, update_auth),
    )
}

/// Plans the account shape for one batch of a (possibly multi-transaction) deploy.
///
/// Builds the header (unchanged formula — always `segment_number` 0, independent of
/// `segment_count`, so [`immutable_deploy_account_id`] stays stable regardless of how a deploy is
/// batched) plus `batch_user_elf` chunked at [`MAX_SEGMENT_DATA_LEN`], numbered `first_segment,
/// first_segment+1, ...`.
///
/// `segment_count` is the *total* across the whole deployment, not just this batch — written
/// into the header's `ProgramData` identically by every batch, so [`execute_deploy`]'s header
/// check can catch a caller who declares a different total between transactions. [`plan_deploy`]
/// is the single-batch (whole program, `first_segment` 0) special case of this — the single
/// source of truth both [`execute_deploy`] and `V03State::insert_program` build from, so live
/// deploys and genesis-seeded programs can never diverge on chunk boundaries, ordering, or PDA
/// derivation.
#[must_use]
pub fn plan_deploy_range(
    loader_account_id: AccountId,
    image_id: ProgramId,
    segment_count: u32,
    update_auth: AccountId,
    first_segment: u32,
    batch_user_elf: &[u8],
) -> DeployPlan {
    let header_seed = header_pda_seed(image_id, 0, update_auth);
    let header = PlannedAccount {
        account_id: AccountId::for_public_pda(&loader_account_id, &header_seed),
        seed: header_seed,
        data: borsh::to_vec(&ProgramData {
            image_id,
            segment_count,
            update_auth,
        })
        .expect("ProgramData borsh serialization should not fail"),
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
            let seed = segment_pda_seed(image_id, segment_number, update_auth);
            PlannedAccount {
                account_id: AccountId::for_public_pda(&loader_account_id, &seed),
                seed,
                data: chunk.to_vec(),
            }
        })
        .collect();

    DeployPlan { header, segments }
}

/// Computes the account shape (header + N bytecode segments) for deploying the whole of
/// `user_elf` at `image_id` under `update_auth` in a single batch. See [`plan_deploy_range`].
#[must_use]
pub fn plan_deploy(
    loader_account_id: AccountId,
    image_id: ProgramId,
    update_auth: AccountId,
    user_elf: &[u8],
) -> DeployPlan {
    let segment_count = segment_count_for(user_elf);
    plan_deploy_range(
        loader_account_id,
        image_id,
        segment_count,
        update_auth,
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

/// The dispatch address a program with `image_id` lives at once deployed via `Deploy` with no
/// upgrade authority.
///
/// `segment_count` 0, `update_auth` `AccountId::default()`. What every genesis-seeded builtin,
/// and any `Deploy` submitted with a default `update_auth`, dispatches at.
#[must_use]
pub fn immutable_deploy_account_id(image_id: ProgramId) -> AccountId {
    header_account_id(
        lee_core::program::PROGRAM_LOADER_ACCOUNT_ID,
        image_id,
        0,
        AccountId::default(),
    )
}

/// Executes one `Deploy` transaction — either a whole deployment in one shot, or one batch of a
/// multi-transaction deployment.
///
/// `image_id`/`segment_count` are caller-declared, not derived from `user_elf_batch` (a batch
/// covering only part of the program can't derive either from its own fragment). Whether that
/// declaration is trustworthy going into this call, and consequently what this transaction must
/// additionally prove, depends on whether `first_segment == 0` and `user_elf_batch` covers all
/// `segment_count` segments — i.e. whether this transaction is the whole deployment:
///
/// - **Whole deployment in one shot**: `user_elf_batch` is independently decoded and its real
///   `image_id` recomputed (combined with the assumed [`KERNEL_ELF`]) and checked against the
///   declared one right here — exactly as trustworthy as a single-transaction deploy, no signature
///   required.
/// - **A genuine partial batch**: `image_id`/`segment_count` can't be verified from what this
///   transaction alone carries — [`V03State::get_program`] only catches a mismatch once every
///   segment eventually exists. In the meantime, this transaction must instead prove control of
///   `update_auth`: `update_auth` must be non-default (there is no key to sign a partial deploy of
///   an immutable program with), included as this call's second `pre_states` entry, and
///   `is_authorized`. Every transaction in a partial sequence re-proves this independently, so no
///   one else can inject a rogue continuation into someone else's in-progress deployment either.
///
/// Derives the header and this batch's segment PDAs (chunking `user_elf_batch` across as many
/// segments as it covers, starting at `first_segment` — see [`plan_deploy_range`]) and claims
/// all of them. The header target may be `Account::default()` (starting a new deployment) or
/// already exactly this deployment's header (continuing one) — every other target must be
/// `Account::default()`, since each segment is written exactly once.
///
/// Called natively from dispatch's `PROGRAM_LOADER_ACCOUNT_ID` shortcut (see that
/// constant's doc comment in `lee_core::program`) — `Deploy` has no guest binary of its own.
#[must_use]
pub fn execute_deploy(
    self_account_id: AccountId,
    pre_states: &[AccountWithMetadata],
    user_elf_batch: &[u8],
    image_id: ProgramId,
    segment_count: u32,
    first_segment: u32,
    update_auth: AccountId,
) -> Vec<AccountPostState> {
    let plan = plan_deploy_range(
        self_account_id,
        image_id,
        segment_count,
        update_auth,
        first_segment,
        user_elf_batch,
    );
    let batch_end = first_segment
        .checked_add(u32::try_from(plan.segments.len()).expect("segment count fits in u32"))
        .expect("no overflow");
    assert!(
        batch_end <= segment_count,
        "Deploy batch runs past the declared segment_count"
    );
    let is_complete = first_segment == 0 && batch_end == segment_count;

    let (header_target, update_auth_target, segment_targets) = if is_complete {
        let real_image_id = compute_image_id(user_elf_batch)
            .expect("user_elf must decode as a valid RISC0 program binary");
        assert_eq!(
            image_id, real_image_id,
            "declared image_id does not match the submitted bytecode"
        );
        let (header_target, segment_targets) = pre_states
            .split_first()
            .expect("Deploy requires at least a header account");
        (header_target, None, segment_targets)
    } else {
        assert_ne!(
            update_auth,
            AccountId::default(),
            "a partial Deploy requires a real update_auth - an immutable program can only be \
             deployed in a single, self-contained transaction"
        );
        let (header_target, rest) = pre_states
            .split_first()
            .expect("Deploy requires at least a header account");
        let (update_auth_target, segment_targets) = rest
            .split_first()
            .expect("a partial Deploy requires an update_auth signer account after the header");
        assert_eq!(
            update_auth_target.account_id, update_auth,
            "second account of a partial Deploy must be the update_auth account"
        );
        assert!(
            update_auth_target.is_authorized,
            "a partial Deploy requires update_auth's signature"
        );
        (header_target, Some(update_auth_target), segment_targets)
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

    check_header_target(self_account_id, header_target, &plan.header);
    for (target, planned) in segment_targets.iter().zip(&plan.segments) {
        check_segment_target(target, planned);
    }

    // pre_states/post_states are matched positionally (see validate_execution), so an
    // update_auth signer slot present in pre_states must get a matching entry here too. Its
    // nonce gets bumped just by signing (independent of this program), so once it's ever
    // acted as a signer it's no longer `Account::default()` — left unclaimed, that combination
    // (non-default account, default owner) is permanently rejected by validate_execution on any
    // later batch that reuses it. Claiming it under the loader on its first use avoids that;
    // later batches then see it already loader-owned and just pass it through unchanged.
    let update_auth_post_state = update_auth_target.map(|target| {
        if target.account.program_owner == DEFAULT_PROGRAM_OWNER {
            AccountPostState::new_claimed(target.account.clone(), Claim::Authorized)
        } else {
            AccountPostState::new(target.account.clone())
        }
    });

    // A fresh header claims default->owned via Claim::Pda, same as -7. An idempotent re-claim
    // (a later batch in the same sequence revisiting the header) must mirror the pre-state
    // exactly instead — validate_execution rejects any post-state whose program_owner differs
    // from pre, and the header's real program_owner is already set from the earlier batch's
    // claim by this point, not the default placeholder a fresh claim's post-state carries.
    let header_post_state = if header_target.account == Account::default() {
        AccountPostState::new_claimed(
            Account {
                data: Data::try_from(plan.header.data.clone())
                    .expect("elf chunk must fit under DATA_MAX_LENGTH"),
                ..Account::default()
            },
            Claim::Pda(plan.header.seed),
        )
    } else {
        AccountPostState::new(header_target.account.clone())
    };

    std::iter::once(header_post_state)
        .chain(update_auth_post_state)
        .chain(plan.segments.iter().map(|planned| {
            AccountPostState::new_claimed(
                Account {
                    data: Data::try_from(planned.data.clone())
                        .expect("elf chunk must fit under DATA_MAX_LENGTH"),
                    ..Account::default()
                },
                Claim::Pda(planned.seed),
            )
        }))
        .collect()
}

/// The header may either be a fresh claim (`Account::default()`) or an idempotent re-claim of
/// exactly this deployment's already-written header — never anything else.
fn check_header_target(
    self_account_id: AccountId,
    target: &AccountWithMetadata,
    planned: &PlannedAccount,
) {
    assert_eq!(
        target.account_id, planned.account_id,
        "wrong deployment target account"
    );
    let already_this_header = Account {
        program_owner: self_account_id,
        data: Data::try_from(planned.data.clone())
            .expect("elf chunk must fit under DATA_MAX_LENGTH"),
        ..Account::default()
    };
    assert!(
        target.account == Account::default() || target.account == already_this_header,
        "header must be untouched, or already exactly this deployment's header"
    );
}

/// Every segment target must be untouched — each segment is written exactly once, whether this
/// is the transaction that first claims it or a later one revisiting the same range by mistake.
fn check_segment_target(target: &AccountWithMetadata, planned: &PlannedAccount) {
    assert_eq!(
        target.account_id, planned.account_id,
        "wrong deployment target account"
    );
    assert_eq!(
        target.account,
        Account::default(),
        "segment already deployed"
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    const IMAGE_ID: ProgramId = [1, 2, 3, 4, 5, 6, 7, 8];
    const LOADER_ID: AccountId = AccountId::new([9; 32]);
    const REAL_UPDATE_AUTH: AccountId = AccountId::new([42; 32]);

    fn plan_for(len: usize) -> DeployPlan {
        let user_elf = vec![0xAB_u8; len];
        plan_deploy(LOADER_ID, IMAGE_ID, AccountId::default(), &user_elf)
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
            let plan = plan_deploy(LOADER_ID, IMAGE_ID, AccountId::default(), &user_elf);
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
            let whole = plan_deploy(LOADER_ID, IMAGE_ID, AccountId::default(), &user_elf);
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

                let batch1 = plan_deploy_range(
                    LOADER_ID,
                    IMAGE_ID,
                    segment_count,
                    AccountId::default(),
                    0,
                    first_bytes,
                );
                let batch2 = plan_deploy_range(
                    LOADER_ID,
                    IMAGE_ID,
                    segment_count,
                    AccountId::default(),
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

    #[test]
    fn execute_deploy_single_batch_still_works() {
        let program = test_programs::claimer();
        let user_elf = extract_user_elf(program.elf()).unwrap();
        let image_id = program.id();

        let plan = plan_deploy(LOADER_ID, image_id, AccountId::default(), &user_elf);
        let segment_count = u32::try_from(plan.segments.len()).unwrap();

        let mut pre_states = vec![header_target(&plan, Account::default())];
        pre_states.extend(fresh_segment_targets(&plan));

        let post_states = execute_deploy(
            LOADER_ID,
            &pre_states,
            &user_elf,
            image_id,
            segment_count,
            0,
            AccountId::default(),
        );
        assert_eq!(post_states.len(), 1 + plan.segments.len());
    }

    #[test]
    fn execute_deploy_two_batch_sequence_succeeds() {
        let program = test_programs::claimer();
        let user_elf = extract_user_elf(program.elf()).unwrap();
        let image_id = program.id();
        let plan = plan_deploy(LOADER_ID, image_id, REAL_UPDATE_AUTH, &user_elf);
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
            REAL_UPDATE_AUTH,
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
            image_id,
            segment_count,
            0,
            REAL_UPDATE_AUTH,
        );
        assert_eq!(post1.len(), 2 + batch1_plan.segments.len());

        // `execute_deploy`'s own return value leaves `program_owner` at the default placeholder
        // — the caller (validated_state_diff's claim processing) is what sets the real owner
        // once a Claim::Pda is approved. What batch 2 actually sees as the header's pre-state is
        // the *post-claim-processing* account, so reconstruct that directly rather than reusing
        // `post1[0].account()` verbatim.
        let header_after_batch1 = Account {
            program_owner: LOADER_ID,
            data: Data::try_from(batch1_plan.header.data).unwrap(),
            ..Account::default()
        };

        // Batch 2: header (already-deployed, matching) + signer + segments[split..]
        let batch2_plan = plan_deploy_range(
            LOADER_ID,
            image_id,
            segment_count,
            REAL_UPDATE_AUTH,
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
            image_id,
            segment_count,
            u32::try_from(split).unwrap(),
            REAL_UPDATE_AUTH,
        );
        assert_eq!(post2.len(), 2 + batch2_plan.segments.len());
    }

    #[test]
    #[should_panic(expected = "a partial Deploy requires a real update_auth")]
    fn execute_deploy_rejects_a_partial_batch_with_default_update_auth() {
        let program = test_programs::claimer();
        let user_elf = extract_user_elf(program.elf()).unwrap();
        let image_id = program.id();
        let plan = plan_deploy(LOADER_ID, image_id, AccountId::default(), &user_elf);
        assert!(plan.segments.len() > 1, "need a real multi-segment program");
        let segment_count = u32::try_from(plan.segments.len()).unwrap();
        let split = plan.segments.len() - 1;
        let byte_split: usize = plan.segments[..split].iter().map(|s| s.data.len()).sum();
        let (first_bytes, _second_bytes) = user_elf.split_at(byte_split);

        let batch_plan = plan_deploy_range(
            LOADER_ID,
            image_id,
            segment_count,
            AccountId::default(),
            0,
            first_bytes,
        );
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
            image_id,
            segment_count,
            0,
            AccountId::default(),
        );
    }

    #[test]
    #[should_panic(expected = "requires update_auth's signature")]
    fn execute_deploy_rejects_a_partial_batch_without_update_auths_signature() {
        let program = test_programs::claimer();
        let user_elf = extract_user_elf(program.elf()).unwrap();
        let image_id = program.id();
        let plan = plan_deploy(LOADER_ID, image_id, REAL_UPDATE_AUTH, &user_elf);
        assert!(plan.segments.len() > 1, "need a real multi-segment program");
        let segment_count = u32::try_from(plan.segments.len()).unwrap();
        let split = plan.segments.len() - 1;
        let byte_split: usize = plan.segments[..split].iter().map(|s| s.data.len()).sum();
        let (first_bytes, _second_bytes) = user_elf.split_at(byte_split);

        let batch_plan = plan_deploy_range(
            LOADER_ID,
            image_id,
            segment_count,
            REAL_UPDATE_AUTH,
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
            image_id,
            segment_count,
            0,
            REAL_UPDATE_AUTH,
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
        let plan = plan_deploy_range(LOADER_ID, image_id, 1, AccountId::default(), 0, &user_elf);
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
            image_id,
            1,
            0,
            AccountId::default(),
        );
    }

    #[test]
    #[should_panic(expected = "must include at least one segment")]
    fn execute_deploy_rejects_header_only_batch() {
        let plan = plan_deploy_range(LOADER_ID, IMAGE_ID, 2, REAL_UPDATE_AUTH, 2, &[]);
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
            IMAGE_ID,
            2,
            2,
            REAL_UPDATE_AUTH,
        );
    }

    #[test]
    #[should_panic(expected = "segment already deployed")]
    fn execute_deploy_rejects_rewriting_a_written_segment() {
        let program = test_programs::claimer();
        let user_elf = extract_user_elf(program.elf()).unwrap();
        let image_id = program.id();
        let plan = plan_deploy(LOADER_ID, image_id, AccountId::default(), &user_elf);
        let segment_count = u32::try_from(plan.segments.len()).unwrap();

        let mut pre_states = vec![header_target(&plan, Account::default())];
        // First segment already claimed (non-default), rest fresh.
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
            image_id,
            segment_count,
            0,
            AccountId::default(),
        );
    }

    #[test]
    #[should_panic(expected = "declared image_id does not match the submitted bytecode")]
    fn execute_deploy_rejects_a_complete_batch_with_a_dishonest_image_id() {
        let program = test_programs::claimer();
        let user_elf = extract_user_elf(program.elf()).unwrap();
        let dishonest_image_id = [99, 99, 99, 99, 99, 99, 99, 99];
        let segment_count = segment_count_for(&user_elf);

        let plan = plan_deploy(
            LOADER_ID,
            dishonest_image_id,
            AccountId::default(),
            &user_elf,
        );
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
            dishonest_image_id,
            segment_count,
            0,
            AccountId::default(),
        );
    }

    #[test]
    fn full_round_trip_against_a_real_program() {
        let program = test_programs::claimer();
        let full_binary = program.elf();
        let user_elf = extract_user_elf(full_binary).unwrap();

        let plan = plan_deploy(LOADER_ID, program.id(), AccountId::default(), &user_elf);
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
