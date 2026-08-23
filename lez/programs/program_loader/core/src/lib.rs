use borsh::{BorshDeserialize, BorshSerialize};
pub use lee_core::program::{PdaSeed, ProgramData};
use lee_core::{
    account::{Account, AccountId, AccountWithMetadata, Data},
    program::{AccountPostState, Claim, ProgramId},
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
    /// Deploys a new program: writes its `ProgramData` header and as many bytecode segments as
    /// its size requires (see [`MAX_SEGMENT_DATA_LEN`]), each claimed as a PDA of the loader.
    ///
    /// The bytecode itself travels via the dispatching message's `raw_payload`, not this
    /// instruction — see `Message::raw_payload`'s doc comment for why.
    ///
    /// Required accounts (1 + `segment_count`, where `segment_count` is determined by the
    /// submitted bytecode's length — see [`plan_deploy`]), in order:
    /// - The target `ProgramData` header PDA account (must be `Account::default()`)
    /// - The target segment PDA accounts holding the raw bytecode, in segment order (each must be
    ///   `Account::default()`)
    Deploy {
        /// Distinguishes independent deployments of identical bytecode (same `image_id`) from
        /// one another, so a second deployer never collides with an existing deployment's PDAs.
        /// Also who may redeploy this same slot in the future once upgrade authority is
        /// implemented (a future PR) — for now this is a placeholder with no enforcement.
        /// `AccountId::default()` means no upgrade authority (immutable).
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
/// Same inputs as [`header_pda_seed`], domain-separated so the two never collide. Kept as
/// a distinct account from the header specifically so that authenticating a program's identity
/// (e.g. for privacy-preserving proof verification) never has to touch its bytecode: the only
/// account-authentication primitive available is whole-account equality, so what's bundled into
/// one account sets the floor for how cheap that authentication can be.
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

/// Computes the account shape (header + N bytecode segments, chunked at
/// [`MAX_SEGMENT_DATA_LEN`]) for deploying `user_elf` at `image_id` under `update_auth`.
///
/// The single source of truth both [`execute_deploy`] and `V03State::insert_program` build from —
/// so live deploys and genesis-seeded programs can never diverge on chunk boundaries, ordering,
/// or PDA derivation.
#[must_use]
pub fn plan_deploy(
    loader_account_id: AccountId,
    image_id: ProgramId,
    update_auth: AccountId,
    user_elf: &[u8],
) -> DeployPlan {
    let chunks: Vec<&[u8]> = if user_elf.is_empty() {
        vec![&[]]
    } else {
        user_elf.chunks(MAX_SEGMENT_DATA_LEN).collect()
    };
    let segment_count = u32::try_from(chunks.len()).expect("segment count fits in u32");

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

    let segments = chunks
        .into_iter()
        .enumerate()
        .map(|(i, chunk)| {
            let segment_number = u32::try_from(i).expect("segment index fits in u32");
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

/// Executes the `Deploy` instruction.
///
/// Verifies `user_elf` decodes as a valid RISC0 program (combined with the assumed
/// [`KERNEL_ELF`]), derives its header and segment PDAs (chunking `user_elf` across as many
/// segments as [`plan_deploy`] reports), and claims all of them.
///
/// Called natively from dispatch's `PROGRAM_LOADER_ACCOUNT_ID` shortcut (see that constant's
/// doc comment in `lee_core::program`) — `Deploy` has no guest binary of its own.
#[must_use]
pub fn execute_deploy(
    self_account_id: AccountId,
    pre_states: &[AccountWithMetadata],
    user_elf: &[u8],
    update_auth: AccountId,
) -> Vec<AccountPostState> {
    let image_id =
        compute_image_id(user_elf).expect("user_elf must decode as a valid RISC0 program binary");
    let plan = plan_deploy(self_account_id, image_id, update_auth, user_elf);

    let expected_len = plan
        .segments
        .len()
        .checked_add(1)
        .expect("segment count fits in usize");
    assert_eq!(
        pre_states.len(),
        expected_len,
        "Deploy requires exactly 1 header + segment_count segment accounts"
    );
    let (header_target, segment_targets) =
        pre_states.split_first().expect("checked non-empty above");

    check_deploy_target(header_target, &plan.header);
    for (target, planned) in segment_targets.iter().zip(&plan.segments) {
        check_deploy_target(target, planned);
    }

    std::iter::once(&plan.header)
        .chain(&plan.segments)
        .map(|planned| {
            AccountPostState::new_claimed(
                Account {
                    data: Data::try_from(planned.data.clone())
                        .expect("elf chunk must fit under DATA_MAX_LENGTH"),
                    ..Account::default()
                },
                Claim::Pda(planned.seed),
            )
        })
        .collect()
}

fn check_deploy_target(target: &AccountWithMetadata, planned: &PlannedAccount) {
    assert_eq!(
        target.account_id, planned.account_id,
        "wrong deployment target account"
    );
    assert_eq!(
        target.account,
        Account::default(),
        "program already deployed"
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    const IMAGE_ID: ProgramId = [1, 2, 3, 4, 5, 6, 7, 8];
    const LOADER_ID: AccountId = AccountId::new([9; 32]);

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
