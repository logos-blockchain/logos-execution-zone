use borsh::{BorshDeserialize, BorshSerialize};
pub use lee_core::program::{ProgramHeader, ProgramSegment};
use lee_core::{
    account::{Account, AccountId, AccountWithMetadata, Data},
    program::{AccountPostState, Claim, PROGRAM_LOADER_ACCOUNT_ID, ProgramId},
};

/// Max bytes of bytecode per segment. Under `DATA_MAX_LENGTH` with headroom for a segment's own
/// borsh framing; not enforced here — `Data::try_from` in `write_segment` does that.
pub const MAX_SEGMENT_DATA_LEN: usize = 96 * 1024;

/// Hard cap on a deployed program's segment chain length (~2 MiB of bytecode at 96 KiB/segment).
pub const MAX_PROGRAM_SEGMENTS: usize = 20;

#[derive(BorshSerialize, BorshDeserialize)]
pub enum Instruction {
    /// Writes one new bytecode segment at `pre_states[0]` (must be `Account::default()`, claimed
    /// via `Claim::Authorized` — no derivation requirement, see [`ProgramSegment`]). Write-once:
    /// no instruction edits a segment after creation.
    ///
    /// If `next_segment` is `Some`, that account must already hold a valid [`ProgramSegment`]
    /// (read-only, `pre_states[1]`) — chains are always linked tail-to-head.
    WriteSegment {
        bytecode: Vec<u8>,
        next_segment: Option<AccountId>,
    },
    /// Creates a new program header at `pre_states[0]` (must be `Account::default()`, claimed via
    /// `Claim::Authorized`). `pre_states[1..]` is the segment chain from `first_segment`, in link
    /// order, read-only. `image_id` is always recomputed from the chain, never taken from the
    /// caller.
    CreateHeader {
        first_segment: AccountId,
        immutable: bool,
    },
    /// Rewrites an existing header at `pre_states[0]` (must already hold a valid
    /// [`ProgramHeader`], be `is_authorized`, and not already be `immutable`) — an ordinary data
    /// mutation, not a claim. Same chain/`image_id` handling as `CreateHeader`.
    UpdateHeader {
        first_segment: AccountId,
        immutable: bool,
    },
}

/// The `AccountId` a genesis-seeded builtin's header lives at: the bijection of its `image_id`.
/// A live `Deploy`'d program has no such deterministic address — its deployer chooses the header
/// account directly. Kept under this name for the many call sites needing "builtin X's address."
#[must_use]
pub fn immutable_deploy_account_id(image_id: ProgramId) -> AccountId {
    AccountId::from(image_id)
}

/// The deterministic `AccountId` a genesis builtin's `segment_number`'th segment lives at. Only
/// genesis uses this — a live `Deploy` claims arbitrary, deployer-chosen accounts instead, since
/// it has a real signer; genesis doesn't, so `V03State::insert_program` needs a way to
/// precompute segment addresses before inserting them directly.
#[must_use]
pub fn genesis_segment_account_id(header_account_id: AccountId, segment_number: u32) -> AccountId {
    use risc0_zkvm::sha::{Impl, Sha256 as _};
    const GENESIS_SEGMENT_ID_PREFIX: &[u8; 32] = b"/LEE/v0.3/AccountId/GenesisSeg/\x00";

    let mut bytes = [0_u8; 32 + 32 + 4];
    bytes[0..32].copy_from_slice(GENESIS_SEGMENT_ID_PREFIX);
    bytes[32..64].copy_from_slice(header_account_id.as_ref());
    bytes[64..].copy_from_slice(&segment_number.to_le_bytes());
    AccountId::new(
        Impl::hash_bytes(&bytes)
            .as_bytes()
            .try_into()
            .expect("Hash output must be exactly 32 bytes long"),
    )
}

/// Executes `NewSegment`.
#[must_use]
pub fn write_segment(
    pre_states: Vec<AccountWithMetadata>,
    bytecode: Vec<u8>,
    next_segment: Option<AccountId>,
) -> Vec<AccountPostState> {
    let expected_len = if next_segment.is_some() { 2 } else { 1 };
    assert_eq!(
        pre_states.len(),
        expected_len,
        "NewSegment requires exactly {expected_len} account(s)"
    );

    assert_eq!(
        pre_states[0].account,
        Account::default(),
        "segment target already deployed"
    );

    let mut post_states = Vec::with_capacity(pre_states.len());
    post_states.push(AccountPostState::new_claimed(
        Account {
            data: Data::from(&ProgramSegment {
                bytecode,
                next_segment,
            }),
            ..Account::default()
        },
        Claim::Authorized,
    ));

    if let Some(next) = next_segment {
        let referenced = &pre_states[1];
        assert_eq!(
            referenced.account_id, next,
            "second account must be the segment `next_segment` points to"
        );
        assert_eq!(
            referenced.account.program_owner, PROGRAM_LOADER_ACCOUNT_ID,
            "`next_segment` must be loader-owned"
        );
        assert!(
            ProgramSegment::try_from(&referenced.account.data).is_ok(),
            "`next_segment` must already hold a valid segment — segments are linked tail-to-head"
        );
        post_states.push(AccountPostState::new(referenced.account.clone()));
    }

    post_states
}

/// Executes `UploadHeader`.
#[must_use]
pub fn create_header(
    pre_states: Vec<AccountWithMetadata>,
    first_segment: AccountId,
    immutable: bool,
) -> Vec<AccountPostState> {
    assert!(
        !pre_states.is_empty(),
        "UploadHeader requires at least the header target account"
    );
    assert_eq!(
        pre_states[0].account,
        Account::default(),
        "header target already deployed"
    );
    assert_eq!(
        pre_states.get(1).map(|pre| pre.account_id),
        Some(first_segment),
        "first_segment must match the first supplied segment account"
    );

    let image_id = compute_image_id(&pre_states);

    let mut post_states = vec![AccountPostState::new_claimed(
        Account {
            data: Data::from(&ProgramHeader {
                image_id,
                program_first_segment: first_segment,
                immutable,
            }),
            ..Account::default()
        },
        Claim::Authorized,
    )];
    post_states.extend(
        pre_states[1..]
            .iter()
            .map(|pre| AccountPostState::new(pre.account.clone())),
    );
    post_states
}

/// Executes `UpdateHeader`.
#[must_use]
pub fn update_header(
    pre_states: Vec<AccountWithMetadata>,
    first_segment: AccountId,
    immutable: bool,
) -> Vec<AccountPostState> {
    assert!(
        !pre_states.is_empty(),
        "UpdateHeader requires at least the header target account"
    );
    let old_header = ProgramHeader::try_from(&pre_states[0].account.data)
        .expect("UpdateHeader target must already hold a valid header — use UploadHeader to create one");
    assert!(
        !old_header.immutable,
        "UpdateHeader target is immutable and cannot be updated"
    );
    assert!(
        pre_states[0].is_authorized,
        "UpdateHeader target must be authorized by the signer"
    );
    assert_eq!(
        pre_states.get(1).map(|pre| pre.account_id),
        Some(first_segment),
        "first_segment must match the first supplied segment account"
    );

    let image_id = compute_image_id(&pre_states);

    let mut post_states = vec![AccountPostState::new(Account {
        data: Data::from(&ProgramHeader {
            image_id,
            program_first_segment: first_segment,
            immutable,
        }),
        ..pre_states[0].account.clone()
    })];
    post_states.extend(
        pre_states[1..]
            .iter()
            .map(|pre| AccountPostState::new(pre.account.clone())),
    );
    post_states
}

/// `segments_with_header[0]` is the header account, not part of the chain. Walks
/// `segments_with_header[1..]`, which must appear in exact link order, concatenating bytecode
/// and recomputing the real `image_id` over the result. Never trusts a caller-supplied
/// `image_id`, and rejects a chain over `MAX_PROGRAM_SEGMENTS`.
fn compute_image_id(segments_with_header: &[AccountWithMetadata]) -> ProgramId {
    let mut elf = Vec::new();
    let mut expected_next = segments_with_header.get(1).map(|pre| pre.account_id);
    let mut segment_count = 0_usize;
    for pre in &segments_with_header[1..] {
        segment_count = segment_count.saturating_add(1);
        assert!(
            segment_count <= MAX_PROGRAM_SEGMENTS,
            "segment chain exceeds the {MAX_PROGRAM_SEGMENTS}-segment cap"
        );
        let account_id = expected_next.expect(
            "chain ended (a segment declared `next_segment: None`) before all supplied \
             segment accounts were consumed",
        );
        assert_eq!(
            pre.account_id, account_id,
            "segment accounts must be supplied in exact chain order"
        );
        assert_eq!(
            pre.account.program_owner, PROGRAM_LOADER_ACCOUNT_ID,
            "segment {account_id} must be loader-owned"
        );
        let segment = ProgramSegment::try_from(&pre.account.data)
            .expect("every supplied segment account must decode as a valid ProgramSegment");
        elf.extend_from_slice(&segment.bytecode);
        expected_next = segment.next_segment;
    }
    assert!(
        expected_next.is_none(),
        "the chain continues past the last supplied segment account"
    );

    risc0_binfmt::compute_image_id(&elf)
        .expect("concatenated segment bytecode must decode as a valid RISC0 program binary")
        .into()
}
