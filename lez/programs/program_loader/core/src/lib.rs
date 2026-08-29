use borsh::{BorshDeserialize, BorshSerialize};
pub use lee_core::program::{ProgramHeader, ProgramSegment};
use lee_core::{
    account::{Account, AccountId, AccountWithMetadata, Data},
    program::{AccountPostState, Claim, ProgramId},
};

/// Max bytes of bytecode per segment. Under `DATA_MAX_LENGTH` with headroom for a segment's own
/// borsh framing; not enforced here — `Data::try_from` in `execute_new_segment` does that.
pub const MAX_SEGMENT_DATA_LEN: usize = 96 * 1024;

#[derive(BorshSerialize, BorshDeserialize)]
pub enum Instruction {
    /// Writes one new bytecode segment at `pre_states[0]` (must be `Account::default()`, claimed
    /// via `Claim::Authorized` — no derivation requirement, see [`ProgramSegment`]). Write-once:
    /// no instruction edits a segment after creation.
    ///
    /// If `next_segment` is `Some`, that account must already hold a valid [`ProgramSegment`]
    /// (read-only, `pre_states[1]`) — chains are always linked tail-to-head.
    NewSegment {
        bytecode: Vec<u8>,
        next_segment: Option<AccountId>,
    },
    /// Creates a new program header at `pre_states[0]` (must be `Account::default()`, claimed via
    /// `Claim::Authorized`). `pre_states[1..]` is the segment chain from `first_segment`, in link
    /// order, read-only. `image_id` is always recomputed from the chain, never taken from the
    /// caller.
    UploadHeader {
        first_segment: AccountId,
        immutable: bool,
    },
    /// Rewrites an existing header at `pre_states[0]` (must already hold a valid
    /// [`ProgramHeader`] and be `is_authorized`) — an ordinary data mutation, not a claim. The
    /// existing header's `immutable` is never consulted; whether an update is possible is purely
    /// a matter of who still controls the account. Same chain/`image_id` handling as
    /// `UploadHeader`.
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
pub fn execute_new_segment(
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
pub fn execute_upload_header(
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

    let image_id = recompute_image_id(&pre_states, first_segment);

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
pub fn execute_update_header(
    pre_states: Vec<AccountWithMetadata>,
    first_segment: AccountId,
    immutable: bool,
) -> Vec<AccountPostState> {
    assert!(
        !pre_states.is_empty(),
        "UpdateHeader requires at least the header target account"
    );
    assert!(
        ProgramHeader::try_from(&pre_states[0].account.data).is_ok(),
        "UpdateHeader target must already hold a valid header — use UploadHeader to create one"
    );
    assert!(
        pre_states[0].is_authorized,
        "UpdateHeader target must be authorized by the signer"
    );

    let image_id = recompute_image_id(&pre_states, first_segment);

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

/// Walks the segment chain starting at `first_segment` — `pre_states[1..]`, which must appear in
/// exactly link order — concatenating bytecode and recomputing the real `image_id` over the
/// result. Never trusts a caller-supplied `image_id`.
fn recompute_image_id(pre_states: &[AccountWithMetadata], first_segment: AccountId) -> ProgramId {
    let mut elf = Vec::new();
    let mut expected_next = Some(first_segment);
    for pre in &pre_states[1..] {
        let account_id = expected_next.expect(
            "chain ended (a segment declared `next_segment: None`) before all supplied \
             segment accounts were consumed",
        );
        assert_eq!(
            pre.account_id, account_id,
            "segment accounts must be supplied in exact chain order starting at `first_segment`"
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
