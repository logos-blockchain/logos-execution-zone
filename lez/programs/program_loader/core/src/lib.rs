//! Core logic for `program_loader`, the native (non-guest) pseudo-program that deploys and
//! updates programs living at [`PROGRAM_LOADER_ACCOUNT_ID`].
//!
//! Deployment is permissionless by construction, not by an explicit claim: every instruction
//! here writes only to accounts that start out `Account::default()` (unowned), and ownership of
//! an unowned account transfers to whoever writes its data first — see
//! `lee_core::program::acquire_ownership_on_data_write`. There is no separate authorization step
//! for a fresh segment or header; the write itself is the claim. Updating an existing header is
//! the one operation that isn't permissionless, since it mutates an account the loader already
//! owns — that requires the caller to be `is_authorized` for it, checked here directly rather
//! than through the diff-validation rules (which only gate balance decreases on authorization).
use borsh::{BorshDeserialize, BorshSerialize};
pub use lee_core::program::{MAX_PROGRAM_SEGMENTS, ProgramHeader, ProgramSegment};
use lee_core::{
    account::{Account, AccountId, AccountWithMetadata, BalanceDiff, Data},
    program::{AccountStateDiff, PROGRAM_LOADER_ACCOUNT_ID, ProgramId},
};

/// Recommended max bytes of bytecode per segment.
///
/// Not enforced here — `Data::try_from` in `write_segment` rejects an oversized segment against
/// the account's own `DATA_MAX_LENGTH` cap regardless — this just keeps a live deploy's segments
/// comfortably under it.
pub const MAX_SEGMENT_DATA_LEN: usize = 96 * 1024;

/// Variants are append-only. Borsh encodes the variant as a leading tag byte, so inserting one
/// ahead of `WriteSegment` shifts every existing encoding.
#[derive(Clone, Debug, BorshSerialize, BorshDeserialize)]
pub enum Instruction {
    /// Writes one new bytecode segment at `pre_states[0]` (must be `Account::default()` —
    /// write-once, no instruction edits a segment after creation). Permissionless: no
    /// authorization is required of `pre_states[0]`, since writing an unowned account's data is
    /// itself how the loader comes to own it.
    ///
    /// If `next_segment` is `Some`, that account must already hold a valid [`ProgramSegment`]
    /// (read-only, `pre_states[1]`) — chains are always linked tail-to-head, so a segment can
    /// only reference one that's already real.
    ///
    /// Required accounts (1, or 2 if `next_segment` is `Some`).
    WriteSegment {
        bytecode: Vec<u8>,
        next_segment: Option<AccountId>,
    },
    /// Creates a new program header at `pre_states[0]` (must be `Account::default()`;
    /// permissionless for the same reason as `WriteSegment`). `pre_states[1..]` is the segment
    /// chain from `first_segment`, in link order, read-only. `image_id` is always recomputed
    /// from the chain, never taken from the caller.
    ///
    /// Required accounts (1 + the segment chain length).
    CreateHeader {
        first_segment: AccountId,
        immutable: bool,
    },
    /// Rewrites an existing header at `pre_states[0]` (must already hold a valid
    /// [`ProgramHeader`], be `is_authorized`, and not already be `immutable`). Unlike the other
    /// two instructions this is an ordinary mutation of an account the loader already owns, so
    /// it needs the authorization the other two don't. Same chain/`image_id` handling as
    /// `CreateHeader`.
    ///
    /// Required accounts (1 + the segment chain length).
    UpdateHeader {
        first_segment: AccountId,
        immutable: bool,
    },
}

/// Executes `WriteSegment`.
#[must_use]
pub fn write_segment(
    pre_states: &[AccountWithMetadata],
    bytecode: Vec<u8>,
    next_segment: Option<AccountId>,
) -> Vec<AccountStateDiff> {
    let expected_len = if next_segment.is_some() { 2 } else { 1 };
    let (target, rest) = pre_states
        .split_first()
        .unwrap_or_else(|| panic!("WriteSegment requires exactly {expected_len} account(s)"));
    assert_eq!(
        pre_states.len(),
        expected_len,
        "WriteSegment requires exactly {expected_len} account(s)"
    );
    assert_eq!(
        target.account,
        Account::default(),
        "segment target already deployed"
    );

    let mut diffs = vec![AccountStateDiff::new(
        target.clone(),
        BalanceDiff::Add(0),
        Data::try_from(
            ProgramSegment {
                bytecode,
                next_segment,
            }
            .to_bytes(),
        )
        .expect("segment must fit under DATA_MAX_LENGTH"),
    )];

    if let (Some(next), [referenced]) = (next_segment, rest) {
        assert_eq!(
            referenced.account_id, next,
            "second account must be the segment `next_segment` points to"
        );
        assert_eq!(
            referenced.account.program_owner, PROGRAM_LOADER_ACCOUNT_ID,
            "`next_segment` must be loader-owned"
        );
        assert!(
            ProgramSegment::from_bytes(&referenced.account.data).is_some(),
            "`next_segment` must already hold a valid segment \u{2014} segments are linked tail-to-head"
        );
        diffs.push(AccountStateDiff::unchanged(referenced.clone()));
    }

    diffs
}

/// Executes `CreateHeader`.
#[must_use]
pub fn create_header(
    pre_states: &[AccountWithMetadata],
    first_segment: AccountId,
    immutable: bool,
) -> Vec<AccountStateDiff> {
    assert!(
        !pre_states.is_empty(),
        "CreateHeader requires at least the header target account"
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

    let image_id = compute_image_id(pre_states);

    let mut diffs = vec![AccountStateDiff::new(
        pre_states[0].clone(),
        BalanceDiff::Add(0),
        Data::try_from(
            ProgramHeader {
                image_id,
                program_first_segment: first_segment,
                immutable,
            }
            .to_bytes(),
        )
        .expect("program header must fit under DATA_MAX_LENGTH"),
    )];
    diffs.extend(
        pre_states[1..]
            .iter()
            .map(|pre| AccountStateDiff::unchanged(pre.clone())),
    );
    diffs
}

/// Executes `UpdateHeader`.
#[must_use]
pub fn update_header(
    pre_states: &[AccountWithMetadata],
    first_segment: AccountId,
    immutable: bool,
) -> Vec<AccountStateDiff> {
    assert!(
        !pre_states.is_empty(),
        "UpdateHeader requires at least the header target account"
    );
    let old_header = ProgramHeader::from_bytes(&pre_states[0].account.data).expect(
        "UpdateHeader target must already hold a valid header \u{2014} use CreateHeader to make one",
    );
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

    let image_id = compute_image_id(pre_states);

    let mut diffs = vec![AccountStateDiff::new(
        pre_states[0].clone(),
        BalanceDiff::Add(0),
        Data::try_from(
            ProgramHeader {
                image_id,
                program_first_segment: first_segment,
                immutable,
            }
            .to_bytes(),
        )
        .expect("program header must fit under DATA_MAX_LENGTH"),
    )];
    diffs.extend(
        pre_states[1..]
            .iter()
            .map(|pre| AccountStateDiff::unchanged(pre.clone())),
    );
    diffs
}

/// `segments_with_header[0]` is the header account, not part of the chain. Walks
/// `segments_with_header[1..]`, which must appear in exact link order, concatenating bytecode
/// and recomputing the real `image_id` over the result — the same walk `get_program_via` does at
/// resolution time, so a program built here decodes exactly as it will later execute. Never
/// trusts a caller-supplied `image_id`, and rejects a chain over `MAX_PROGRAM_SEGMENTS`.
///
/// Segments only ever hold `user_elf`; the protocol's default kernel is re-attached here
/// before the image id is computed.
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
        let segment = ProgramSegment::from_bytes(&pre.account.data)
            .expect("every supplied segment account must decode as a valid ProgramSegment");
        elf.extend_from_slice(&segment.bytecode);
        expected_next = segment.next_segment;
    }
    assert!(
        expected_next.is_none(),
        "the chain continues past the last supplied segment account"
    );

    let full_binary =
        risc0_binfmt::ProgramBinary::new(&elf, risc0_zkos_v1compat::V1COMPAT_ELF).encode();
    risc0_binfmt::compute_image_id(&full_binary)
        .expect("concatenated segment bytecode must decode as a valid RISC0 program binary")
        .into()
}

#[cfg(test)]
mod tests;
