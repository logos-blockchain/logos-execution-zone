//! Native program deployment and updates through [`PROGRAM_LOADER_ACCOUNT_ID`].
//!
//! Writing a fresh segment or header is permissionless — a still-empty loader shard has no prior
//! claim to violate — but a header target must always be `is_authorized`, so a real header can't
//! be squatted at an address some other account id (e.g. a shadow program's) will later resolve
//! to. Checked here directly rather than through the diff-validation rules.
use borsh::{BorshDeserialize, BorshSerialize};
pub use lee_core::program::{
    MAX_PROGRAM_SEGMENTS, ProgramHeader, ProgramSegment, immutable_mirror_commitment,
};
use lee_core::{
    Commitment,
    account::{AccountId, BalanceDiff, ShardData},
    program::{AccountInput, AccountStateDiff, PROGRAM_LOADER_ACCOUNT_ID, ProgramId},
};

/// Recommended max bytes of bytecode per segment.
///
/// Not enforced here — `ShardData::try_from` in `write_segment` rejects an oversized segment
/// against the account's own `DATA_MAX_LENGTH` cap regardless — this just keeps a live deploy's
/// segments comfortably under it.
pub const MAX_SEGMENT_DATA_LEN: usize = 96 * 1024;

/// Variants are append-only. Borsh encodes the variant as a leading tag byte, so inserting one
/// ahead of `WriteSegment` shifts every existing encoding.
#[derive(Clone, Debug, BorshSerialize, BorshDeserialize)]
pub enum Instruction {
    /// Writes a new segment to the empty loader shard of `pre_states[0]`, without authorization.
    ///
    /// If `next_segment` is `Some`, `pre_states[1]` must be that account and contain a valid
    /// [`ProgramSegment`] in its loader shard. Segments are immutable and linked from tail to head.
    ///
    /// Required accounts (1, or 2 if `next_segment` is `Some`).
    WriteSegment {
        bytecode: Vec<u8>,
        next_segment: Option<AccountId>,
    },
    /// Creates a header in the empty loader shard of `pre_states[0]`, which must be
    /// `is_authorized`.
    ///
    /// `pre_states[1..]` supplies the read-only segment chain from `first_segment`, in link order.
    /// The image ID is computed from that chain.
    ///
    /// Required accounts (1 + the segment chain length).
    CreateHeader {
        first_segment: AccountId,
        immutable: bool,
    },
    /// Updates the header in `pre_states[0]`'s loader shard.
    ///
    /// Requires an authorized account and a valid, mutable [`ProgramHeader`].
    /// Uses the same segment chain and image ID calculation as [`Instruction::CreateHeader`].
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
    pre_states: &[AccountInput],
    bytecode: Vec<u8>,
    next_segment: Option<AccountId>,
) -> Vec<AccountStateDiff> {
    let expected_len = if next_segment.is_some() { 2 } else { 1 };
    assert_eq!(
        pre_states.len(),
        expected_len,
        "WriteSegment requires exactly {expected_len} account(s)"
    );
    let (target, rest) = pre_states.split_first().expect("length checked above");
    // A program at this address would run as the loader, and so could rewrite any program's
    // header or segments.
    assert_ne!(
        target.account_id, PROGRAM_LOADER_ACCOUNT_ID,
        "the loader's own dispatch address is not a deployable target"
    );
    assert!(
        target.shard_of(PROGRAM_LOADER_ACCOUNT_ID).is_empty(),
        "segment target already deployed"
    );

    let mut diffs = vec![AccountStateDiff::new(
        target.clone(),
        BalanceDiff::Add(0),
        ShardData::try_from(
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
        assert!(
            ProgramSegment::from_bytes(referenced.shard_of(PROGRAM_LOADER_ACCOUNT_ID)).is_some(),
            "`next_segment` must already hold a valid segment \u{2014} segments are linked tail-to-head"
        );
        diffs.push(AccountStateDiff::unchanged(referenced.clone()));
    }

    diffs
}

/// Executes `CreateHeader`.
///
/// Returns a private [`Commitment`] alongside the diffs when `immutable` is set from birth.
#[must_use]
pub fn create_header(
    pre_states: &[AccountInput],
    first_segment: AccountId,
    immutable: bool,
) -> (Vec<AccountStateDiff>, Option<Commitment>) {
    assert!(
        !pre_states.is_empty(),
        "CreateHeader requires at least the header target account"
    );
    assert_ne!(
        pre_states[0].account_id, PROGRAM_LOADER_ACCOUNT_ID,
        "the loader's own dispatch address is not a deployable target"
    );
    assert!(
        pre_states[0].shard_of(PROGRAM_LOADER_ACCOUNT_ID).is_empty(),
        "header target already deployed"
    );
    assert_eq!(
        pre_states.get(1).map(|pre| pre.account_id),
        Some(first_segment),
        "first_segment must match the first supplied segment account"
    );

    finalize_header(pre_states, first_segment, immutable)
}

/// Executes `UpdateHeader`.
///
/// Returns a private [`Commitment`] alongside the diffs when this call is what flips `immutable`
/// to `true`.
#[must_use]
pub fn update_header(
    pre_states: &[AccountInput],
    first_segment: AccountId,
    immutable: bool,
) -> (Vec<AccountStateDiff>, Option<Commitment>) {
    assert!(
        !pre_states.is_empty(),
        "UpdateHeader requires at least the header target account"
    );
    let old_header =
        ProgramHeader::from_bytes(pre_states[0].shard_of(PROGRAM_LOADER_ACCOUNT_ID)).expect(
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

    finalize_header(pre_states, first_segment, immutable)
}

/// Shared tail of `create_header`/`update_header`, once each has run its own distinct validation:
/// recomputes the real `image_id` from the segment chain, builds the finalized `ProgramHeader`,
/// emits its mirror commitment if `immutable` is set, and diffs the header account.
fn finalize_header(
    pre_states: &[AccountInput],
    first_segment: AccountId,
    immutable: bool,
) -> (Vec<AccountStateDiff>, Option<Commitment>) {
    assert!(
        pre_states[0].is_authorized,
        "header target must be an authorized account"
    );
    let header_account_id = pre_states[0].account_id;
    let image_id = compute_image_id(pre_states);
    let header = ProgramHeader {
        image_id,
        program_first_segment: first_segment,
        immutable,
    };
    let new_commitment = immutable.then(|| immutable_mirror_commitment(header_account_id, &header));

    let mut diffs = vec![AccountStateDiff::new(
        pre_states[0].clone(),
        BalanceDiff::Add(0),
        ShardData::try_from(header.to_bytes()).expect("program header must fit under DATA_MAX_LENGTH"),
    )];
    diffs.extend(
        pre_states[1..]
            .iter()
            .map(|pre| AccountStateDiff::unchanged(pre.clone())),
    );
    (diffs, new_commitment)
}

/// `segments_with_header[0]` is the header account, not part of the chain. Walks
/// `segments_with_header[1..]`, which must appear in exact link order, concatenating bytecode
/// and recomputing the real `image_id` over the result — the same walk `get_program_via` does at
/// resolution time, so a program built here decodes exactly as it will later execute. Never
/// trusts a caller-supplied `image_id`, and rejects a chain over `MAX_PROGRAM_SEGMENTS`.
///
/// Segments only ever hold `user_elf`; the protocol's default kernel is re-attached here
/// before the image id is computed.
fn compute_image_id(segments_with_header: &[AccountInput]) -> ProgramId {
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
        let segment = ProgramSegment::from_bytes(pre.shard_of(PROGRAM_LOADER_ACCOUNT_ID))
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
