//! Native program deployment and updates through [`PROGRAM_LOADER_ACCOUNT_ID`].
//!
//! Instructions only change loader shards. Creating a segment or header requires no
//! authorization; updating a header requires an authorized account and a mutable header.
use borsh::{BorshDeserialize, BorshSerialize};
pub use lee_core::program::{MAX_PROGRAM_SEGMENTS, ProgramHeader, ProgramSegment};
use lee_core::{
    account::{AccountId, AccountInput, BalanceDiff, Data},
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
    /// Creates a header in the empty loader shard of `pre_states[0]`, without authorization.
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
    assert!(
        target.shard_of(PROGRAM_LOADER_ACCOUNT_ID).is_empty(),
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
        assert!(
            ProgramSegment::from_bytes(referenced.shard_of(PROGRAM_LOADER_ACCOUNT_ID)).is_some(),
            "`next_segment` must already hold a valid segment \u{2014} segments are linked tail-to-head"
        );
        diffs.push(AccountStateDiff::unchanged(referenced.clone()));
    }

    diffs
}

/// Executes `CreateHeader`.
#[must_use]
pub fn create_header(
    pre_states: &[AccountInput],
    first_segment: AccountId,
    immutable: bool,
) -> Vec<AccountStateDiff> {
    assert!(
        !pre_states.is_empty(),
        "CreateHeader requires at least the header target account"
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
    pre_states: &[AccountInput],
    first_segment: AccountId,
    immutable: bool,
) -> Vec<AccountStateDiff> {
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

    risc0_binfmt::compute_image_id(&elf)
        .expect("concatenated segment bytecode must decode as a valid RISC0 program binary")
        .into()
}

#[cfg(test)]
mod tests;
