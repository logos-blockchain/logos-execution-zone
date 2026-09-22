//! Native program deployment and updates through [`PROGRAM_LOADER_ACCOUNT_ID`].
//!
//! Instructions only change loader shards. Creating a segment or header requires no
//! authorization; updating a header requires an authorized account and a mutable header.
//!
//! The loader is trusted, public-only native code, so unlike a guest program its planner reads
//! the selected loader shards directly from live pending state rather than through
//! `ProgramInput`. Its results reach the account only as [`ShardEffect`]s resolved by
//! [`resolve`], the same selected-shard application every other program goes through.
use borsh::{BorshDeserialize, BorshSerialize};
pub use lee_core::program::{MAX_PROGRAM_SEGMENTS, ProgramHeader, ProgramSegment};
use lee_core::{
    account::{AccountId, ShardData},
    native_token::NATIVE_TOKEN_PROGRAM_ID,
    program::{AccountMeta, PROGRAM_LOADER_ACCOUNT_ID, ProgramId, ResolveInput, ShardEffect},
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
    /// Writes a new segment to the empty loader shard of `accounts[0]`, without authorization.
    ///
    /// If `next_segment` is `Some`, `accounts[1]` must be that account and contain a valid
    /// [`ProgramSegment`] in its loader shard. Segments are immutable and linked from tail to head.
    ///
    /// Required accounts (1, or 2 if `next_segment` is `Some`).
    WriteSegment {
        bytecode: Vec<u8>,
        next_segment: Option<AccountId>,
    },
    /// Creates a header in the empty loader shard of `accounts[0]`, without authorization.
    ///
    /// `accounts[1..]` supplies the read-only segment chain from `first_segment`, in link order.
    /// The image ID is computed from that chain.
    ///
    /// Required accounts (1 + the segment chain length).
    CreateHeader {
        first_segment: AccountId,
        immutable: bool,
    },
    /// Updates the header in `accounts[0]`'s loader shard.
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

/// The planner has already validated emptiness, authorization, mutability, chain order and the
/// recomputed image ID against live state; the bytes are what that validation produced.
#[derive(Clone, Debug, BorshSerialize, BorshDeserialize)]
pub enum Effect {
    Write(Vec<u8>),
}

/// Every handle a loader instruction takes selects the loader's own shard. The planner reads
/// through that shard and writes only through it, so a handle naming another program's shard is
/// a malformed invocation rather than something to silently read past.
fn loader_shards(accounts: &[AccountMeta]) {
    for account in accounts {
        assert_eq!(
            account.program_account_id, PROGRAM_LOADER_ACCOUNT_ID,
            "a loader handle carries another program's shard selector"
        );
    }
}

fn write(target: &AccountMeta, bytes: Vec<u8>) -> ShardEffect {
    assert!(
        ShardData::try_from(bytes.clone()).is_ok(),
        "a loader write must fit under DATA_MAX_LENGTH"
    );
    ShardEffect::new(target, &Effect::Write(bytes))
}

/// Executes `WriteSegment`.
#[must_use]
pub fn write_segment<'state>(
    accounts: &[AccountMeta],
    shard: impl Fn(AccountId) -> &'state ShardData,
    bytecode: Vec<u8>,
    next_segment: Option<AccountId>,
) -> Vec<ShardEffect> {
    loader_shards(accounts);
    let expected_len = if next_segment.is_some() { 2 } else { 1 };
    assert_eq!(
        accounts.len(),
        expected_len,
        "WriteSegment requires exactly {expected_len} account(s)"
    );
    let (target, rest) = accounts.split_first().expect("length checked above");
    assert!(
        shard(target.account_id).is_empty(),
        "segment target already deployed"
    );

    if let (Some(next), [referenced]) = (next_segment, rest) {
        assert_eq!(
            referenced.account_id, next,
            "second account must be the segment `next_segment` points to"
        );
        assert!(
            ProgramSegment::from_bytes(shard(referenced.account_id)).is_some(),
            "`next_segment` must already hold a valid segment \u{2014} segments are linked tail-to-head"
        );
    }

    vec![write(
        target,
        ProgramSegment {
            bytecode,
            next_segment,
        }
        .to_bytes(),
    )]
}

fn reject_reserved_target(account_id: AccountId) {
    assert_ne!(
        account_id, NATIVE_TOKEN_PROGRAM_ID,
        "the native token program has no deployable bytecode"
    );
}

/// Executes `CreateHeader`.
#[must_use]
pub fn create_header<'state>(
    accounts: &[AccountMeta],
    shard: impl Fn(AccountId) -> &'state ShardData,
    first_segment: AccountId,
    immutable: bool,
) -> Vec<ShardEffect> {
    loader_shards(accounts);
    let target = accounts
        .first()
        .expect("CreateHeader requires at least the header target account");
    reject_reserved_target(target.account_id);
    assert!(
        shard(target.account_id).is_empty(),
        "header target already deployed"
    );

    vec![write(
        target,
        header_bytes(accounts, shard, first_segment, immutable),
    )]
}

/// Executes `UpdateHeader`.
#[must_use]
pub fn update_header<'state>(
    accounts: &[AccountMeta],
    shard: impl Fn(AccountId) -> &'state ShardData,
    first_segment: AccountId,
    immutable: bool,
) -> Vec<ShardEffect> {
    loader_shards(accounts);
    let target = accounts
        .first()
        .expect("UpdateHeader requires at least the header target account");
    reject_reserved_target(target.account_id);
    let old_header = ProgramHeader::from_bytes(shard(target.account_id)).expect(
        "UpdateHeader target must already hold a valid header \u{2014} use CreateHeader to make one",
    );
    assert!(
        !old_header.immutable,
        "UpdateHeader target is immutable and cannot be updated"
    );
    assert!(
        target.is_authorized,
        "UpdateHeader target must be authorized by the signer"
    );

    vec![write(
        target,
        header_bytes(accounts, shard, first_segment, immutable),
    )]
}

fn header_bytes<'state>(
    accounts: &[AccountMeta],
    shard: impl Fn(AccountId) -> &'state ShardData,
    first_segment: AccountId,
    immutable: bool,
) -> Vec<u8> {
    assert_eq!(
        accounts.get(1).map(|account| account.account_id),
        Some(first_segment),
        "first_segment must match the first supplied segment account"
    );
    ProgramHeader {
        image_id: compute_image_id(accounts, shard),
        program_first_segment: first_segment,
        immutable,
    }
    .to_bytes()
}

#[must_use]
pub fn resolve(input: &ResolveInput) -> ShardData {
    let Effect::Write(bytes) =
        borsh::from_slice(&input.effect_data).expect("a loader effect must decode");
    ShardData::try_from(bytes).expect("a loader write must fit under DATA_MAX_LENGTH")
}

/// `segments_with_header[0]` is the header account, not part of the chain. Walks
/// `segments_with_header[1..]`, which must appear in exact link order, concatenating bytecode
/// and recomputing the real `image_id` over the result — the same walk `get_program_via` does at
/// resolution time, so a program built here decodes exactly as it will later execute. Never
/// trusts a caller-supplied `image_id`, and rejects a chain over `MAX_PROGRAM_SEGMENTS`.
fn compute_image_id<'state>(
    segments_with_header: &[AccountMeta],
    shard: impl Fn(AccountId) -> &'state ShardData,
) -> ProgramId {
    let mut elf = Vec::new();
    let mut expected_next = segments_with_header
        .get(1)
        .map(|account| account.account_id);
    let mut segment_count = 0_usize;
    for supplied in &segments_with_header[1..] {
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
            supplied.account_id, account_id,
            "segment accounts must be supplied in exact chain order"
        );
        let segment = ProgramSegment::from_bytes(shard(supplied.account_id))
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
