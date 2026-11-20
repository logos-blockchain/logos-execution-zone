//! The bridge records the sequencer core keeps in the store: deposits waiting for their mints to
//! finalize, and withdrawals waiting for their Bedrock events.

use std::collections::HashSet;

use borsh::{BorshDeserialize, BorshSerialize};
use common::HashType;
use kameo::{actor::ActorRef, error::SendError};
use sequencer_storage_actor::{
    ColumnFamily, Storable, Stores,
    error::Error,
    full_type_name,
    protocol::{Delete, Get, GetRange, Store, WriteBatch},
    utils::Pages,
};

/// How many pending deposits [`pending_deposits`] reads at a time.
const PENDING_DEPOSITS_PAGE: usize = 64;

/// An L1 deposit event observed but not yet seen finalized.
///
/// Purely a liveness queue: whether to emit a mint is decided against chain
/// state, and the record is dropped once its mint finalizes.
#[derive(Debug, Clone, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct PendingDepositEventRecord {
    pub deposit_op_id: HashType,
    pub source_tx_hash: HashType,
    pub amount: u64,
    pub metadata: Vec<u8>,
}

impl Storable for PendingDepositEventRecord {
    type Key = HashType;

    const COLUMN_FAMILY: ColumnFamily = ColumnFamily::ShortLived;
    const TYPE_NAME: &'static str = full_type_name!(PendingDepositEventRecord);
}

/// Identity of one withdrawal: the id of the channel note it releases.
///
/// Shared by the intent recorded when the sequencer publishes a withdrawal and
/// the Bedrock event that later reports it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct WithdrawalReconciliationKey {
    pub released_note_id: [u8; 32],
}

impl AsRef<[u8]> for WithdrawalReconciliationKey {
    fn as_ref(&self) -> &[u8] {
        &self.released_note_id
    }
}

impl TryFrom<&[u8]> for WithdrawalReconciliationKey {
    type Error = std::array::TryFromSliceError;

    fn try_from(bytes: &[u8]) -> Result<Self, Self::Error> {
        Ok(Self {
            released_note_id: bytes.try_into()?,
        })
    }
}

/// An L2 withdraw intent this sequencer published, awaiting the Bedrock event
/// that reports it.
///
/// Carries no value: the key is the whole fact, and presence is the intent.
#[derive(BorshSerialize, BorshDeserialize)]
pub struct PendingWithdrawalRecord;

impl Storable for PendingWithdrawalRecord {
    type Key = WithdrawalReconciliationKey;

    const COLUMN_FAMILY: ColumnFamily = ColumnFamily::ShortLived;
    const TYPE_NAME: &'static str = full_type_name!(PendingWithdrawalRecord);
}

/// Writes recording the deposits of `observed` not already pending and dropping the records of
/// `finalized`, with how many deposits they record.
///
/// A deposit finalized along with being observed is never recorded.
pub async fn deposit_writes<S: Stores<PendingDepositEventRecord>>(
    storage_ref: &ActorRef<S>,
    observed: Vec<PendingDepositEventRecord>,
    finalized: &HashSet<HashType>,
) -> Result<(WriteBatch, usize), SendError<Get<PendingDepositEventRecord>, Error>> {
    let mut writes = WriteBatch::new();
    #[expect(
        clippy::iter_over_hash_type,
        reason = "Deletes of distinct keys commute"
    )]
    for deposit_op_id in finalized {
        writes.delete(&Delete::<PendingDepositEventRecord>::new(*deposit_op_id));
    }

    let mut seen = HashSet::new();
    let mut recorded = 0_usize;
    for record in observed.into_iter().filter(|record| {
        !finalized.contains(&record.deposit_op_id) && seen.insert(record.deposit_op_id)
    }) {
        let pending = storage_ref
            .ask(Get::<PendingDepositEventRecord>::new(record.deposit_op_id))
            .await?;
        if pending.is_none() {
            writes.store(Store::new(record.deposit_op_id, record));
            recorded = recorded.saturating_add(1);
        }
    }

    Ok((writes, recorded))
}

/// Writes raising the intents of `published` and settling the intents `consumed` reports, with the
/// withdrawals of `consumed` no intent is held for.
pub async fn withdrawal_writes<S: Stores<PendingWithdrawalRecord>>(
    storage_ref: &ActorRef<S>,
    published: &HashSet<WithdrawalReconciliationKey>,
    consumed: &HashSet<WithdrawalReconciliationKey>,
) -> Result<
    (WriteBatch, Vec<WithdrawalReconciliationKey>),
    SendError<Get<PendingWithdrawalRecord>, Error>,
> {
    let mut writes = WriteBatch::new();
    let mut unmatched = Vec::new();
    #[expect(
        clippy::iter_over_hash_type,
        reason = "Writes of distinct keys commute, and the order of unmatched withdrawals does not \
                  matter"
    )]
    for key in consumed {
        let matched = published.contains(key)
            || storage_ref
                .ask(Get::<PendingWithdrawalRecord>::new(*key))
                .await?
                .is_some();
        if matched {
            writes.delete(&Delete::<PendingWithdrawalRecord>::new(*key));
        } else {
            unmatched.push(*key);
        }
    }

    for key in published.difference(consumed) {
        writes.store(Store::new(*key, PendingWithdrawalRecord));
    }

    Ok((writes, unmatched))
}

/// Every pending deposit, in deposit op id order.
pub async fn pending_deposits<S: Stores<PendingDepositEventRecord>>(
    storage_ref: &ActorRef<S>,
) -> Result<Vec<PendingDepositEventRecord>, SendError<GetRange<PendingDepositEventRecord>, Error>> {
    let mut pages =
        Pages::<_, PendingDepositEventRecord>::new(storage_ref, None, None, PENDING_DEPOSITS_PAGE);
    let mut records = Vec::new();
    while let Some(page) = pages.next().await? {
        records.extend(page.into_iter().map(|(_deposit_op_id, record)| record));
    }
    Ok(records)
}

#[cfg(test)]
mod tests {
    use std::collections::HashSet;

    use common::HashType;
    use kameo::actor::{ActorRef, Spawn as _};
    use sequencer_storage_actor::mock::MockStorageActor;

    use super::{
        PendingDepositEventRecord, WithdrawalReconciliationKey, deposit_writes, pending_deposits,
        withdrawal_writes,
    };

    fn withdrawal_key(byte: u8) -> WithdrawalReconciliationKey {
        WithdrawalReconciliationKey {
            released_note_id: [byte; 32],
        }
    }

    fn deposit_record(byte: u8) -> PendingDepositEventRecord {
        PendingDepositEventRecord {
            deposit_op_id: HashType([byte; 32]),
            source_tx_hash: HashType([byte; 32]),
            amount: u64::from(byte),
            metadata: Vec::new(),
        }
    }

    /// Records the deposits of `observed` and drops the records of the `finalized` op ids,
    /// returning how many deposits were recorded.
    async fn record_deposits(
        storage_ref: &ActorRef<MockStorageActor>,
        observed: Vec<PendingDepositEventRecord>,
        finalized: &[u8],
    ) -> usize {
        let finalized = finalized.iter().map(|byte| HashType([*byte; 32])).collect();
        let (writes, recorded) = deposit_writes(storage_ref, observed, &finalized)
            .await
            .expect("Failed to read the pending deposits");
        storage_ref
            .ask(writes)
            .await
            .expect("Failed to write the deposits");
        recorded
    }

    /// Raises the `published` intents and settles the `consumed` ones, returning the consumed
    /// withdrawals no intent was held for.
    async fn reconcile_withdrawals(
        storage_ref: &ActorRef<MockStorageActor>,
        published: &[u8],
        consumed: &[u8],
    ) -> Vec<WithdrawalReconciliationKey> {
        let keys =
            |bytes: &[u8]| -> HashSet<_> { bytes.iter().copied().map(withdrawal_key).collect() };
        let (writes, unmatched) = withdrawal_writes(storage_ref, &keys(published), &keys(consumed))
            .await
            .expect("Failed to read the withdraw intents");
        storage_ref
            .ask(writes)
            .await
            .expect("Failed to write the withdrawals");
        unmatched
    }

    /// The reconciliation is a set membership test, so an intent has to outlive the
    /// update that raised it and every later update that touches the set.
    #[tokio::test]
    async fn withdraw_intents_survive_later_updates() {
        let storage_ref = MockStorageActor::spawn(MockStorageActor::new());

        // Raised one at a time, as the produce path does: each update must leave the
        // earlier intents alone.
        for byte in 1..=3 {
            reconcile_withdrawals(&storage_ref, &[byte], &[]).await;
        }

        assert!(
            reconcile_withdrawals(&storage_ref, &[], &[1, 2, 3])
                .await
                .is_empty(),
            "Every reported note was published by this node, so none is unmatched"
        );
    }

    /// The reconciliation reports the events this node cannot account for — never the
    /// intents it is still waiting on.
    #[tokio::test]
    async fn withdraw_event_without_an_intent_is_reported_unmatched() {
        let storage_ref = MockStorageActor::spawn(MockStorageActor::new());

        reconcile_withdrawals(&storage_ref, &[1], &[]).await;

        // Note 2 was never published here; note 1 is still outstanding and must not
        // be reported just because another event arrived.
        assert_eq!(
            reconcile_withdrawals(&storage_ref, &[], &[2]).await,
            vec![withdrawal_key(2)]
        );
    }

    /// A settled intent is gone for good, so a re-delivered event has nothing left
    /// to match.
    #[tokio::test]
    async fn consumed_withdrawal_is_not_matched_twice() {
        let storage_ref = MockStorageActor::spawn(MockStorageActor::new());

        reconcile_withdrawals(&storage_ref, &[1], &[]).await;
        assert!(
            reconcile_withdrawals(&storage_ref, &[], &[1])
                .await
                .is_empty()
        );

        assert_eq!(
            reconcile_withdrawals(&storage_ref, &[], &[1]).await,
            vec![withdrawal_key(1)]
        );
    }

    /// An intent reported in the update that raises it is settled at once.
    #[tokio::test]
    async fn withdrawal_published_and_consumed_together_is_matched() {
        let storage_ref = MockStorageActor::spawn(MockStorageActor::new());

        assert!(
            reconcile_withdrawals(&storage_ref, &[1], &[1])
                .await
                .is_empty()
        );
        assert_eq!(
            reconcile_withdrawals(&storage_ref, &[], &[1]).await,
            vec![withdrawal_key(1)],
            "The intent is settled, so none is left to match"
        );
    }

    /// The recorded count is what the caller logs as newly owed mints, so a
    /// re-delivery of an already pending deposit must count for nothing.
    #[tokio::test]
    async fn only_newly_recorded_deposits_are_counted() {
        let storage_ref = MockStorageActor::spawn(MockStorageActor::new());

        assert_eq!(
            record_deposits(
                &storage_ref,
                vec![deposit_record(1), deposit_record(2), deposit_record(2)],
                &[]
            )
            .await,
            2
        );

        // One already pending, one new: only the new one is owed.
        assert_eq!(
            record_deposits(
                &storage_ref,
                vec![deposit_record(2), deposit_record(3)],
                &[]
            )
            .await,
            1
        );

        assert_eq!(
            pending_deposits(&storage_ref)
                .await
                .expect("Failed to read the pending deposits"),
            vec![deposit_record(1), deposit_record(2), deposit_record(3)]
        );
    }

    /// Backfill can deliver a deposit and its finalization in one event: the record
    /// is owed nothing, and counting it would log a mint that never comes.
    #[tokio::test]
    async fn deposit_finalized_in_the_same_update_is_never_recorded() {
        let storage_ref = MockStorageActor::spawn(MockStorageActor::new());

        assert_eq!(
            record_deposits(&storage_ref, vec![deposit_record(1)], &[1]).await,
            0
        );
        assert!(
            pending_deposits(&storage_ref)
                .await
                .expect("Failed to read the pending deposits")
                .is_empty()
        );
    }

    /// A record goes by its own op id, never because some other deposit finalized.
    #[tokio::test]
    async fn only_the_finalized_deposit_record_is_dropped() {
        let storage_ref = MockStorageActor::spawn(MockStorageActor::new());

        record_deposits(
            &storage_ref,
            vec![deposit_record(1), deposit_record(2)],
            &[],
        )
        .await;
        record_deposits(&storage_ref, Vec::new(), &[1]).await;

        assert_eq!(
            pending_deposits(&storage_ref)
                .await
                .expect("Failed to read the pending deposits"),
            vec![deposit_record(2)]
        );
    }
}
