use borsh::{BorshDeserialize, BorshSerialize};
use kameo::actor::{ActorRef, Spawn as _};

use crate::{
    ColumnFamily, Storable, StorageActor, Stores,
    encoding::{BigEndian, SingletonKey},
    full_type_name,
    protocol::{Count, Delete, Get, GetFirst, GetLast, GetRange, Store, WriteBatch},
    utils::Pages,
};

#[derive(Debug, Clone, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
struct Note {
    text: String,
}

impl Storable for Note {
    type Key = BigEndian<u64>;

    const COLUMN_FAMILY: ColumnFamily = ColumnFamily::LongLived;
    const TYPE_NAME: &'static str = full_type_name!(Note);
}

/// Id the next [`Note`] is stored under.
#[derive(Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
struct NextNoteId {
    id: u64,
}

impl Storable for NextNoteId {
    type Key = SingletonKey;

    const COLUMN_FAMILY: ColumnFamily = ColumnFamily::LongLived;
    const TYPE_NAME: &'static str = full_type_name!(NextNoteId);
}

/// A value that always fails to encode.
#[derive(BorshDeserialize)]
struct Unencodable;

impl BorshSerialize for Unencodable {
    fn serialize<W: std::io::Write>(&self, _writer: &mut W) -> std::io::Result<()> {
        Err(std::io::Error::other("Refused to encode"))
    }
}

impl Storable for Unencodable {
    type Key = SingletonKey;

    const COLUMN_FAMILY: ColumnFamily = ColumnFamily::LongLived;
    const TYPE_NAME: &'static str = full_type_name!(Unencodable);
}

/// Holding the task's output keeps the stopped actor's state alive, which is exactly the
/// situation `on_stop` exists for: the lock has to be gone by the time the shutdown result
/// resolves, not by the time the state happens to be dropped.
#[tokio::test]
async fn stopped_actor_releases_the_database_lock() {
    let dir = tempfile::tempdir().expect("Failed to create temp dir");
    let prepared = StorageActor::prepare();
    let actor_ref = prepared.actor_ref().clone();
    let join_handle = prepared.spawn(StorageActor::new(dir.path()).expect("Failed to open db"));

    actor_ref
        .stop_gracefully()
        .await
        .expect("Failed to stop the actor");
    actor_ref.wait_for_shutdown_with_result(|_| ()).await;

    StorageActor::new(dir.path()).expect("Database lock must be released once the actor stops");

    drop(join_handle);
}

#[test]
fn opening_fails_when_the_db_path_is_a_file() {
    let temp_dir = tempfile::tempdir().unwrap();
    let db_path = temp_dir.path().join("db");
    // Force RocksDB open to fail with an IO error by placing a file at DB path.
    std::fs::write(&db_path, b"not-a-directory").unwrap();

    assert!(StorageActor::new(&db_path).is_err());
}

fn note(text: &str) -> Note {
    Note {
        text: text.to_owned(),
    }
}

fn spawn(dir: &tempfile::TempDir) -> ActorRef<StorageActor> {
    StorageActor::spawn(StorageActor::new(dir.path()).expect("Failed to open db"))
}

async fn store_note(storage_ref: &ActorRef<StorageActor>, id: u64, text: &str) {
    storage_ref
        .ask(Store::new(BigEndian::new(&id), note(text)))
        .await
        .expect("Failed to store a note");
}

async fn all_notes(storage_ref: &ActorRef<StorageActor>) -> Vec<Note> {
    note_range(storage_ref, None, None, usize::MAX).await
}

async fn note_range(
    storage_ref: &ActorRef<StorageActor>,
    start: Option<u64>,
    end: Option<u64>,
    limit: usize,
) -> Vec<Note> {
    storage_ref
        .ask(GetRange::<Note>::new(
            start.map(|id| BigEndian::new(&id)),
            end.map(|id| BigEndian::new(&id)),
            limit,
        ))
        .await
        .expect("Failed to get a range of notes")
        .into_iter()
        .map(|(_key, value)| value)
        .collect()
}

/// Stores `text` under the next free id, written against the storage traits
/// the way a client crate would.
async fn add_note<S: Stores<Note> + Stores<NextNoteId>>(
    storage_ref: &ActorRef<S>,
    text: &str,
) -> u64 {
    let id = storage_ref
        .ask(Get::<NextNoteId>::default())
        .await
        .expect("Failed to get the next id")
        .map_or(0, |next| next.id);

    let mut batch = WriteBatch::new();
    batch.store(Store::new(BigEndian::new(&id), note(text)));
    batch.store(Store::from_value(NextNoteId {
        id: id.checked_add(1).expect("Note ids must not run out"),
    }));
    storage_ref
        .ask(batch)
        .await
        .expect("Failed to write the batch");

    id
}

#[tokio::test]
async fn a_stored_value_is_got_back_by_its_key() {
    let dir = tempfile::tempdir().expect("Failed to create temp dir");
    let storage_ref = spawn(&dir);

    store_note(&storage_ref, 7, "seven").await;

    let stored = storage_ref
        .ask(Get::<Note>::new(BigEndian::new(&7)))
        .await
        .expect("Failed to get the note");
    let absent = storage_ref
        .ask(Get::<Note>::new(BigEndian::new(&8)))
        .await
        .expect("Failed to get the absent note");

    assert_eq!(stored, Some(note("seven")));
    assert_eq!(absent, None);
}

#[tokio::test]
async fn storing_under_a_used_key_replaces_the_value() {
    let dir = tempfile::tempdir().expect("Failed to create temp dir");
    let storage_ref = spawn(&dir);

    store_note(&storage_ref, 1, "old").await;
    store_note(&storage_ref, 1, "new").await;

    let stored = storage_ref
        .ask(Get::<Note>::new(BigEndian::new(&1)))
        .await
        .expect("Failed to get the note");

    assert_eq!(stored, Some(note("new")));
}

#[tokio::test]
async fn a_deleted_value_is_gone() {
    let dir = tempfile::tempdir().expect("Failed to create temp dir");
    let storage_ref = spawn(&dir);

    store_note(&storage_ref, 1, "one").await;
    storage_ref
        .ask(Delete::<Note>::new(BigEndian::new(&1)))
        .await
        .expect("Failed to delete the note");

    let stored = storage_ref
        .ask(Get::<Note>::new(BigEndian::new(&1)))
        .await
        .expect("Failed to get the note");

    assert_eq!(stored, None);
}

#[tokio::test]
async fn values_are_listed_and_counted_in_key_order() {
    let dir = tempfile::tempdir().expect("Failed to create temp dir");
    let storage_ref = spawn(&dir);

    for (id, text) in [(300, "c"), (1, "a"), (256, "b")] {
        store_note(&storage_ref, id, text).await;
    }
    // Another type in the same family must not show up among the notes.
    storage_ref
        .ask(Store::from_value(NextNoteId { id: 9 }))
        .await
        .expect("Failed to store the next id");

    let all = all_notes(&storage_ref).await;
    let first = storage_ref
        .ask(GetFirst::<Note>::new())
        .await
        .expect("Failed to get the first note");
    let last = storage_ref
        .ask(GetLast::<Note>::new())
        .await
        .expect("Failed to get the last note");
    let count = storage_ref
        .ask(Count::<Note>::new())
        .await
        .expect("Failed to count the notes");

    assert_eq!(all, vec![note("a"), note("b"), note("c")]);
    assert_eq!(first.map(|(_key, value)| value), Some(note("a")));
    assert_eq!(last.map(|(_key, value)| value), Some(note("c")));
    assert_eq!(count, 3);
}

#[tokio::test]
async fn a_range_starts_at_its_key_and_stops_at_its_limit() {
    let dir = tempfile::tempdir().expect("Failed to create temp dir");
    let storage_ref = spawn(&dir);

    for (id, text) in [(1, "a"), (2, "b"), (4, "d"), (5, "e")] {
        store_note(&storage_ref, id, text).await;
    }

    assert_eq!(
        note_range(&storage_ref, Some(2), None, 2).await,
        vec![note("b"), note("d")],
    );
    assert_eq!(
        note_range(&storage_ref, None, None, 3).await,
        vec![note("a"), note("b"), note("d")],
    );
    assert!(note_range(&storage_ref, None, None, 0).await.is_empty());
}

#[tokio::test]
async fn a_range_from_an_absent_key_starts_at_the_next_key() {
    let dir = tempfile::tempdir().expect("Failed to create temp dir");
    let storage_ref = spawn(&dir);

    for (id, text) in [(1, "a"), (2, "b"), (4, "d"), (5, "e")] {
        store_note(&storage_ref, id, text).await;
    }

    assert_eq!(
        note_range(&storage_ref, Some(3), None, usize::MAX).await,
        vec![note("d"), note("e")],
    );
}

#[tokio::test]
async fn a_range_stops_at_its_end_key() {
    let dir = tempfile::tempdir().expect("Failed to create temp dir");
    let storage_ref = spawn(&dir);

    for (id, text) in [(1, "a"), (2, "b"), (4, "d"), (5, "e")] {
        store_note(&storage_ref, id, text).await;
    }

    assert_eq!(
        note_range(&storage_ref, Some(2), Some(4), usize::MAX).await,
        vec![note("b"), note("d")],
    );
    assert_eq!(
        note_range(&storage_ref, None, Some(3), usize::MAX).await,
        vec![note("a"), note("b")],
    );
    assert!(
        note_range(&storage_ref, Some(4), Some(2), usize::MAX)
            .await
            .is_empty(),
        "A range starting past its end holds nothing"
    );
}

#[tokio::test]
async fn a_range_continues_after_its_last_key() {
    let dir = tempfile::tempdir().expect("Failed to create temp dir");
    let storage_ref = spawn(&dir);

    for (id, text) in [(1, "a"), (2, "b"), (4, "d"), (5, "e")] {
        store_note(&storage_ref, id, text).await;
    }

    let first = storage_ref
        .ask(GetRange::<Note>::new(None, Some(BigEndian::new(&4)), 2))
        .await
        .expect("Failed to get the first range");
    let (last_key, _value) = first.last().cloned().expect("The first range has entries");
    assert_eq!(last_key.as_ref(), BigEndian::new(&2_u64).as_ref());
    assert_eq!(values(first), vec![note("a"), note("b")]);

    let rest = storage_ref
        .ask(GetRange::<Note>::after(
            last_key,
            Some(BigEndian::new(&4)),
            2,
        ))
        .await
        .expect("Failed to get the next range");
    assert_eq!(
        values(rest),
        vec![note("d")],
        "The next range stops at its end"
    );

    let past = storage_ref
        .ask(GetRange::<Note>::after(BigEndian::new(&5), None, 2))
        .await
        .expect("Failed to get a range past the last key");
    assert!(past.is_empty());
}

/// The values of `entries`, dropping their keys.
fn values(entries: Vec<(BigEndian<u64>, Note)>) -> Vec<Note> {
    entries.into_iter().map(|(_key, value)| value).collect()
}

/// The values of every page of `pages`, in order.
async fn read_pages(mut pages: Pages<'_, StorageActor, Note>) -> Vec<Vec<Note>> {
    let mut read = Vec::new();
    while let Some(page) = pages.next().await.expect("Failed to read a page") {
        read.push(values(page));
    }
    read
}

#[tokio::test]
async fn pages_read_a_range_a_page_at_a_time() {
    let dir = tempfile::tempdir().expect("Failed to create temp dir");
    let storage_ref = spawn(&dir);

    for (id, text) in [(1, "a"), (2, "b"), (4, "d"), (5, "e"), (7, "g")] {
        store_note(&storage_ref, id, text).await;
    }

    assert_eq!(
        read_pages(Pages::new(&storage_ref, None, None, 2)).await,
        vec![
            vec![note("a"), note("b")],
            vec![note("d"), note("e")],
            vec![note("g")]
        ],
    );
    assert_eq!(
        read_pages(Pages::new(
            &storage_ref,
            Some(BigEndian::new(&2)),
            Some(BigEndian::new(&5)),
            2
        ))
        .await,
        vec![vec![note("b"), note("d")], vec![note("e")]],
        "A range ending on a full page reads one empty page past it"
    );
    assert!(
        read_pages(Pages::new(&storage_ref, Some(BigEndian::new(&8)), None, 2))
            .await
            .is_empty()
    );
}

#[tokio::test]
async fn a_range_does_not_go_past_its_type() {
    let dir = tempfile::tempdir().expect("Failed to create temp dir");
    let storage_ref = spawn(&dir);

    store_note(&storage_ref, 1, "a").await;
    // Sorts right before the notes, in the same family.
    storage_ref
        .ask(Store::from_value(NextNoteId { id: 9 }))
        .await
        .expect("Failed to store the next id");

    assert_eq!(
        note_range(&storage_ref, Some(2), None, usize::MAX).await,
        Vec::new(),
    );
    assert_eq!(
        note_range(&storage_ref, None, None, usize::MAX).await,
        vec![note("a")],
    );
    assert_eq!(
        note_range(&storage_ref, None, Some(0), usize::MAX).await,
        Vec::new(),
    );
}

#[tokio::test]
async fn first_and_last_of_an_unstored_type_are_none() {
    let dir = tempfile::tempdir().expect("Failed to create temp dir");
    let storage_ref = spawn(&dir);

    let first = storage_ref
        .ask(GetFirst::<Note>::new())
        .await
        .expect("Failed to get the first note");
    let last = storage_ref
        .ask(GetLast::<Note>::new())
        .await
        .expect("Failed to get the last note");

    assert!(first.is_none());
    assert!(last.is_none());
}

#[tokio::test]
async fn a_write_batch_commits_writes_of_every_type() {
    let dir = tempfile::tempdir().expect("Failed to create temp dir");
    let storage_ref = spawn(&dir);

    assert_eq!(add_note(&storage_ref, "first").await, 0);
    assert_eq!(add_note(&storage_ref, "second").await, 1);

    let notes = all_notes(&storage_ref).await;
    let next_id = storage_ref
        .ask(Get::<NextNoteId>::default())
        .await
        .expect("Failed to get the next id");

    assert_eq!(notes, vec![note("first"), note("second")]);
    assert_eq!(next_id, Some(NextNoteId { id: 2 }));
}

#[tokio::test]
async fn later_writes_in_a_batch_replace_earlier_ones() {
    let dir = tempfile::tempdir().expect("Failed to create temp dir");
    let storage_ref = spawn(&dir);

    let mut batch = WriteBatch::new();
    batch.store(Store::new(BigEndian::new(&1), note("put then deleted")));
    batch.delete(&Delete::<Note>::new(BigEndian::new(&1)));
    batch.store(Store::new(BigEndian::new(&2), note("replaced")));
    batch.store(Store::new(BigEndian::new(&2), note("kept")));
    storage_ref
        .ask(batch)
        .await
        .expect("Failed to write the batch");

    let all = all_notes(&storage_ref).await;

    assert_eq!(all, vec![note("kept")]);
}

#[tokio::test]
async fn a_batch_with_a_value_failing_to_encode_writes_nothing() {
    let dir = tempfile::tempdir().expect("Failed to create temp dir");
    let storage_ref = spawn(&dir);

    let mut batch = WriteBatch::new();
    batch.store(Store::new(BigEndian::new(&1), note("not written")));
    batch.store(Store::from_value(Unencodable));
    let result = storage_ref.ask(batch).await;

    assert!(result.is_err(), "Writing an unencodable value must fail");
    assert_eq!(all_notes(&storage_ref).await, Vec::new());
}
