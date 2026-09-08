use kameo::Reply;

/// Special message to trigger mockall's checkpoint mechanism.
pub struct Checkpoint;

/// Special message to [`std::mem::replace()`] the inner state of mock actor with a new
/// one, returning old state.
/// This is useful for testing, to swap in a new mock with different expectations.
pub struct Replace<T> {
    pub mock: T,
}

#[derive(Reply)]
pub struct ReplaceReply<T: Send + 'static> {
    pub old_mock: T,
}
