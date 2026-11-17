//! STF prototype: the host records every public program session it runs, and the block guest
//! replays them, checking each journal by composition instead of executing the program.

use std::cell::RefCell;
#[cfg(target_os = "zkvm")]
use std::collections::VecDeque;

use borsh::{BorshDeserialize, BorshSerialize};
#[cfg(target_os = "zkvm")]
use lee_core::program::Transition;
use lee_core::{
    account::Cycles,
    program::{ProgramId, ReceiveInput},
};

#[cfg(target_os = "zkvm")]
use crate::error::LeeError;

/// One public program session, in the order the block's execution ran it.
#[derive(Clone, BorshSerialize, BorshDeserialize)]
pub struct RecordedCall {
    pub image_id: ProgramId,
    /// The framed input the session read; the host proves the session from it.
    pub input: Vec<u8>,
    pub journal: Vec<u8>,
    pub cycles: Cycles,
}

#[cfg(not(target_os = "zkvm"))]
thread_local! {
    static RECORDER: RefCell<Option<(Vec<RecordedCall>, std::collections::HashMap<ProgramId, Vec<u8>>)>> =
        const { RefCell::new(None) };
}

/// Starts recording the sessions this thread runs.
#[cfg(not(target_os = "zkvm"))]
pub fn start_recording() {
    RECORDER.with(|r| *r.borrow_mut() = Some((Vec::new(), std::collections::HashMap::new())));
}

/// Stops recording, returning the sessions and the ELF of every image they ran.
#[cfg(not(target_os = "zkvm"))]
#[must_use]
pub fn take_recording() -> (Vec<RecordedCall>, std::collections::HashMap<ProgramId, Vec<u8>>) {
    RECORDER
        .with(|r| r.borrow_mut().take())
        .unwrap_or_default()
}

#[cfg(not(target_os = "zkvm"))]
pub(crate) fn record(
    image_id: ProgramId,
    elf: &[u8],
    input: &ReceiveInput,
    journal: &[u8],
    cycles: Cycles,
) {
    RECORDER.with(|r| {
        if let Some((calls, elfs)) = r.borrow_mut().as_mut() {
            let payload = borsh::to_vec(input).expect("ReceiveInput serializes");
            calls.push(RecordedCall {
                image_id,
                input: lee_core::to_frame(&payload),
                journal: journal.to_vec(),
                cycles,
            });
            elfs.entry(image_id).or_insert_with(|| elf.to_vec());
        }
    });
}

#[cfg(target_os = "zkvm")]
thread_local! {
    static REPLAY: RefCell<VecDeque<RecordedCall>> = const { RefCell::new(VecDeque::new()) };
}

/// Installs the sessions the block guest replays, in execution order.
#[cfg(target_os = "zkvm")]
pub fn install(calls: Vec<RecordedCall>) {
    REPLAY.with(|r| *r.borrow_mut() = calls.into());
}

/// How many installed sessions were not replayed.
#[cfg(target_os = "zkvm")]
#[must_use]
pub fn remaining() -> usize {
    REPLAY.with(|r| r.borrow().len())
}

/// Replays the next session: its journal is verified against `image_id` by composition and must
/// carry `input`. Its cycle count is taken on trust.
#[cfg(target_os = "zkvm")]
pub(crate) fn replay(
    image_id: ProgramId,
    input: &ReceiveInput,
    cycle_budget: Cycles,
) -> Result<(Transition, Cycles), LeeError> {
    let call = REPLAY
        .with(|r| r.borrow_mut().pop_front())
        .expect("a recorded session for every program call");
    assert_eq!(call.image_id, image_id, "recorded session ran another image");
    if call.cycles > cycle_budget {
        return Err(LeeError::OutOfGas {
            budget: cycle_budget,
        });
    }
    risc0_zkvm::guest::env::verify(image_id, &call.journal)
        .unwrap_or_else(|_: core::convert::Infallible| unreachable!());
    let transition = super::transition_journal(&call.journal)?;
    assert_eq!(
        borsh::to_vec(&transition.input).expect("serializes"),
        borsh::to_vec(input).expect("serializes"),
        "recorded session read another input"
    );
    Ok((transition, call.cycles))
}
