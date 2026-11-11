//! Unit tests for the bookkeeping this crate owns directly: segment/header shape, write-once and
//! chain-order enforcement, and `UpdateHeader`'s authorization/immutability gates.
//!
//! A success path through `create_header`/`update_header` needs bytecode that decodes as a real
//! RISC0 program (`compute_image_id` rejects anything else), so those are covered at the
//! state-machine integration level instead, against real guest ELFs.

use std::collections::HashMap;

use lee_core::account::{AccountId, Actor};

use super::*;

/// The live loader actor states the planner reads through, standing in for pending/committed state.
#[derive(Default)]
struct ActorStates(HashMap<AccountId, ActorState>);

impl ActorStates {
    fn with(mut self, account_id: AccountId, data: ActorState) -> Self {
        self.0.insert(account_id, data);
        self
    }

    fn segment(self, account_id: AccountId, bytecode: Vec<u8>, next: Option<AccountId>) -> Self {
        self.with(
            account_id,
            ActorState::from(
                ProgramSegment {
                    bytecode,
                    next_segment: next,
                }
                .to_loader_actor_state(),
            ),
        )
    }

    fn header(self, account_id: AccountId, header: &ProgramHeader) -> Self {
        self.with(account_id, ActorState::from(header.to_loader_actor_state()))
    }

    fn read<'actor_states>(
        &'actor_states self,
    ) -> impl Fn(AccountId) -> &'actor_states ActorState + 'actor_states {
        const ABSENT: &ActorState = &ActorState::empty();
        move |account_id| self.0.get(&account_id).unwrap_or(ABSENT)
    }
}

fn input(
    target: AccountId,
    is_authorized: bool,
    pre_state: ActorState,
    message: &Message,
) -> ReceiveInput {
    let receiver = Actor::new(target, PROGRAM_LOADER_ACCOUNT_ID);
    ReceiveInput {
        receiver,
        from: None,
        is_authorized,
        pre_state,
        message: borsh::to_vec(message).expect("borsh serialization is infallible"),
    }
}

#[test]
fn write_segment_writes_the_loader_actor_state() {
    let target_id = AccountId::new([1; 32]);
    let actor_states = ActorStates::default();
    let message = Message::WriteSegment {
        bytecode: vec![1, 2, 3],
        next_segment: None,
    };

    let (transition, new_commitment) = handle_message(
        &input(target_id, true, ActorState::empty(), &message),
        actor_states.read(),
    );

    let post_state = transition
        .response
        .post_state
        .expect("a segment was written");
    let segment = ProgramSegment::from_loader_actor_state(&post_state).expect("valid segment");
    assert_eq!(segment.bytecode, vec![1, 2, 3]);
    assert_eq!(segment.next_segment, None);
    assert!(
        transition.response.sync_messages.is_empty()
            && transition.response.async_messages.is_empty()
    );
    assert!(new_commitment.is_none());
}

#[test]
#[should_panic(expected = "WriteSegment target must be an authorized account")]
fn write_segment_rejects_an_unauthorized_target() {
    let message = Message::WriteSegment {
        bytecode: vec![1],
        next_segment: None,
    };

    let _transition = handle_message(
        &input(
            AccountId::new([1; 32]),
            false,
            ActorState::empty(),
            &message,
        ),
        ActorStates::default().read(),
    );
}

#[test]
fn write_segment_stores_header_sized_bytecode_as_a_segment() {
    let next_id = AccountId::new([1; 32]);
    let actor_states = ActorStates::default().segment(next_id, vec![9], None);
    for (bytecode_len, next_segment) in [(60, None), (28, Some(next_id))] {
        let message = Message::WriteSegment {
            bytecode: vec![0; bytecode_len],
            next_segment,
        };

        let (transition, _) = handle_message(
            &input(AccountId::new([2; 32]), true, ActorState::empty(), &message),
            actor_states.read(),
        );

        let stored = transition
            .response
            .post_state
            .expect("a segment was written");
        assert!(ProgramSegment::from_loader_actor_state(&stored).is_some());
        assert_eq!(ProgramHeader::from_loader_actor_state(&stored), None);
    }
}

#[test]
#[should_panic(expected = "already deployed")]
fn write_segment_rejects_an_occupied_loader_actor_state() {
    let target_id = AccountId::new([1; 32]);
    let actor_states = ActorStates::default().segment(target_id, vec![9], None);
    let pre_state = actor_states.read()(target_id).clone();
    let message = Message::WriteSegment {
        bytecode: vec![1],
        next_segment: None,
    };

    let _transition = handle_message(
        &input(target_id, true, pre_state, &message),
        actor_states.read(),
    );
}

#[test]
#[should_panic(expected = "must already hold a valid segment")]
fn write_segment_rejects_a_next_segment_with_malformed_data() {
    let target_id = AccountId::new([1; 32]);
    let next_id = AccountId::new([2; 32]);
    let actor_states = ActorStates::default().with(next_id, ActorState::from(vec![0xff, 0xff]));
    let message = Message::WriteSegment {
        bytecode: vec![1],
        next_segment: Some(next_id),
    };

    let _transition = handle_message(
        &input(target_id, true, ActorState::empty(), &message),
        actor_states.read(),
    );
}

#[test]
#[should_panic(expected = "header target already deployed")]
fn create_header_rejects_an_occupied_loader_actor_state() {
    let target_id = AccountId::new([1; 32]);
    let actor_states = ActorStates::default().header(
        target_id,
        &ProgramHeader {
            image_id: [0; 8],
            program_first_segment: AccountId::new([2; 32]),
            immutable: false,
        },
    );
    let pre_state = actor_states.read()(target_id).clone();
    let message = Message::CreateHeader {
        first_segment: AccountId::new([2; 32]),
        immutable: false,
    };

    let _transition = handle_message(
        &input(target_id, false, pre_state, &message),
        actor_states.read(),
    );
}

#[test]
#[should_panic(expected = "must decode as a valid ProgramSegment")]
fn create_header_rejects_a_chain_that_does_not_end() {
    let target_id = AccountId::new([1; 32]);
    let first_segment = AccountId::new([2; 32]);
    let second_segment = AccountId::new([3; 32]);
    let dangling = AccountId::new([4; 32]);
    let actor_states = ActorStates::default()
        .segment(first_segment, vec![1], Some(second_segment))
        .segment(second_segment, vec![2], Some(dangling));
    let message = Message::CreateHeader {
        first_segment,
        immutable: false,
    };

    let _transition = handle_message(
        &input(target_id, true, ActorState::empty(), &message),
        actor_states.read(),
    );
}

#[test]
#[should_panic(expected = "use CreateHeader to make one")]
fn update_header_rejects_a_target_with_no_existing_header() {
    let target_id = AccountId::new([1; 32]);
    let message = Message::UpdateHeader {
        first_segment: AccountId::new([2; 32]),
        immutable: false,
    };

    let _transition = handle_message(
        &input(target_id, true, ActorState::empty(), &message),
        ActorStates::default().read(),
    );
}

#[test]
#[should_panic(expected = "immutable and cannot be updated")]
fn update_header_rejects_an_immutable_header() {
    let target_id = AccountId::new([1; 32]);
    let first_segment = AccountId::new([2; 32]);
    let actor_states = ActorStates::default().header(
        target_id,
        &ProgramHeader {
            image_id: [0; 8],
            program_first_segment: first_segment,
            immutable: true,
        },
    );
    let pre_state = actor_states.read()(target_id).clone();
    let message = Message::UpdateHeader {
        first_segment,
        immutable: false,
    };

    let _transition = handle_message(
        &input(target_id, true, pre_state, &message),
        actor_states.read(),
    );
}

#[test]
#[should_panic(expected = "must be authorized by the signer")]
fn update_header_rejects_an_unauthorized_caller() {
    let target_id = AccountId::new([1; 32]);
    let first_segment = AccountId::new([2; 32]);
    let actor_states = ActorStates::default().header(
        target_id,
        &ProgramHeader {
            image_id: [0; 8],
            program_first_segment: first_segment,
            immutable: false,
        },
    );
    let pre_state = actor_states.read()(target_id).clone();
    let message = Message::UpdateHeader {
        first_segment,
        immutable: false,
    };

    let _transition = handle_message(
        &input(target_id, false, pre_state, &message),
        actor_states.read(),
    );
}

#[test]
#[should_panic(expected = "the native token program has no deployable bytecode")]
fn a_header_may_not_be_created_for_the_native_token_program() {
    let segment_id = AccountId::new([2; 32]);
    let message = Message::CreateHeader {
        first_segment: segment_id,
        immutable: false,
    };

    let _transition = handle_message(
        &input(NATIVE_TOKEN_PROGRAM_ID, true, ActorState::empty(), &message),
        ActorStates::default().read(),
    );
}

#[test]
#[should_panic(expected = "the loader's own dispatch address")]
fn a_segment_cannot_be_written_at_the_loader_address() {
    let message = Message::WriteSegment {
        bytecode: vec![0_u8; 32],
        next_segment: None,
    };

    let _transition = handle_message(
        &input(
            PROGRAM_LOADER_ACCOUNT_ID,
            true,
            ActorState::empty(),
            &message,
        ),
        ActorStates::default().read(),
    );
}

#[test]
#[should_panic(expected = "the loader's own dispatch address")]
fn a_header_cannot_be_created_at_the_loader_address() {
    let first_segment = AccountId::new([3; 32]);
    let message = Message::CreateHeader {
        first_segment,
        immutable: true,
    };

    let _transition = handle_message(
        &input(
            PROGRAM_LOADER_ACCOUNT_ID,
            true,
            ActorState::empty(),
            &message,
        ),
        ActorStates::default().read(),
    );
}

#[test]
fn build_segments_links_each_chunk_to_the_next_id() {
    let user_elf: Vec<u8> = (0..=u8::MAX)
        .cycle()
        .take(MAX_SEGMENT_DATA_LEN * 2 + 5)
        .collect();
    let ids = [
        AccountId::new([1; 32]),
        AccountId::new([2; 32]),
        AccountId::new([3; 32]),
    ];

    let segments = build_segments(&user_elf, &ids).expect("valid chain");

    let next: Vec<_> = segments
        .iter()
        .map(|segment| segment.next_segment)
        .collect();
    assert_eq!(next, vec![Some(ids[1]), Some(ids[2]), None]);
    let rejoined: Vec<u8> = segments
        .into_iter()
        .flat_map(|segment| segment.bytecode)
        .collect();
    assert_eq!(rejoined, user_elf);
}

#[test]
fn build_segments_rejects_a_segment_count_mismatch() {
    let user_elf = vec![0; MAX_SEGMENT_DATA_LEN + 1];
    assert_eq!(
        build_segments(&user_elf, &[AccountId::new([1; 32])]),
        Err(SegmentChainError::CountMismatch {
            expected: 2,
            actual: 1
        })
    );
}

/// Refused before upload, not at `CreateHeader` after every segment is paid for.
#[test]
fn build_segments_rejects_a_chain_over_the_segment_cap() {
    let count = MAX_PROGRAM_SEGMENTS + 1;
    let user_elf = vec![0; MAX_SEGMENT_DATA_LEN * count];
    let ids: Vec<_> = (0..count)
        .map(|i| AccountId::new([u8::try_from(i).unwrap(); 32]))
        .collect();
    assert_eq!(
        build_segments(&user_elf, &ids),
        Err(SegmentChainError::TooManySegments { count })
    );
}

fn linked_header() -> ProgramHeader {
    ProgramHeader {
        image_id: [60, 0, 0, 0, 0, 0, 0, 0],
        program_first_segment: AccountId::new([3; 32]),
        immutable: false,
    }
}

#[test]
#[should_panic(expected = "every supplied segment account must decode as a valid ProgramSegment")]
fn create_header_rejects_a_chain_linking_to_a_header() {
    let linked_header_id = AccountId::new([2; 32]);
    let actor_states = ActorStates::default().header(linked_header_id, &linked_header());
    let message = Message::CreateHeader {
        first_segment: linked_header_id,
        immutable: true,
    };

    let _transition = handle_message(
        &input(AccountId::new([1; 32]), true, ActorState::empty(), &message),
        actor_states.read(),
    );
}

#[test]
#[should_panic(expected = "`next_segment` must already hold a valid segment")]
fn write_segment_rejects_linking_to_a_header() {
    let linked_header_id = AccountId::new([2; 32]);
    let actor_states = ActorStates::default().header(linked_header_id, &linked_header());
    let message = Message::WriteSegment {
        bytecode: vec![1],
        next_segment: Some(linked_header_id),
    };

    let _transition = handle_message(
        &input(AccountId::new([1; 32]), true, ActorState::empty(), &message),
        actor_states.read(),
    );
}
