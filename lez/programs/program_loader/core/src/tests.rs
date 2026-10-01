//! Unit tests for the bookkeeping this crate owns directly: segment/header shape, write-once and
//! chain-order enforcement, and `UpdateHeader`'s authorization/immutability gates.
//!
//! A success path through `create_header`/`update_header` needs bytecode that decodes as a real
//! RISC0 program (`compute_image_id` rejects anything else), so those are covered at the
//! state-machine integration level instead, against real guest ELFs.

use std::collections::HashMap;

use lee_core::{
    account::{AccountId, Actor},
    program::Origin,
};

use super::*;

/// The live loader shards the planner reads through, standing in for pending/committed state.
#[derive(Default)]
struct Shards(HashMap<AccountId, ActorState>);

impl Shards {
    fn with(mut self, account_id: AccountId, data: ActorState) -> Self {
        self.0.insert(account_id, data);
        self
    }

    fn segment(self, account_id: AccountId, bytecode: Vec<u8>, next: Option<AccountId>) -> Self {
        self.with(
            account_id,
            ActorState::try_from(
                ProgramSegment {
                    bytecode,
                    next_segment: next,
                }
                .to_bytes(),
            )
            .unwrap(),
        )
    }

    fn header(self, account_id: AccountId, header: &ProgramHeader) -> Self {
        self.with(account_id, ActorState::try_from(header.to_bytes()).unwrap())
    }

    fn read<'shards>(&'shards self) -> impl Fn(AccountId) -> &'shards ActorState + 'shards {
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
        origin: Origin::Root,
        is_authorized,
        pre_state,
        message: borsh::to_vec(message).expect("borsh serialization is infallible"),
    }
}

#[test]
fn write_segment_writes_the_loader_shard() {
    let target_id = AccountId::new([1; 32]);
    let shards = Shards::default();
    let message = Message::WriteSegment {
        bytecode: vec![1, 2, 3],
        next_segment: None,
    };

    let (transition, new_commitment) = receive(
        &input(target_id, false, ActorState::empty(), &message),
        shards.read(),
    );

    let post_state = transition
        .response
        .post_state
        .expect("a segment was written");
    let segment = ProgramSegment::from_bytes(&post_state).expect("valid segment");
    assert_eq!(segment.bytecode, vec![1, 2, 3]);
    assert_eq!(segment.next_segment, None);
    assert!(transition.response.sends.is_empty());
    assert!(new_commitment.is_none());
}

#[test]
#[should_panic(expected = "already deployed")]
fn write_segment_rejects_an_occupied_loader_shard() {
    let target_id = AccountId::new([1; 32]);
    let shards = Shards::default().segment(target_id, vec![9], None);
    let pre_state = shards.read()(target_id).clone();
    let message = Message::WriteSegment {
        bytecode: vec![1],
        next_segment: None,
    };

    let _transition = receive(&input(target_id, false, pre_state, &message), shards.read());
}

#[test]
#[should_panic(expected = "must already hold a valid segment")]
fn write_segment_rejects_a_next_segment_with_malformed_data() {
    let target_id = AccountId::new([1; 32]);
    let next_id = AccountId::new([2; 32]);
    let shards = Shards::default().with(next_id, ActorState::try_from(vec![0xff, 0xff]).unwrap());
    let message = Message::WriteSegment {
        bytecode: vec![1],
        next_segment: Some(next_id),
    };

    let _transition = receive(
        &input(target_id, false, ActorState::empty(), &message),
        shards.read(),
    );
}

#[test]
#[should_panic(expected = "header target already deployed")]
fn create_header_rejects_an_occupied_loader_shard() {
    let target_id = AccountId::new([1; 32]);
    let shards = Shards::default().header(
        target_id,
        &ProgramHeader {
            image_id: [0; 8],
            program_first_segment: AccountId::new([2; 32]),
            immutable: false,
        },
    );
    let pre_state = shards.read()(target_id).clone();
    let message = Message::CreateHeader {
        first_segment: AccountId::new([2; 32]),
        immutable: false,
    };

    let _transition = receive(&input(target_id, false, pre_state, &message), shards.read());
}

#[test]
#[should_panic(expected = "must decode as a valid ProgramSegment")]
fn create_header_rejects_a_chain_that_does_not_end() {
    let target_id = AccountId::new([1; 32]);
    let first_segment = AccountId::new([2; 32]);
    let second_segment = AccountId::new([3; 32]);
    let dangling = AccountId::new([4; 32]);
    let shards = Shards::default()
        .segment(first_segment, vec![1], Some(second_segment))
        .segment(second_segment, vec![2], Some(dangling));
    let message = Message::CreateHeader {
        first_segment,
        immutable: false,
    };

    let _transition = receive(
        &input(target_id, true, ActorState::empty(), &message),
        shards.read(),
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

    let _transition = receive(
        &input(target_id, true, ActorState::empty(), &message),
        Shards::default().read(),
    );
}

#[test]
#[should_panic(expected = "immutable and cannot be updated")]
fn update_header_rejects_an_immutable_header() {
    let target_id = AccountId::new([1; 32]);
    let first_segment = AccountId::new([2; 32]);
    let shards = Shards::default().header(
        target_id,
        &ProgramHeader {
            image_id: [0; 8],
            program_first_segment: first_segment,
            immutable: true,
        },
    );
    let pre_state = shards.read()(target_id).clone();
    let message = Message::UpdateHeader {
        first_segment,
        immutable: false,
    };

    let _transition = receive(&input(target_id, true, pre_state, &message), shards.read());
}

#[test]
#[should_panic(expected = "must be authorized by the signer")]
fn update_header_rejects_an_unauthorized_caller() {
    let target_id = AccountId::new([1; 32]);
    let first_segment = AccountId::new([2; 32]);
    let shards = Shards::default().header(
        target_id,
        &ProgramHeader {
            image_id: [0; 8],
            program_first_segment: first_segment,
            immutable: false,
        },
    );
    let pre_state = shards.read()(target_id).clone();
    let message = Message::UpdateHeader {
        first_segment,
        immutable: false,
    };

    let _transition = receive(&input(target_id, false, pre_state, &message), shards.read());
}

#[test]
#[should_panic(expected = "the native token program has no deployable bytecode")]
fn a_header_may_not_be_created_for_the_native_token_program() {
    let segment_id = AccountId::new([2; 32]);
    let message = Message::CreateHeader {
        first_segment: segment_id,
        immutable: false,
    };

    let _transition = receive(
        &input(NATIVE_TOKEN_PROGRAM_ID, true, ActorState::empty(), &message),
        Shards::default().read(),
    );
}

#[test]
#[should_panic(expected = "the loader's own dispatch address")]
fn a_segment_cannot_be_written_at_the_loader_address() {
    let message = Message::WriteSegment {
        bytecode: vec![0_u8; 32],
        next_segment: None,
    };

    let _transition = receive(
        &input(
            PROGRAM_LOADER_ACCOUNT_ID,
            true,
            ActorState::empty(),
            &message,
        ),
        Shards::default().read(),
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

    let _transition = receive(
        &input(
            PROGRAM_LOADER_ACCOUNT_ID,
            true,
            ActorState::empty(),
            &message,
        ),
        Shards::default().read(),
    );
}
