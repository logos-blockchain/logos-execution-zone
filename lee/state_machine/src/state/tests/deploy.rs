use lee_core::program::{PROGRAM_LOADER_ACCOUNT_ID, ProgramHeader, ProgramSegment};
use program_loader_core::Instruction;

use super::*;
use crate::state::MAX_PROGRAM_SEGMENTS;

/// Proof that a program's bytecode split across multiple segment accounts reconstructs into
/// something that executes identically to the original: writes several segments (linked
/// tail-to-head, at arbitrary addresses) plus a `ProgramHeader` directly via
/// `force_insert_account`, then confirms `get_program` returns the same bytes and execution
/// output as a direct run against the untouched original.
#[test]
fn manually_segmented_program_reconstructs_and_executes_identically() {
    let program = crate::test_methods::claimer();
    let full_binary = program.elf();

    // However many chunks, as long as it's more than one — this is testing reconstruction
    // across several accounts, not any particular chunk size.
    let chunk_size = full_binary.len().div_ceil(4).max(1);
    let chunks: Vec<&[u8]> = full_binary.chunks(chunk_size).collect();
    assert!(
        chunks.len() > 1,
        "test needs a real multi-chunk split, got {} chunk(s)",
        chunks.len()
    );

    let mut state = V03State::new();

    // Segment addresses carry no derivation requirement — arbitrary, distinct accounts.
    let segment_account_ids: Vec<AccountId> = (0..chunks.len())
        .map(|i| AccountId::new([u8::try_from(i + 1).unwrap(); 32]))
        .collect();

    // Linked tail-to-head: the last chunk's segment has no `next_segment`.
    for (i, chunk) in chunks.iter().enumerate().rev() {
        state.force_insert_account(
            segment_account_ids[i],
            Account {
                program_owner: PROGRAM_LOADER_ACCOUNT_ID,
                data: Data::from(&ProgramSegment {
                    bytecode: chunk.to_vec(),
                    next_segment: segment_account_ids.get(i + 1).copied(),
                }),
                ..Account::default()
            },
        );
    }

    let header_account_id = AccountId::new([0xff; 32]);
    state.force_insert_account(
        header_account_id,
        Account {
            program_owner: PROGRAM_LOADER_ACCOUNT_ID,
            data: Data::from(&ProgramHeader {
                image_id: program.id(),
                program_first_segment: segment_account_ids[0],
                immutable: true,
            }),
            ..Account::default()
        },
    );

    let (found_image_id, reconstructed_binary) = state
        .get_program(header_account_id)
        .expect("a fully-landed multi-segment program must reconstruct without error")
        .expect("a fully-landed multi-segment program must be found");
    assert_eq!(
        found_image_id,
        program.id(),
        "get_program must recompute the same image_id as the original"
    );
    assert_eq!(
        reconstructed_binary, full_binary,
        "get_program must concatenate the segments back in order to reproduce the original exactly"
    );

    let reconstructed_program = Program::new(reconstructed_binary.into()).unwrap();
    assert_eq!(
        reconstructed_program.id(),
        program.id(),
        "the reconstructed binary must recompute to the same image_id"
    );

    let pre_states = vec![AccountWithMetadata::new(
        Account::default(),
        true,
        AccountId::new([21; 32]),
    )];
    let instruction_data = Program::serialize_instruction(()).unwrap();
    let self_account_id = program.deployed_account_id();

    let direct_output = program
        .execute(self_account_id, None, &pre_states, &instruction_data)
        .expect("direct execution against the original binary should succeed");
    let reconstructed_output = reconstructed_program
        .execute(self_account_id, None, &pre_states, &instruction_data)
        .expect("execution against the manually-reconstructed binary should succeed");

    assert_eq!(direct_output, reconstructed_output);
}

/// A segment chain longer than `MAX_PROGRAM_SEGMENTS` is rejected. The cap trips before the walk
/// checks the next account exists, so the one past the limit is never created.
#[test]
fn program_with_more_than_max_segments_is_rejected() {
    let mut state = V03State::new();

    let segment_account_ids: Vec<AccountId> = (0..MAX_PROGRAM_SEGMENTS)
        .map(|i| AccountId::new([u8::try_from(i + 1).unwrap(); 32]))
        .collect();
    let one_too_many = AccountId::new([0xEE; 32]);

    for i in (0..MAX_PROGRAM_SEGMENTS).rev() {
        let next_segment = if i + 1 == MAX_PROGRAM_SEGMENTS {
            Some(one_too_many)
        } else {
            segment_account_ids.get(i + 1).copied()
        };
        state.force_insert_account(
            segment_account_ids[i],
            Account {
                program_owner: PROGRAM_LOADER_ACCOUNT_ID,
                data: Data::from(&ProgramSegment {
                    bytecode: vec![],
                    next_segment,
                }),
                ..Account::default()
            },
        );
    }

    let header_account_id = AccountId::new([0xff; 32]);
    state.force_insert_account(
        header_account_id,
        Account {
            program_owner: PROGRAM_LOADER_ACCOUNT_ID,
            data: Data::from(&ProgramHeader {
                image_id: [0; 8],
                program_first_segment: segment_account_ids[0],
                immutable: true,
            }),
            ..Account::default()
        },
    );

    assert!(
        matches!(
            state.get_program(header_account_id),
            Err(LeeError::InvalidProgramBytecode(_))
        ),
        "a chain of {} segments must be rejected by the {MAX_PROGRAM_SEGMENTS}-segment cap",
        MAX_PROGRAM_SEGMENTS + 1
    );
}

/// An `UploadHeader` transaction naming an over-long chain is rejected outright.
#[test]
fn program_with_more_than_max_segments_is_rejected_at_deploy_time() {
    let mut state = V03State::new();

    let segment_account_ids: Vec<AccountId> = (0..=MAX_PROGRAM_SEGMENTS)
        .map(|i| AccountId::new([u8::try_from(i + 1).unwrap(); 32]))
        .collect();

    for i in (0..segment_account_ids.len()).rev() {
        state.force_insert_account(
            segment_account_ids[i],
            Account {
                program_owner: PROGRAM_LOADER_ACCOUNT_ID,
                data: Data::from(&ProgramSegment {
                    bytecode: vec![],
                    next_segment: segment_account_ids.get(i + 1).copied(),
                }),
                ..Account::default()
            },
        );
    }

    let header_key = PrivateKey::try_new([0xAB; 32]).unwrap();
    let header_account_id = AccountId::from(&PublicKey::new_from_private_key(&header_key));

    let mut account_ids = vec![header_account_id];
    account_ids.extend_from_slice(&segment_account_ids);
    let message = public_transaction::Message::try_new(
        PROGRAM_LOADER_ACCOUNT_ID,
        account_ids,
        vec![Nonce(0)],
        Instruction::CreateHeader {
            first_segment: segment_account_ids[0],
            immutable: true,
        },
    )
    .expect("UploadHeader instruction data should always be serializable");
    let witness_set = public_transaction::WitnessSet::for_message(&message, &[&header_key]);
    let tx = PublicTransaction::new(message, witness_set);

    let result = state.transition_from_public_transaction(&tx, 1, 0);

    let err = result.expect_err("an over-long chain must be rejected at deploy time");
    assert!(
        err.to_string().contains("segment chain exceeds"),
        "rejection should cite the segment cap, got: {err}"
    );
    assert_eq!(
        state.get_account_by_id(header_account_id),
        Account::default(),
        "the header account must remain unclaimed after a rejected deploy"
    );
}
