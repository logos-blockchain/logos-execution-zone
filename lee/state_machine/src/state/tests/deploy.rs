use lee_core::program::{PROGRAM_LOADER_ACCOUNT_ID, ProgramHeader, ProgramSegment};

use super::*;

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
