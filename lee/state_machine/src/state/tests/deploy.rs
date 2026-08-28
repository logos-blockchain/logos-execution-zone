use lee_core::program::{PROGRAM_LOADER_ACCOUNT_ID, ProgramData};

use super::*;

/// Ad hoc proof that a program's bytecode can be split across multiple PDA accounts and
/// reconstructed into something that executes identically to the original.
///
/// No production code path *writes* more than one segment yet — a real `Deploy` still writes
/// exactly one — but `get_program` itself already reconstructs across however many segments a
/// header declares, so this test drives that reconstruction for real: it writes several segment
/// accounts plus a `ProgramData` header directly via `force_insert_account`, then calls
/// `get_program` on the header and confirms both the returned bytes and the execution output
/// match a direct run against the untouched original.
#[test]
fn manually_segmented_program_reconstructs_and_executes_identically() {
    let program = crate::test_methods::claimer();
    let full_binary = program.elf();
    let update_auth = AccountId::default();

    // However many chunks, as long as it's more than one — this is testing reconstruction
    // across several accounts, not any particular chunk size.
    let chunk_size = full_binary.len().div_ceil(4).max(1);
    let chunks: Vec<&[u8]> = full_binary.chunks(chunk_size).collect();
    assert!(
        chunks.len() > 1,
        "test needs a real multi-chunk split, got {} chunk(s)",
        chunks.len()
    );
    // segment_count currently holds the last segment's index, not a count.
    let segment_count = u32::try_from(chunks.len() - 1).unwrap();

    let mut state = V03State::new();
    let segment_account_ids: Vec<AccountId> = (0..chunks.len())
        .map(|i| {
            program_loader_core::segment_account_id(
                PROGRAM_LOADER_ACCOUNT_ID,
                program.id(),
                u32::try_from(i).unwrap(),
                update_auth,
            )
        })
        .collect();
    for (account_id, chunk) in segment_account_ids.iter().zip(&chunks) {
        state.force_insert_account(
            *account_id,
            Account {
                program_owner: PROGRAM_LOADER_ACCOUNT_ID,
                data: Data::try_from(chunk.to_vec()).unwrap(),
                ..Account::default()
            },
        );
    }

    let header_account_id = program_loader_core::header_account_id(
        PROGRAM_LOADER_ACCOUNT_ID,
        program.id(),
        segment_count,
        update_auth,
    );
    state.force_insert_account(
        header_account_id,
        Account {
            program_owner: PROGRAM_LOADER_ACCOUNT_ID,
            data: Data::from(&ProgramData {
                image_id: program.id(),
                segment_count,
                update_auth,
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
