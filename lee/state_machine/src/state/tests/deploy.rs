use lee_core::program::PROGRAM_LOADER_ACCOUNT_ID;

use super::*;

/// Ad hoc proof that a program's bytecode can be split across multiple PDA accounts and
/// reconstructed into something that executes identically to the original.
///
/// No production code path exercises this yet — `execute_deploy`/`get_program` are still
/// single-segment only (a real `Deploy` writes exactly one segment). But
/// `program_loader_core::segment_pda_seed` already takes a segment index as an input (currently
/// always `0` in production — see its doc comment), so the addressing scheme this test drives by
/// hand is the real one, not a stand-in. This test writes several segment accounts directly via
/// `force_insert_account`, fetches them back in order, concatenates, and confirms both the bytes
/// and the execution output match a direct run against the untouched original.
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

    let reconstructed_binary: Vec<u8> = segment_account_ids
        .iter()
        .flat_map(|account_id| state.get_account_by_id(*account_id).data.to_vec())
        .collect();
    assert_eq!(
        reconstructed_binary, full_binary,
        "concatenating the segments back in order must reproduce the original binary exactly"
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
