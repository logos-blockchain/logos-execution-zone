//! Exercises `program_loader`'s native (non-guest) dispatch fast-path in
//! `ValidatedStateDiff::execute_authorized`, and `get_program_via`'s segment-chain resolution
//! that a live deploy (or a hand-assembled one, here) must decode back out of.

use lee_core::program::{MAX_PROGRAM_SEGMENTS, ProgramHeader, ReceiveInput};
use program_loader_core::Message as LoaderMessage;

use super::*;

fn loader_tx(
    target: AccountId,
    nonces: Vec<Nonce>,
    message: &LoaderMessage,
    signers: &[&PrivateKey],
) -> PublicTransaction {
    let to = Actor::new(target, PROGRAM_LOADER_ACCOUNT_ID);
    public_tx(to, vec![to], nonces, message, signers)
}

/// Proof that a program's bytecode split across multiple segment accounts reconstructs into
/// something that executes identically to the original: writes several segments (linked
/// tail-to-head, at arbitrary addresses) plus a `ProgramHeader` directly via
/// `force_insert_account`, then confirms `get_builtin_program` returns the same bytes and execution
/// output as a direct run against the untouched original.
#[test]
fn manually_segmented_program_reconstructs_and_executes_identically() {
    let program = crate::test_methods::scripted();
    let full_binary = program.elf();
    // Segments only ever hold `user_elf`.
    let user_elf = risc0_binfmt::ProgramBinary::decode(full_binary)
        .unwrap()
        .user_elf;

    // However many chunks, as long as it's more than one — this is testing reconstruction
    // across several accounts, not any particular chunk size.
    let chunk_size = user_elf.len().div_ceil(4).max(1);
    let chunks: Vec<&[u8]> = user_elf.chunks(chunk_size).collect();
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
            Account::default().with_shard(
                PROGRAM_LOADER_ACCOUNT_ID,
                ActorState::from(
                    ProgramSegment {
                        bytecode: chunk.to_vec(),
                        next_segment: segment_account_ids.get(i + 1).copied(),
                    }
                    .to_bytes(),
                ),
            ),
        );
    }

    // A header can be looked up by `get_builtin_program` at any chosen `ProgramId` — its own
    // `image_id` field (asserted below) is what actually carries the program's real identity.
    let header_program_id: ProgramId = [0xffff_ffff; 8];
    let header_account_id = AccountId::from_builtin_program(header_program_id);
    state.force_insert_account(
        header_account_id,
        Account::default().with_shard(
            PROGRAM_LOADER_ACCOUNT_ID,
            ActorState::from(
                ProgramHeader {
                    image_id: program.id(),
                    program_first_segment: segment_account_ids[0],
                    immutable: true,
                }
                .to_bytes(),
            ),
        ),
    );

    let (found_image_id, reconstructed_binary) = state
        .get_builtin_program(header_account_id)
        .expect("a fully-landed multi-segment program must be found");
    assert_eq!(
        found_image_id,
        program.id(),
        "get_builtin_program must recompute the same image_id as the original"
    );
    assert_eq!(
        reconstructed_binary, full_binary,
        "get_builtin_program must concatenate the segments back in order to reproduce the original exactly"
    );

    let reconstructed_program = Program::new(reconstructed_binary.into()).unwrap();
    assert_eq!(
        reconstructed_program.id(),
        program.id(),
        "the reconstructed binary must recompute to the same image_id"
    );

    let receiver = Actor::new(AccountId::new([21; 32]), header_account_id);
    let input = ReceiveInput {
        receiver,
        origin: None,
        is_authorized: true,
        pre_state: ActorState::empty(),
        message: Program::serialize_message(Script::write(vec![7; 4])).unwrap(),
    };

    let direct_output = program
        .receive(&input, crate::program::DEFAULT_PUBLIC_CYCLE_BUDGET)
        .expect("direct execution against the original binary should succeed");
    let reconstructed_output = reconstructed_program
        .receive(&input, crate::program::DEFAULT_PUBLIC_CYCLE_BUDGET)
        .expect("execution against the manually-reconstructed binary should succeed");

    assert_eq!(direct_output, reconstructed_output);
}

/// Unlike the round-trip above, which builds its program in-tree, this checks a real committed
/// artifact, so it can catch its embedded kernel drifting from the protocol's current one.
#[test]
fn a_committed_artifacts_kernel_has_not_drifted() {
    let user_elf = risc0_binfmt::ProgramBinary::decode(crate::PRIVACY_PRESERVING_CIRCUIT_ELF)
        .expect("a committed artifact decodes")
        .user_elf;
    let reattached = crate::program::attach_kernel(user_elf);
    let image_id: ProgramId = risc0_binfmt::compute_image_id(&reattached)
        .expect("re-attaching the current kernel must still decode")
        .into();
    assert_eq!(
        image_id,
        crate::PRIVACY_PRESERVING_CIRCUIT_ID,
        "the committed artifact's embedded kernel no longer matches attach_kernel's current one \
         \u{2014} rebuild artifacts (`just build-artifacts`)"
    );
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
            Account::default().with_shard(
                PROGRAM_LOADER_ACCOUNT_ID,
                ActorState::from(
                    ProgramSegment {
                        bytecode: vec![],
                        next_segment,
                    }
                    .to_bytes(),
                ),
            ),
        );
    }

    let header_program_id: ProgramId = [0; 8];
    let header_account_id = AccountId::from_builtin_program(header_program_id);
    state.force_insert_account(
        header_account_id,
        Account::default().with_shard(
            PROGRAM_LOADER_ACCOUNT_ID,
            ActorState::from(
                ProgramHeader {
                    image_id: header_program_id,
                    program_first_segment: segment_account_ids[0],
                    immutable: true,
                }
                .to_bytes(),
            ),
        ),
    );

    assert!(
        state.get_builtin_program(header_account_id).is_none(),
        "a chain of {} segments must be rejected by the {MAX_PROGRAM_SEGMENTS}-segment cap",
        MAX_PROGRAM_SEGMENTS + 1
    );
}

/// A `CreateHeader` transaction naming an over-long chain is rejected outright, through the same
/// native dispatch path (`PROGRAM_LOADER_ACCOUNT_ID`) a real deploy uses — not a guest, and not
/// `force_insert_account`.
#[test]
fn program_with_more_than_max_segments_is_rejected_at_deploy_time() {
    let mut state = V03State::new();

    let segment_account_ids: Vec<AccountId> = (0..=MAX_PROGRAM_SEGMENTS)
        .map(|i| AccountId::new([u8::try_from(i + 1).unwrap(); 32]))
        .collect();

    for i in (0..segment_account_ids.len()).rev() {
        state.force_insert_account(
            segment_account_ids[i],
            Account::default().with_shard(
                PROGRAM_LOADER_ACCOUNT_ID,
                ActorState::from(
                    ProgramSegment {
                        bytecode: vec![],
                        next_segment: segment_account_ids.get(i + 1).copied(),
                    }
                    .to_bytes(),
                ),
            ),
        );
    }

    let header_key = PrivateKey::try_new([0xAB; 32]).unwrap();
    let header_account_id = AccountId::from(&PublicKey::new_from_private_key(&header_key));

    let tx = loader_tx(
        header_account_id,
        vec![Nonce(0)],
        &LoaderMessage::CreateHeader {
            first_segment: segment_account_ids[0],
            immutable: true,
        },
        &[&header_key],
    );

    let result = state.transition_from_public_transaction(&tx, 1, 0);

    let err = result.expect_err("an over-long chain must be rejected at deploy time");
    assert!(
        err.to_string().contains("segment chain exceeds"),
        "rejection should cite the segment cap, got: {err}"
    );
    assert_eq!(
        state.get_account_by_id(header_account_id),
        Account::default(),
        "the header account must be untouched after a rejected deploy"
    );
}

/// Writes a segment chain and header through the native loader, then executes the program.
#[test]
fn write_segment_then_create_header_deploys_a_dispatchable_program() {
    let mut state = V03State::new();
    let program = crate::test_methods::scripted();

    let user_elf = risc0_binfmt::ProgramBinary::decode(program.elf())
        .unwrap()
        .user_elf
        .to_vec();
    let chunks: Vec<&[u8]> = user_elf
        .chunks(program_loader_core::MAX_SEGMENT_DATA_LEN)
        .collect();
    // Base 10 keeps these clear of the header key's [2; 32] below.
    let segment_keys: Vec<PrivateKey> = (0..chunks.len())
        .map(|i| PrivateKey::try_new([u8::try_from(i).unwrap().saturating_add(10); 32]).unwrap())
        .collect();
    let segment_account_ids: Vec<AccountId> = segment_keys
        .iter()
        .map(|key| AccountId::from(&PublicKey::new_from_private_key(key)))
        .collect();

    write_segments(&mut state, &chunks, &segment_keys, &segment_account_ids);

    let header_key = PrivateKey::try_new([2; 32]).unwrap();
    let header_account_id = AccountId::from(&PublicKey::new_from_private_key(&header_key));
    let create_header_tx = loader_tx(
        header_account_id,
        vec![Nonce(0)],
        &LoaderMessage::CreateHeader {
            first_segment: segment_account_ids[0],
            immutable: true,
        },
        &[&header_key],
    );
    state
        .transition_from_public_transaction(&create_header_tx, 2, 0)
        .expect("CreateHeader should succeed once the segment it names already exists");

    // Deployed at an arbitrary key-derived address rather than its builtin address, so
    // resolution goes through `get_program_via` directly.
    let (image_id, user_elf) =
        lee_core::program::get_program_via(header_account_id, |id| state.loader_shard(id))
            .expect("the newly-deployed program must be resolvable by its header address");
    assert_eq!(image_id, program.id());
    assert_eq!(
        crate::program::attach_kernel(&user_elf),
        program.elf().to_vec()
    );

    // Dispatch a root delivery to the freshly-deployed address, exactly like calling any
    // builtin — the loader's native handling of the deploy is invisible from here on.
    let target_id = AccountId::new([9; 32]);
    let target = Actor::new(target_id, header_account_id);
    let call_tx = public_tx(target, vec![target], vec![], Script::default(), &[]);
    state
        .transition_from_public_transaction(&call_tx, 3, 0)
        .expect("dispatching to the deployed program must succeed like any other account");
    assert_eq!(
        state.get_account_by_id(target_id),
        Account::default(),
        "an empty script changes nothing"
    );
}

#[test]
fn create_header_rejects_a_shadow_derived_target_the_signer_does_not_control() {
    let mut state = V03State::new();
    let honest_program = crate::test_methods::scripted();
    let weakened_program = crate::test_methods::forges_echo();
    let segment_account_ids = force_insert_segment_chain(&mut state, honest_program.elf(), 0x20);

    let shadow_addr = AccountId::for_shadow_program(&weakened_program.id());

    let unrelated_key = PrivateKey::try_new([0x77; 32]).unwrap();
    let tx = loader_tx(
        shadow_addr,
        vec![Nonce(0)],
        &LoaderMessage::CreateHeader {
            first_segment: segment_account_ids[0],
            immutable: true,
        },
        &[&unrelated_key],
    );

    let result = state.transition_from_public_transaction(&tx, 1, 0);

    let err = result.expect_err("a header target the signer doesn't control must be rejected");
    assert!(
        err.to_string().contains("must be an authorized account"),
        "rejection should cite the authorization rule, got: {err}"
    );
    assert_eq!(
        state.get_account_by_id(shadow_addr),
        Account::default(),
        "the shadow-derived account must remain unclaimed after a rejected deploy"
    );
}

/// A `CreateHeader` transaction with `immutable: true` lands the private commitment mirroring the
/// finalized header, so it can later be referenced in a privacy-preserving transaction without
/// public disclosure.
#[test]
fn create_header_immutable_from_birth_lands_immutable_mirror_commitment() {
    let mut state = V03State::new();
    let program = crate::test_methods::scripted();
    let segment_account_ids = force_insert_segment_chain(&mut state, program.elf(), 0x01);

    let header_key = PrivateKey::try_new([0xAB; 32]).unwrap();
    let header_account_id = AccountId::from(&PublicKey::new_from_private_key(&header_key));

    let tx = loader_tx(
        header_account_id,
        vec![Nonce(0)],
        &LoaderMessage::CreateHeader {
            first_segment: segment_account_ids[0],
            immutable: true,
        },
        &[&header_key],
    );

    state
        .transition_from_public_transaction(&tx, 1, 0)
        .expect("an immutable-from-birth CreateHeader should succeed");

    let expected_header = ProgramHeader {
        image_id: program.id(),
        program_first_segment: segment_account_ids[0],
        immutable: true,
    };
    let commitment =
        program_loader_core::immutable_mirror_commitment(header_account_id, &expected_header);
    assert!(
        state.get_proof_for_commitment(&commitment).is_some(),
        "an immutable-from-birth header must land its private mirror commitment"
    );
}

/// A `CreateHeader` transaction with `immutable: false` leaves the private commitment tree
/// untouched — only a header that's actually immutable ever gets a mirror commitment.
#[test]
fn create_header_mutable_leaves_commitment_tree_unchanged() {
    let mut state = V03State::new();
    let program = crate::test_methods::scripted();
    let root_before = state.commitment_root();
    let segment_account_ids = force_insert_segment_chain(&mut state, program.elf(), 0x02);

    let header_key = PrivateKey::try_new([0xCD; 32]).unwrap();
    let header_account_id = AccountId::from(&PublicKey::new_from_private_key(&header_key));

    let tx = loader_tx(
        header_account_id,
        vec![Nonce(0)],
        &LoaderMessage::CreateHeader {
            first_segment: segment_account_ids[0],
            immutable: false,
        },
        &[&header_key],
    );

    state
        .transition_from_public_transaction(&tx, 1, 0)
        .expect("a mutable CreateHeader should succeed");

    assert_eq!(
        state.commitment_root(),
        root_before,
        "a header deployed with immutable: false must not emit any private commitment"
    );
}

/// An `UpdateHeader` transaction that flips `immutable` from `false` to `true` lands the private
/// mirror commitment at that exact moment — the same as being immutable from birth.
#[test]
fn update_header_flip_to_immutable_lands_immutable_mirror_commitment() {
    let mut state = V03State::new();
    let program = crate::test_methods::scripted();
    let segment_account_ids = force_insert_segment_chain(&mut state, program.elf(), 0x03);

    let header_key = PrivateKey::try_new([0xEF; 32]).unwrap();
    let header_account_id = AccountId::from(&PublicKey::new_from_private_key(&header_key));

    let create_tx = loader_tx(
        header_account_id,
        vec![Nonce(0)],
        &LoaderMessage::CreateHeader {
            first_segment: segment_account_ids[0],
            immutable: false,
        },
        &[&header_key],
    );
    state
        .transition_from_public_transaction(&create_tx, 1, 0)
        .expect("the initial mutable CreateHeader should succeed");

    let root_after_create = state.commitment_root();
    let current_nonce = state.get_account_by_id(header_account_id).nonce;

    let update_tx = loader_tx(
        header_account_id,
        vec![current_nonce],
        &LoaderMessage::UpdateHeader {
            first_segment: segment_account_ids[0],
            immutable: true,
        },
        &[&header_key],
    );
    state
        .transition_from_public_transaction(&update_tx, 2, 0)
        .expect("flipping immutable to true via UpdateHeader should succeed");

    assert_ne!(
        state.commitment_root(),
        root_after_create,
        "flipping immutable to true must land a new private commitment"
    );

    let expected_header = ProgramHeader {
        image_id: program.id(),
        program_first_segment: segment_account_ids[0],
        immutable: true,
    };
    let commitment =
        program_loader_core::immutable_mirror_commitment(header_account_id, &expected_header);
    assert!(
        state.get_proof_for_commitment(&commitment).is_some(),
        "the landed commitment must match the now-immutable header"
    );
}

fn write_segments(
    state: &mut V03State,
    chunks: &[&[u8]],
    segment_keys: &[PrivateKey],
    segment_account_ids: &[AccountId],
) {
    // Linked tail-to-head: the last chunk's segment has no `next_segment`.
    for i in (0..chunks.len()).rev() {
        let tx = loader_tx(
            segment_account_ids[i],
            vec![Nonce(0)],
            &LoaderMessage::WriteSegment {
                bytecode: chunks[i].to_vec(),
                next_segment: segment_account_ids.get(i.saturating_add(1)).copied(),
            },
            &[&segment_keys[i]],
        );
        state
            .transition_from_public_transaction(&tx, 1, 0)
            .expect("WriteSegment should succeed against a fresh account");
    }
}

#[test]
fn a_program_deployed_earlier_in_the_transaction_is_dispatchable_by_a_later_call() {
    let mut state = V03State::new().with_test_programs();
    let program = crate::test_methods::scripted();

    let user_elf = risc0_binfmt::ProgramBinary::decode(program.elf())
        .unwrap()
        .user_elf
        .to_vec();
    let chunks: Vec<&[u8]> = user_elf
        .chunks(program_loader_core::MAX_SEGMENT_DATA_LEN)
        .collect();
    let segment_keys: Vec<PrivateKey> = (0..chunks.len())
        .map(|i| PrivateKey::try_new([u8::try_from(i).unwrap().saturating_add(20); 32]).unwrap())
        .collect();
    let segment_account_ids: Vec<AccountId> = segment_keys
        .iter()
        .map(|key| AccountId::from(&PublicKey::new_from_private_key(key)))
        .collect();
    write_segments(&mut state, &chunks, &segment_keys, &segment_account_ids);

    let header_key = PrivateKey::try_new([30; 32]).unwrap();
    let header_account_id = AccountId::from(&PublicKey::new_from_private_key(&header_key));
    let deployer = Actor::new(header_account_id, scripted_id());
    let header = Actor::new(header_account_id, PROGRAM_LOADER_ACCOUNT_ID);
    let deployed = Actor::new(AccountId::new([9; 32]), header_account_id);
    let tx = public_tx(
        deployer,
        vec![deployer, header, deployed],
        vec![Nonce(0)],
        Script::default()
            .call(
                header,
                &LoaderMessage::CreateHeader {
                    first_segment: segment_account_ids[0],
                    immutable: true,
                },
            )
            .call(deployed, &Script::write(vec![7; 4])),
        &[&header_key],
    );

    state
        .transition_from_public_transaction(&tx, 2, 0)
        .expect("the header written by the first send must dispatch the second");

    let (image_id, _) =
        lee_core::program::get_program_via(header_account_id, |id| state.loader_shard(id)).unwrap();
    assert_eq!(image_id, program.id());
    assert_eq!(
        state
            .get_account_by_id(deployed.account_id)
            .data
            .shard(header_account_id)
            .as_ref(),
        [7; 4]
    );
}
