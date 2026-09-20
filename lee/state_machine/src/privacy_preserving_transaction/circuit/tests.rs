#![expect(clippy::shadow_unrelated, reason = "We don't care about it in tests")]

use lee_core::{
    Commitment, DUMMY_COMMITMENT_HASH, EncryptedAccountData, EncryptionScheme, EphemeralSecretKey,
    Nullifier, NullifierPublicKey, NullifierWitness, PrivacyPreservingCircuitOutput,
    PrivateWitness, PublicAction, SharedSecretKey, WitnessKind,
    account::{Account, AccountId, AccountWithMetadata, Nonce, data::Data},
    program::{PdaSeed, PrivateAccountKind},
};

use super::*;
use crate::{
    error::LeeError,
    privacy_preserving_transaction::circuit::execute_and_prove,
    program::Program,
    state::{
        CommitmentSet,
        tests::{init_pda_witness, test_private_account_keys_1, test_private_account_keys_2},
    },
};

#[derive(borsh::BorshSerialize)]
enum StrippedTokenInstruction {
    Initialize { balance: u128 },
    Transfer { amount: u128 },
}

/// Mirrors just the variant `stripped_token`'s `Initialize` produces - discriminant 0, matching
/// the guest's own `enum TokenDiff { Add(u128), Sub(u128) }`.
#[derive(borsh::BorshSerialize)]
enum TokenDiff {
    Add(u128),
}

/// Mirrors `stripped_token`'s own `TokenAccountData` - what its `Update` resolves a diff to.
#[derive(borsh::BorshSerialize, borsh::BorshDeserialize)]
struct TokenAccountData {
    balance: u128,
}

/// `lying_probe_instruction` always claims to be answering `A`, regardless of what it's
/// actually asked. `verify_probe_receipt` binds a `Probe` answer to the instruction its real
/// `Execute` call received, so proving `B` (with `A`'s dishonest `Probe` receipt attached) must
/// be rejected, not silently accepted as covering `B`.
#[derive(borsh::BorshSerialize)]
enum LyingProbeInstruction {
    #[expect(dead_code, reason = "discriminant must match the guest's `Instruction::A` (0)")]
    A,
    B,
}

/// Which receipt(s) `execute_and_prove_omitting_a_receipt` should withhold — simulating a
/// dishonest *prover* that skips proving something the honest pipeline always supplies, as
/// opposed to a dishonest *guest* that lies inside a receipt it does supply.
enum Omit {
    /// Withholds `Update` too: leaving it queued would misattribute it as the `Probe` slot
    /// instead of leaving the queue genuinely empty where `Probe` is expected.
    Probe,
    Update,
}

fn decrypt_kind(
    output: &PrivacyPreservingCircuitOutput,
    ssk: &SharedSecretKey,
    idx: usize,
) -> PrivateAccountKind {
    let (kind, _) = EncryptionScheme::decrypt(
        &output.private_actions[idx].encrypted_post_state.ciphertext,
        ssk,
        &output.private_actions[idx].nullifier,
    )
    .unwrap();
    kind
}

/// A single-call, no-chaining rebuild of `execute_and_prove`'s proving pipeline, with `omit`
/// withholding one receipt the honest pipeline always supplies for a call that writes a public
/// account. `PrivateBackend` treats every receipt as untrusted prover input verified only by
/// `env::verify`, so this exercises what happens when the prover simply doesn't supply one,
/// distinct from `lying_*`'s dishonest-but-present receipts.
fn execute_and_prove_omitting_a_receipt(
    program: &Program,
    self_account_id: AccountId,
    pre: &AccountWithMetadata,
    instruction_data: &InstructionData,
    omit: &Omit,
) -> Result<(PrivacyPreservingCircuitOutput, Proof), LeeError> {
    let mut env_builder = ExecutorEnv::builder();
    let mut program_outputs = Vec::new();
    let pre_states = vec![pre.clone()];

    let execute_receipt = execute_and_prove_program(
        program,
        self_account_id,
        None,
        &pre_states,
        instruction_data,
    )?;
    let execute_output: ProgramOutput =
        borsh::from_slice(from_frame(&execute_receipt.journal.bytes).ok_or_else(|| {
            LeeError::ProgramOutputDeserializationError(
                "malformed inner-receipt journal frame".to_owned(),
            )
        })?)
        .map_err(|e| LeeError::ProgramOutputDeserializationError(e.to_string()))?;
    program_outputs.push(execute_output.clone());
    env_builder.add_assumption(execute_receipt);

    if !matches!(omit, Omit::Probe) {
        let probe_receipt = execute_and_prove_probe(
            program,
            self_account_id,
            None,
            &pre_states,
            instruction_data,
        )?;
        let probe_output: ProgramOutput =
            borsh::from_slice(from_frame(&probe_receipt.journal.bytes).ok_or_else(|| {
                LeeError::ProgramOutputDeserializationError(
                    "malformed inner-receipt journal frame".to_owned(),
                )
            })?)
            .map_err(|e| LeeError::ProgramOutputDeserializationError(e.to_string()))?;
        program_outputs.push(probe_output);
        env_builder.add_assumption(probe_receipt);
    }

    let diff = execute_output
        .state_diffs
        .first()
        .expect("test guest always emits exactly one diff");
    let post_data = diff
        .post_data
        .as_ref()
        .expect("test guest's one diff is always a write");
    // Omitting `Probe` alone would leave `Update` next in the queue, where `verify_probe_receipt`
    // would pop and reject it as a malformed `Probe` envelope instead of finding the queue empty
    // — a different, misattributed panic. Testing the empty-queue path cleanly requires nothing
    // queued after `Execute` at all.
    if !matches!(omit, Omit::Update | Omit::Probe) {
        let update_receipt =
            execute_and_prove_incremental(program, self_account_id, &diff.pre_state, post_data)?;
        let update_output: ProgramOutput =
            borsh::from_slice(from_frame(&update_receipt.journal.bytes).ok_or_else(|| {
                LeeError::ProgramOutputDeserializationError(
                    "malformed inner-receipt journal frame".to_owned(),
                )
            })?)
            .map_err(|e| LeeError::ProgramOutputDeserializationError(e.to_string()))?;
        program_outputs.push(update_output);
        env_builder.add_assumption(update_receipt);
    }

    let circuit_input = PrivacyPreservingCircuitInput {
        program_outputs,
        account_identities: vec![InputAccountIdentity::Public],
        program_account_id: self_account_id,
        dummy_inputs: vec![],
        ciphertext_padding: None,
        initial_pre_states: vec![pre.account_id],
        program_image_claims: vec![ProgramImageClaim {
            account_id: self_account_id,
            image_id: program.id(),
        }],
    };

    let circuit_input_payload = borsh::to_vec(&circuit_input)?;
    env_builder.write_slice(&to_frame(&circuit_input_payload));
    let env = env_builder.build().unwrap();
    let prover = default_prover();
    let prove_info = prover
        .prove_with_opts(env, PRIVACY_PRESERVING_CIRCUIT_ELF, &ProverOpts::succinct())
        .map_err(|e| LeeError::CircuitProvingError(e.to_string()))?;

    let proof = Proof(borsh::to_vec(&prove_info.receipt.inner)?);
    let circuit_output: PrivacyPreservingCircuitOutput = borsh::from_slice(
        from_frame(&prove_info.receipt.journal.bytes).ok_or_else(|| {
            LeeError::CircuitOutputDeserializationError(
                "malformed circuit journal frame".to_owned(),
            )
        })?,
    )
    .map_err(|e| LeeError::CircuitOutputDeserializationError(e.to_string()))?;

    Ok((circuit_output, proof))
}

#[test]
fn proof_inner_roundtrip() {
    // `Proof::from_inner(b).into_inner()` must return exactly `b`. Catches
    // mutations of `into_inner` returning `vec![]`, `vec![0]`, or `vec![1]`,
    // and of `from_inner` discarding its argument.
    let bytes = vec![0xDE_u8, 0xAD, 0xBE, 0xEF];
    assert_eq!(Proof::from_inner(bytes.clone()).into_inner(), bytes);
    assert!(Proof::from_inner(vec![]).into_inner().is_empty());
    assert_eq!(Proof::from_inner(vec![0xFF]).into_inner(), vec![0xFF_u8]);
}

/// `PrivateBackend::resolve_write`'s counterpart to the public-side `incremental_update_cycles_*`
/// tests: confirms the in-circuit `Update` resolution runs through a real proof, not just
/// compiles. `stripped_token`'s `Initialize` is the only program here that writes `post_data`
/// (not just balance), so it's the only one that exercises this path.
///
/// `Initialize` claims `DeferReads::WriteOnly` (see `stripped_token`'s `Probe` handler), which
/// covers this write, so the account comes out `Deferred`, not `Bound` - `resolve_write` still
/// resolved it in-circuit (that's what this test is really checking), but classification decided
/// the *resolved* value isn't what gets exported; the raw delta is, for settlement to redo.
#[test]
fn prove_privacy_preserving_execution_circuit_resolves_an_incremental_write() {
    let program = crate::test_methods::stripped_token();
    let program_id: AccountId = program.id().into();
    let account_id = AccountId::new([9; 32]);
    let pre = AccountWithMetadata::new(
        Account {
            program_owner: program_id,
            ..Account::default()
        },
        true,
        account_id,
    );

    let instruction_data =
        Program::serialize_instruction(StrippedTokenInstruction::Initialize { balance: 42 })
            .unwrap();

    let (output, proof) = execute_and_prove(
        vec![pre],
        instruction_data,
        vec![InputAccountIdentity::Public],
        &program.into(),
    )
    .unwrap();

    assert!(proof.is_valid_for(&output));

    let [action] = output.public_actions.try_into().unwrap();
    let PublicAction::Deferred {
        account_id: returned_account_id,
        resolutions,
    } = action
    else {
        panic!("expected a Deferred action");
    };
    assert_eq!(returned_account_id, account_id);
    let [resolution] = resolutions.try_into().unwrap();
    assert_eq!(resolution.executing_account_id, program_id);
    let expected_post_data: Data = borsh::to_vec(&TokenDiff::Add(42))
        .unwrap()
        .try_into()
        .unwrap();
    assert_eq!(resolution.post_data, Some(expected_post_data));
}

/// The "once `Bound`, permanent" invariant: `acquire_and_forward` writes directly to
/// `account_id` - a write with no `Probe` claim at all, since it never implements `Incremental` -
/// forcing `Bound`. It then chains to `stripped_token`'s `Initialize` on that very same account,
/// whose `WriteOnly` claim *would* cover this second write and defer it, if the account weren't
/// already permanently `Bound`. Confirms it stays `Bound`, not reverted to `Deferred` by the
/// later covered touch - and that the exported value is the real one `resolve_write` computed
/// for that second touch (`stripped_token`'s), not a mechanical "first touch wins" artifact.
///
/// `acquire_and_forward`'s own write is `Some(vec![])` - `post_data.is_some()` so it still counts
/// as a write for classification, but empty-to-empty changes nothing, so it neither claims
/// ownership of the still-unowned account nor gives `stripped_token`'s later `Initialize`
/// anything but an empty `data` to decode (avoiding its "must decode as `TokenAccountData`"
/// panic on garbage bytes).
#[test]
fn once_bound_a_later_covered_touch_does_not_revert_to_deferred() {
    let delegator = crate::test_methods::acquire_and_forward();
    let callee = crate::test_methods::stripped_token();
    let callee_program_id = callee.id();
    let account_id = AccountId::new([7; 32]);
    let pre = AccountWithMetadata::new(Account::default(), true, account_id);

    let callee_instruction =
        Program::serialize_instruction(StrippedTokenInstruction::Initialize { balance: 42 })
            .unwrap();
    let instruction_data = Program::serialize_instruction((
        Some(Vec::<u8>::new()),
        callee_program_id,
        callee_instruction,
    ))
    .unwrap();

    let callee_account_id: AccountId = callee_program_id.into();
    let program_with_deps = ProgramWithDependencies::new(
        delegator.clone(),
        delegator.id().into(),
        [(callee_account_id, callee)].into(),
    );

    let (output, proof) = execute_and_prove(
        vec![pre],
        instruction_data,
        vec![InputAccountIdentity::Public],
        &program_with_deps,
    )
    .unwrap();

    assert!(proof.is_valid_for(&output));

    let [action] = output.public_actions.try_into().unwrap();
    let PublicAction::Bound { post, .. } = action else {
        panic!("expected the account to stay Bound despite the later covered touch");
    };
    let data: TokenAccountData = borsh::from_slice(post.data.as_ref())
        .expect("resolved post_data must decode as TokenAccountData");
    assert_eq!(data.balance, 42);
}

/// `Transfer` produces two diffs (sender debit, receiver credit) from one call, both covered by
/// its single `All` `Probe` claim - unlike `Initialize`'s one-diff case above, this confirms the
/// classification (and the one `Probe` receipt backing it) is shared correctly across multiple
/// diffs from the same call, not just a single one.
#[test]
fn prove_privacy_preserving_execution_circuit_transfer_defers_both_diffs() {
    let program = crate::test_methods::stripped_token();
    let program_id: AccountId = program.id().into();
    let sender_id = AccountId::new([10; 32]);
    let receiver_id = AccountId::new([11; 32]);

    let sender_data: Data = borsh::to_vec(&TokenAccountData { balance: 100 })
        .unwrap()
        .try_into()
        .unwrap();
    let sender = AccountWithMetadata::new(
        Account {
            program_owner: program_id,
            data: sender_data,
            ..Account::default()
        },
        true,
        sender_id,
    );
    let receiver = AccountWithMetadata::new(Account::default(), true, receiver_id);

    let instruction_data =
        Program::serialize_instruction(StrippedTokenInstruction::Transfer { amount: 30 }).unwrap();

    let (output, proof) = execute_and_prove(
        vec![sender, receiver],
        instruction_data,
        vec![InputAccountIdentity::Public, InputAccountIdentity::Public],
        &program.into(),
    )
    .unwrap();

    assert!(proof.is_valid_for(&output));
    assert_eq!(output.public_actions.len(), 2);
    for action in &output.public_actions {
        assert!(
            matches!(action, PublicAction::Deferred { .. }),
            "expected both diffs to be Deferred, got {action:?}"
        );
    }
}

#[test]
fn probe_answered_for_a_different_instruction_is_rejected() {
    let program = crate::test_methods::lying_probe_instruction();
    let account_id = AccountId::new([12; 32]);
    let pre = AccountWithMetadata::new(Account::default(), true, account_id);

    let instruction_data = Program::serialize_instruction(LyingProbeInstruction::B).unwrap();

    let result = execute_and_prove(
        vec![pre],
        instruction_data,
        vec![InputAccountIdentity::Public],
        &program.into(),
    );

    assert!(
        result.is_err(),
        "a Probe receipt answered for a different instruction must be rejected, got {result:?}"
    );
}

/// `verify_probe_receipt` checks a `Probe` receipt was actually produced by the program it
/// claims to answer for. `lying_probe_self_id` always reports `DEFAULT_PROGRAM_ID` instead.
#[test]
fn probe_self_id_mismatch_is_rejected() {
    let program = crate::test_methods::lying_probe_self_id();
    let account_id = AccountId::new([13; 32]);
    let pre = AccountWithMetadata::new(Account::default(), true, account_id);

    let result = execute_and_prove(
        vec![pre],
        Vec::new(),
        vec![InputAccountIdentity::Public],
        &program.into(),
    );

    assert!(
        result.is_err(),
        "a Probe receipt produced by the wrong program must be rejected, got {result:?}"
    );
}

/// `verify_probe_receipt` checks a `Probe` receipt names the same caller as the real `Execute`
/// call it answers for. `lying_probe_caller_id` always reports a spoofed caller.
#[test]
fn probe_caller_id_mismatch_is_rejected() {
    let program = crate::test_methods::lying_probe_caller_id();
    let account_id = AccountId::new([14; 32]);
    let pre = AccountWithMetadata::new(Account::default(), true, account_id);

    let result = execute_and_prove(
        vec![pre],
        Vec::new(),
        vec![InputAccountIdentity::Public],
        &program.into(),
    );

    assert!(
        result.is_err(),
        "a Probe receipt with a spoofed caller must be rejected, got {result:?}"
    );
}

/// `resolve_write`'s in-circuit `Update` check requires `caller_account_id == None` — `Update` is
/// never caller-gated. `lying_update_caller_id` always reports `Some(caller)` instead.
#[test]
fn update_caller_must_be_none() {
    let program = crate::test_methods::lying_update_caller_id();
    let account_id = AccountId::new([15; 32]);
    let pre = AccountWithMetadata::new(Account::default(), true, account_id);

    let result = execute_and_prove(
        vec![pre],
        Program::serialize_instruction(vec![1_u8, 2, 3]).unwrap(),
        vec![InputAccountIdentity::Public],
        &program.into(),
    );

    assert!(
        result.is_err(),
        "an Update resolution with a non-None caller must be rejected, got {result:?}"
    );
}

/// `resolve_write` checks an `Update` resolution was actually produced by the program it claims
/// to be. `lying_update_self_id` always reports `DEFAULT_PROGRAM_ID` instead.
#[test]
fn update_self_id_mismatch_is_rejected() {
    let program = crate::test_methods::lying_update_self_id();
    let account_id = AccountId::new([21; 32]);
    let pre = AccountWithMetadata::new(Account::default(), true, account_id);

    let result = execute_and_prove(
        vec![pre],
        Program::serialize_instruction(vec![1_u8, 2, 3]).unwrap(),
        vec![InputAccountIdentity::Public],
        &program.into(),
    );

    assert!(
        result.is_err(),
        "an Update resolution produced by the wrong program must be rejected, got {result:?}"
    );
}

/// `resolve_write` checks an `Update` resolution names the account it was given, not a
/// different one. `lying_update_wrong_account` always resolves against a hardcoded account.
#[test]
fn update_resolving_a_different_account_is_rejected() {
    let program = crate::test_methods::lying_update_wrong_account();
    let account_id = AccountId::new([16; 32]);
    let pre = AccountWithMetadata::new(Account::default(), true, account_id);

    let result = execute_and_prove(
        vec![pre],
        Program::serialize_instruction(vec![1_u8, 2, 3]).unwrap(),
        vec![InputAccountIdentity::Public],
        &program.into(),
    );

    assert!(
        result.is_err(),
        "an Update resolution for the wrong account must be rejected, got {result:?}"
    );
}

/// `resolve_write` checks an `Update` resolution was actually run against the real pre-state it
/// was given. `lying_update_wrong_pre_state` fabricates a different balance to resolve against.
#[test]
fn update_resolving_against_a_fabricated_pre_state_is_rejected() {
    let program = crate::test_methods::lying_update_wrong_pre_state();
    let account_id = AccountId::new([17; 32]);
    let pre = AccountWithMetadata::new(
        Account {
            balance: 100,
            ..Account::default()
        },
        true,
        account_id,
    );

    let result = execute_and_prove(
        vec![pre],
        Program::serialize_instruction(vec![1_u8, 2, 3]).unwrap(),
        vec![InputAccountIdentity::Public],
        &program.into(),
    );

    assert!(
        result.is_err(),
        "an Update resolution run against a fabricated pre-state must be rejected, got {result:?}"
    );
}

/// A program that implements `Incremental` but always declines (`Probe` returns `None`) forces
/// `Bound`, exactly like a program that never implemented `Incremental` at all — declining a
/// claim and never making one are indistinguishable to the caller.
#[test]
fn declining_probe_forces_bound() {
    let program = crate::test_methods::declining_probe();
    let account_id = AccountId::new([18; 32]);
    let pre = AccountWithMetadata::new(Account::default(), true, account_id);

    let (output, proof) = execute_and_prove(
        vec![pre],
        Program::serialize_instruction(vec![9_u8, 9, 9]).unwrap(),
        vec![InputAccountIdentity::Public],
        &program.into(),
    )
    .unwrap();

    assert!(proof.is_valid_for(&output));
    let [action] = output.public_actions.try_into().unwrap();
    assert!(
        matches!(action, PublicAction::Bound { .. }),
        "a declined Probe claim must force Bound, got {action:?}"
    );
}

/// `DeferReads::WriteOnly` covers only writes. `write_only_touches_a_read` writes its first
/// account and merely reads its second in the same call — the write is deferrable, but the
/// uncovered read still forces its own account `Bound`, independent of the covered write.
#[test]
fn write_only_claim_does_not_cover_a_read() {
    let program = crate::test_methods::write_only_touches_a_read();
    let written_id = AccountId::new([19; 32]);
    let read_id = AccountId::new([20; 32]);
    let written = AccountWithMetadata::new(Account::default(), true, written_id);
    let read = AccountWithMetadata::new(Account::default(), true, read_id);

    let (output, proof) = execute_and_prove(
        vec![written, read],
        Program::serialize_instruction(vec![4_u8, 5, 6]).unwrap(),
        vec![InputAccountIdentity::Public, InputAccountIdentity::Public],
        &program.into(),
    )
    .unwrap();

    assert!(proof.is_valid_for(&output));
    assert_eq!(output.public_actions.len(), 2);
    assert!(
        matches!(output.public_actions[0], PublicAction::Deferred { .. }),
        "the covered write must be Deferred, got {:?}",
        output.public_actions[0]
    );
    assert!(
        matches!(output.public_actions[1], PublicAction::Bound { .. }),
        "the uncovered read must force Bound, got {:?}",
        output.public_actions[1]
    );
}

/// The other half of `DeferReads::covers`'s asymmetry: `ReadOnly` covers reads, not writes.
/// `read_only_touches_a_write` writes its one account but claims `ReadOnly`, so the write is
/// uncovered and forced `Bound` — exactly as if the program had declined entirely.
#[test]
fn read_only_claim_does_not_cover_a_write() {
    let program = crate::test_methods::read_only_touches_a_write();
    let account_id = AccountId::new([22; 32]);
    let pre = AccountWithMetadata::new(Account::default(), true, account_id);

    let (output, proof) = execute_and_prove(
        vec![pre],
        Program::serialize_instruction(vec![7_u8, 8, 9]).unwrap(),
        vec![InputAccountIdentity::Public],
        &program.into(),
    )
    .unwrap();

    assert!(proof.is_valid_for(&output));
    let [action] = output.public_actions.try_into().unwrap();
    assert!(
        matches!(action, PublicAction::Bound { .. }),
        "a ReadOnly claim must not cover a write, got {action:?}"
    );
}

/// The §3 `stripped_token_robinhood` scenario, proven for real rather than asserted: robinhood
/// reads both accounts to pick a route but never implements `Incremental` itself (its `Probe`
/// answer is always `UnsupportedCallKind`), so its own reads are uncovered and force both
/// accounts `Bound` - even though the chained `Transfer` on `stripped_token` (which genuinely
/// supports `Incremental`) would otherwise defer its own write.
#[test]
fn stripped_token_robinhood_forces_both_accounts_bound() {
    let robinhood = crate::test_methods::stripped_token_robinhood();
    let stripped_token = crate::test_methods::stripped_token();
    let stripped_token_id: AccountId = stripped_token.id().into();

    let account1_id = AccountId::new([30; 32]);
    let account2_id = AccountId::new([31; 32]);
    let account1_data: Data = borsh::to_vec(&TokenAccountData { balance: 100 })
        .unwrap()
        .try_into()
        .unwrap();
    let account2_data: Data = borsh::to_vec(&TokenAccountData { balance: 40 })
        .unwrap()
        .try_into()
        .unwrap();
    let account1 = AccountWithMetadata::new(
        Account {
            program_owner: stripped_token_id,
            data: account1_data,
            ..Account::default()
        },
        true,
        account1_id,
    );
    let account2 = AccountWithMetadata::new(
        Account {
            program_owner: stripped_token_id,
            data: account2_data,
            ..Account::default()
        },
        true,
        account2_id,
    );

    let program_with_deps = ProgramWithDependencies::new(
        robinhood.clone(),
        robinhood.id().into(),
        [(stripped_token_id, stripped_token)].into(),
    );

    let (output, proof) = execute_and_prove(
        vec![account1, account2],
        Program::serialize_instruction(stripped_token_id).unwrap(),
        vec![InputAccountIdentity::Public, InputAccountIdentity::Public],
        &program_with_deps,
    )
    .unwrap();

    assert!(proof.is_valid_for(&output));
    let [action1, action2]: [_; 2] = output.public_actions.try_into().unwrap();

    let PublicAction::Bound { post: post1, .. } = action1 else {
        panic!("robinhood's own uncovered read of account1 must force it Bound, got {action1:?}");
    };
    let PublicAction::Bound { post: post2, .. } = action2 else {
        panic!("robinhood's own uncovered read of account2 must force it Bound, got {action2:?}");
    };

    // Both accounts are Bound, but `resolve_write` still resolved the chained `Transfer` for
    // real - confirms the composition actually ran, rather than both accounts merely defaulting
    // to Bound through some unrelated early exit.
    let balance1: TokenAccountData = borsh::from_slice(post1.data.as_ref()).unwrap();
    let balance2: TokenAccountData = borsh::from_slice(post2.data.as_ref()).unwrap();
    assert_eq!(balance1.balance, 99);
    assert_eq!(balance2.balance, 41);
}

/// A dishonest prover that simply never proves a `Probe` for a call that writes a public
/// account — distinct from `lying_probe_*`, which supply one but lie inside it. `PrivateBackend`
/// requires exactly one `Probe` per such call and panics outright if none is queued.
#[test]
fn missing_probe_receipt_is_rejected() {
    let program = crate::test_methods::stripped_token();
    let program_id: AccountId = program.id().into();
    let account_id = AccountId::new([23; 32]);
    let pre = AccountWithMetadata::new(Account::default(), true, account_id);
    let instruction_data =
        Program::serialize_instruction(StrippedTokenInstruction::Initialize { balance: 42 })
            .unwrap();

    let result = execute_and_prove_omitting_a_receipt(
        &program,
        program_id,
        &pre,
        &instruction_data,
        &Omit::Probe,
    );

    assert!(
        result.is_err(),
        "a call writing a public account with no Probe receipt at all must be rejected, got \
         {result:?}"
    );
}

/// A dishonest prover that simply never proves an `Update` for a write — distinct from
/// `lying_update_*`, which supply one but lie inside it. Every write requires exactly one
/// `Update` resolution regardless of its eventual `Bound`/`Deferred` classification, so
/// `PrivateBackend` panics outright if none is queued.
#[test]
fn missing_update_receipt_is_rejected() {
    let program = crate::test_methods::stripped_token();
    let program_id: AccountId = program.id().into();
    let account_id = AccountId::new([24; 32]);
    let pre = AccountWithMetadata::new(Account::default(), true, account_id);
    let instruction_data =
        Program::serialize_instruction(StrippedTokenInstruction::Initialize { balance: 42 })
            .unwrap();

    let result = execute_and_prove_omitting_a_receipt(
        &program,
        program_id,
        &pre,
        &instruction_data,
        &Omit::Update,
    );

    assert!(
        result.is_err(),
        "a write with no Update receipt at all must be rejected, got {result:?}"
    );
}

#[test]
fn prove_privacy_preserving_execution_circuit_public_and_private_pre_accounts() {
    let recipient_keys = test_private_account_keys_1();
    let program = crate::test_methods::simple_balance_transfer();
    let sender = AccountWithMetadata::new(
        Account {
            program_owner: program.id().into(),
            balance: 100,
            ..Account::default()
        },
        true,
        AccountId::new([0; 32]),
    );

    let recipient_account_id =
        AccountId::for_regular_private_account(&recipient_keys.npk(), &recipient_keys.vpk(), 0);
    let recipient = AccountWithMetadata::new(Account::default(), true, recipient_account_id);

    let balance_to_move: u128 = 37;

    let expected_sender_post = Account {
        program_owner: program.id().into(),
        balance: 100 - balance_to_move,
        nonce: Nonce::default(),
        data: Data::default(),
    };

    let expected_recipient_post = Account {
        balance: balance_to_move,
        nonce: Nonce::private_account_nonce_init(&recipient_account_id),
        ..Account::default()
    };

    let expected_sender_pre = sender.clone();

    let init_nonce = Nonce::private_account_nonce_init(&recipient_account_id);
    let esk = EphemeralSecretKey::new(&recipient_account_id, &[0; 32], &init_nonce);
    let shared_secret = SharedSecretKey::encapsulate_deterministic(&recipient_keys.vpk(), &esk).0;

    let (output, proof) = execute_and_prove(
        vec![sender, recipient],
        Program::serialize_instruction(balance_to_move).unwrap(),
        vec![
            InputAccountIdentity::Public,
            InputAccountIdentity::Private(PrivateWitness {
                vpk: recipient_keys.vpk(),
                random_seed: [0; 32],
                identifier: 0,
                kind: WitnessKind::Regular {
                    ask: Some(recipient_keys.ask),
                },
                nullifier: NullifierWitness::Init {
                    npk: recipient_keys.npk(),
                    commitment_root: DUMMY_COMMITMENT_HASH,
                },
            }),
        ],
        &crate::test_methods::simple_balance_transfer().into(),
    )
    .unwrap();

    assert!(proof.is_valid_for(&output));

    let [action] = output.public_actions.try_into().unwrap();
    let PublicAction::Bound {
        pre: sender_pre,
        post: sender_post,
    } = action
    else {
        panic!("expected a Bound action");
    };
    assert_eq!(sender_pre, expected_sender_pre);
    assert_eq!(sender_post, expected_sender_post);
    assert_eq!(output.private_actions.len(), 1);

    let (_identifier, recipient_post) = EncryptionScheme::decrypt(
        &output.private_actions[0].encrypted_post_state.ciphertext,
        &shared_secret,
        &output.private_actions[0].nullifier,
    )
    .unwrap();
    assert_eq!(recipient_post, expected_recipient_post);
}

#[test]
fn prove_privacy_preserving_execution_circuit_fully_private() {
    let program = crate::test_methods::simple_balance_transfer();
    let sender_keys = test_private_account_keys_1();
    let recipient_keys = test_private_account_keys_2();

    let sender_nonce = Nonce(0xdead_beef);
    let sender_pre = AccountWithMetadata::new(
        Account {
            balance: 100,
            nonce: sender_nonce,
            program_owner: program.id().into(),
            data: Data::default(),
        },
        true,
        AccountId::for_regular_private_account(&sender_keys.npk(), &sender_keys.vpk(), 0),
    );
    let sender_account_id =
        AccountId::for_regular_private_account(&sender_keys.npk(), &sender_keys.vpk(), 0);
    let commitment_sender = Commitment::new(&sender_account_id, &sender_pre.account);

    let recipient_account_id =
        AccountId::for_regular_private_account(&recipient_keys.npk(), &recipient_keys.vpk(), 0);
    let recipient = AccountWithMetadata::new(Account::default(), true, recipient_account_id);
    let balance_to_move: u128 = 37;

    let mut commitment_set = CommitmentSet::with_capacity(2);
    commitment_set.extend(std::slice::from_ref(&commitment_sender));
    let expected_new_nullifiers = vec![
        (
            Nullifier::for_account_update(&commitment_sender, &sender_keys.nsk()),
            commitment_set.digest(),
        ),
        (
            Nullifier::for_account_initialization(&recipient_account_id),
            DUMMY_COMMITMENT_HASH,
        ),
    ];

    let program = crate::test_methods::simple_balance_transfer();

    let expected_private_account_1 = Account {
        program_owner: program.id().into(),
        balance: 100 - balance_to_move,
        nonce: sender_nonce.private_account_nonce_increment(&sender_keys.nsk()),
        ..Default::default()
    };
    let expected_private_account_2 = Account {
        balance: balance_to_move,
        nonce: Nonce::private_account_nonce_init(&recipient_account_id),
        ..Default::default()
    };
    let expected_new_commitments = vec![
        Commitment::new(&sender_account_id, &expected_private_account_1),
        Commitment::new(&recipient_account_id, &expected_private_account_2),
    ];

    let esk_1 = EphemeralSecretKey::new(
        &sender_account_id,
        &[0; 32],
        &sender_nonce.private_account_nonce_increment(&sender_keys.nsk()),
    );
    let shared_secret_1 = SharedSecretKey::encapsulate_deterministic(&sender_keys.vpk(), &esk_1).0;

    let init_nonce_2 = Nonce::private_account_nonce_init(&recipient_account_id);
    let esk_2 = EphemeralSecretKey::new(&recipient_account_id, &[0; 32], &init_nonce_2);
    let shared_secret_2 =
        SharedSecretKey::encapsulate_deterministic(&recipient_keys.vpk(), &esk_2).0;

    let (output, proof) = execute_and_prove(
        vec![sender_pre, recipient],
        Program::serialize_instruction(balance_to_move).unwrap(),
        vec![
            InputAccountIdentity::Private(PrivateWitness {
                vpk: sender_keys.vpk(),
                random_seed: [0; 32],
                identifier: 0,
                kind: WitnessKind::Regular {
                    ask: Some(sender_keys.ask),
                },
                nullifier: NullifierWitness::Update {
                    view_tag: 0,
                    nsk: sender_keys.nsk(),
                    membership_proof: commitment_set
                        .get_proof_for(&commitment_sender)
                        .expect("sender's commitment must be in the set"),
                },
            }),
            InputAccountIdentity::Private(PrivateWitness {
                vpk: recipient_keys.vpk(),
                random_seed: [0; 32],
                identifier: 0,
                kind: WitnessKind::Regular {
                    ask: Some(recipient_keys.ask),
                },
                nullifier: NullifierWitness::Init {
                    npk: recipient_keys.npk(),
                    commitment_root: DUMMY_COMMITMENT_HASH,
                },
            }),
        ],
        &program.into(),
    )
    .unwrap();

    assert!(proof.is_valid_for(&output));
    assert!(output.public_actions.is_empty());
    let sender_nullifier = expected_new_nullifiers[0].0;
    let recipient_nullifier = expected_new_nullifiers[1].0;

    let mut sorted_commitments = expected_new_commitments;
    sorted_commitments.sort_unstable_by_key(Commitment::to_byte_array);
    assert_eq!(output.commitments(), sorted_commitments);

    let mut sorted_nullifiers = expected_new_nullifiers;
    sorted_nullifiers.sort_unstable_by_key(|(nullifier, _)| nullifier.to_byte_array());
    assert_eq!(output.nullifiers(), sorted_nullifiers);

    assert_eq!(output.private_actions.len(), 2);

    let sender_slot = output
        .private_actions
        .iter()
        .position(|action| action.nullifier == sender_nullifier)
        .unwrap();
    let (_identifier, sender_post) = EncryptionScheme::decrypt(
        &output.private_actions[sender_slot]
            .encrypted_post_state
            .ciphertext,
        &shared_secret_1,
        &output.private_actions[sender_slot].nullifier,
    )
    .unwrap();
    assert_eq!(sender_post, expected_private_account_1);

    let recipient_slot = output
        .private_actions
        .iter()
        .position(|action| action.nullifier == recipient_nullifier)
        .unwrap();
    let (_identifier, recipient_post) = EncryptionScheme::decrypt(
        &output.private_actions[recipient_slot]
            .encrypted_post_state
            .ciphertext,
        &shared_secret_2,
        &output.private_actions[recipient_slot].nullifier,
    )
    .unwrap();
    assert_eq!(recipient_post, expected_private_account_2);
}

#[test]
fn init_note_view_tag_is_derived_from_account_keys() {
    let program = crate::test_methods::noop();
    let keys = test_private_account_keys_1();
    let identifier: u128 = 0;
    let account_id = AccountId::for_regular_private_account(&keys.npk(), &keys.vpk(), identifier);
    let account = AccountWithMetadata::new(Account::default(), true, account_id);

    let (output, proof) = execute_and_prove(
        vec![account],
        Program::serialize_instruction(()).unwrap(),
        vec![InputAccountIdentity::Private(PrivateWitness {
            vpk: keys.vpk(),
            random_seed: [0; 32],
            identifier,
            kind: WitnessKind::Regular {
                ask: Some(keys.ask),
            },
            nullifier: NullifierWitness::Init {
                npk: keys.npk(),
                commitment_root: DUMMY_COMMITMENT_HASH,
            },
        })],
        &program.into(),
    )
    .unwrap();

    assert!(proof.is_valid_for(&output));
    assert_eq!(output.private_actions.len(), 1);
    assert_eq!(
        output.private_actions[0].encrypted_post_state.view_tag,
        EncryptedAccountData::compute_view_tag(&keys.npk(), &keys.vpk()),
    );
}

#[test]
fn update_note_view_tag_is_the_supplied_value() {
    let program = crate::test_methods::noop();
    let keys = test_private_account_keys_1();
    let identifier: u128 = 99;
    let account_id = AccountId::for_regular_private_account(&keys.npk(), &keys.vpk(), identifier);
    let account = Account {
        program_owner: program.id().into(),
        balance: 1,
        ..Account::default()
    };
    let commitment = Commitment::new(&account_id, &account);
    let mut commitment_set = CommitmentSet::with_capacity(1);
    commitment_set.extend(std::slice::from_ref(&commitment));
    let sender = AccountWithMetadata::new(account, true, account_id);

    // A tag deliberately different from the address-derived one, so a passthrough is
    // distinguishable from re-derivation.
    let fed_tag = EncryptedAccountData::compute_view_tag(&keys.npk(), &keys.vpk()).wrapping_add(1);

    let (output, proof) = execute_and_prove(
        vec![sender],
        Program::serialize_instruction(()).unwrap(),
        vec![InputAccountIdentity::Private(PrivateWitness {
            vpk: keys.vpk(),
            random_seed: [0; 32],
            identifier,
            kind: WitnessKind::Regular {
                ask: Some(keys.ask),
            },
            nullifier: NullifierWitness::Update {
                view_tag: fed_tag,
                nsk: keys.nsk(),
                membership_proof: commitment_set.get_proof_for(&commitment).unwrap(),
            },
        })],
        &program.into(),
    )
    .unwrap();

    assert!(proof.is_valid_for(&output));
    assert_eq!(output.private_actions.len(), 1);
    assert_eq!(
        output.private_actions[0].encrypted_post_state.view_tag,
        fed_tag
    );
}

#[test]
fn note_ciphertext_is_padded_to_the_requested_length() {
    const PAD: u32 = 512;

    let program = crate::test_methods::noop();
    let keys = test_private_account_keys_1();
    let identifier: u128 = 7;
    let account_id = AccountId::for_regular_private_account(&keys.npk(), &keys.vpk(), identifier);
    let account = Account {
        program_owner: program.id().into(),
        data: Data::try_from(vec![9_u8; 200]).unwrap(),
        ..Account::default()
    };
    let commitment = Commitment::new(&account_id, &account);
    let mut commitment_set = CommitmentSet::with_capacity(1);
    commitment_set.extend(std::slice::from_ref(&commitment));
    let sender = AccountWithMetadata::new(account.clone(), true, account_id);

    let (padded, proof) = execute_and_prove_with_padded_inputs(
        vec![sender],
        Program::serialize_instruction(()).unwrap(),
        vec![InputAccountIdentity::Private(PrivateWitness {
            vpk: keys.vpk(),
            random_seed: [0; 32],
            identifier,
            kind: WitnessKind::Regular {
                ask: Some(keys.ask),
            },
            nullifier: NullifierWitness::Update {
                view_tag: EncryptedAccountData::compute_view_tag(&keys.npk(), &keys.vpk()),
                nsk: keys.nsk(),
                membership_proof: commitment_set.get_proof_for(&commitment).unwrap(),
            },
        })],
        vec![],
        Some(PAD),
        &program.into(),
    )
    .unwrap();

    assert!(proof.is_valid_for(&padded));
    assert_eq!(padded.private_actions.len(), 1);
    let ciphertext = &padded.private_actions[0].encrypted_post_state.ciphertext;
    assert_eq!(
        ciphertext.as_bytes().len(),
        usize::try_from(PAD).expect("pad fits in usize")
    );

    let shared_secret = SharedSecretKey::decapsulate(
        &padded.private_actions[0].encrypted_post_state.epk,
        &keys.d,
        &keys.z,
    )
    .unwrap();
    let (kind, post) = EncryptionScheme::decrypt(
        ciphertext,
        &shared_secret,
        &padded.private_actions[0].nullifier,
    )
    .unwrap();
    assert_eq!(kind, PrivateAccountKind::Regular(identifier));
    assert_eq!(
        post,
        Account {
            nonce: post.nonce,
            ..account
        }
    );
}

#[test]
fn circuit_fails_when_chained_validity_windows_have_empty_intersection() {
    let account_keys = test_private_account_keys_1();
    let pre = AccountWithMetadata::new(
        Account::default(),
        true,
        AccountId::for_regular_private_account(&account_keys.npk(), &account_keys.vpk(), 0),
    );

    let validity_window_chain_caller = crate::test_methods::validity_window_chain_caller();
    let validity_window = crate::test_methods::validity_window();

    let instruction = Program::serialize_instruction((
        Some(1_u64),
        Some(4_u64),
        validity_window.id(),
        Some(4_u64),
        Some(7_u64),
    ))
    .unwrap();

    let program_with_deps = ProgramWithDependencies::new(
        validity_window_chain_caller.clone(),
        validity_window_chain_caller.id().into(),
        [(validity_window.id().into(), validity_window)].into(),
    );

    let result = execute_and_prove(
        vec![pre],
        instruction,
        vec![InputAccountIdentity::Private(PrivateWitness {
            vpk: account_keys.vpk(),
            random_seed: [0; 32],
            identifier: 0,
            kind: WitnessKind::Regular {
                ask: Some(account_keys.ask),
            },
            nullifier: NullifierWitness::Init {
                npk: account_keys.npk(),
                commitment_root: DUMMY_COMMITMENT_HASH,
            },
        })],
        &program_with_deps,
    );

    assert!(matches!(result, Err(LeeError::CircuitProvingError(_))));
}

/// A private PDA bound with a non-default identifier produces a ciphertext that decrypts
/// to `PrivateAccountKind::Pda` carrying the correct `(program_id, seed, identifier)`.
#[test]
fn private_pda_with_custom_identifier_encrypts_correct_kind() {
    let program = crate::test_methods::noop();
    let keys = test_private_account_keys_1();
    let npk = keys.npk();
    let seed = PdaSeed::new([42; 32]);
    let identifier: u128 = 99;
    let account_id = AccountId::for_private_pda(
        &AccountId::from(program.id()),
        &seed,
        &npk,
        &keys.vpk(),
        identifier,
    );
    let init_nonce = Nonce::private_account_nonce_init(&account_id);
    let esk = EphemeralSecretKey::new(&account_id, &[0; 32], &init_nonce);
    let shared_secret = SharedSecretKey::encapsulate_deterministic(&keys.vpk(), &esk).0;

    let pre_state = AccountWithMetadata::new(Account::default(), false, account_id);

    let (output, _proof) = execute_and_prove(
        vec![pre_state],
        Program::serialize_instruction(()).unwrap(),
        vec![InputAccountIdentity::Private(PrivateWitness {
            vpk: keys.vpk(),
            random_seed: [0; 32],
            identifier,
            kind: WitnessKind::Pda {
                binding: Some((program.id().into(), seed)),
            },
            nullifier: NullifierWitness::Init {
                npk,
                commitment_root: DUMMY_COMMITMENT_HASH,
            },
        })],
        &program.clone().into(),
    )
    .unwrap();

    assert_eq!(
        decrypt_kind(&output, &shared_secret, 0),
        PrivateAccountKind::Pda {
            account_id: program.id().into(),
            seed,
            identifier
        },
    );
}

/// PDA init: initializes a new PDA under `simple_balance_transfer`'s ownership.
/// The `simple_transfer_proxy` program chains to `simple_balance_transfer` with `pda_seeds`
/// to establish authorization and the private PDA binding.
#[test]
fn private_pda_init() {
    let program = crate::test_methods::simple_transfer_proxy();
    let simple_transfer = crate::test_methods::simple_balance_transfer();
    let keys = test_private_account_keys_1();
    let npk = keys.npk();
    let seed = PdaSeed::new([42; 32]);
    // PDA (new, private PDA)
    let pda_id =
        AccountId::for_private_pda(&AccountId::from(program.id()), &seed, &npk, &keys.vpk(), 0);
    let pda_pre = AccountWithMetadata::new(Account::default(), false, pda_id);

    let auth_id: AccountId = simple_transfer.id().into();
    let program_with_deps = ProgramWithDependencies::new(
        program.clone(),
        program.id().into(),
        [(auth_id, simple_transfer)].into(),
    );

    // is_withdraw=false triggers init path (1 pre-state)
    let instruction = Program::serialize_instruction((seed, auth_id, 0_u128, false)).unwrap();

    let result = execute_and_prove(
        vec![pda_pre],
        instruction,
        vec![init_pda_witness(&keys, 0, None)],
        &program_with_deps,
    );

    let (output, _proof) = result.expect("PDA init should succeed");
    assert_eq!(output.private_actions.len(), 1);
}

/// PDA withdraw: chains to `simple_balance_transfer` to move balance from PDA to recipient.
/// Uses a default PDA (amount=0) because testing with a pre-funded PDA requires a
/// two-tx sequence with membership proofs.
#[test]
fn private_pda_withdraw() {
    let program = crate::test_methods::simple_transfer_proxy();
    let simple_transfer = crate::test_methods::simple_balance_transfer();
    let keys = test_private_account_keys_1();
    let npk = keys.npk();
    let seed = PdaSeed::new([42; 32]);
    // PDA (new, private PDA)
    let pda_id =
        AccountId::for_private_pda(&AccountId::from(program.id()), &seed, &npk, &keys.vpk(), 0);
    let pda_pre = AccountWithMetadata::new(Account::default(), false, pda_id);

    // Recipient (public)
    let recipient_id = AccountId::new([88; 32]);
    let recipient_pre = AccountWithMetadata::new(
        Account {
            program_owner: simple_transfer.id().into(),
            balance: 10000,
            ..Account::default()
        },
        true,
        recipient_id,
    );

    let auth_id: AccountId = simple_transfer.id().into();
    let program_with_deps = ProgramWithDependencies::new(
        program.clone(),
        program.id().into(),
        [(auth_id, simple_transfer)].into(),
    );

    // is_withdraw=true, amount=0 (PDA has no balance yet)
    let instruction = Program::serialize_instruction((seed, auth_id, 0_u128, true)).unwrap();

    let result = execute_and_prove(
        vec![pda_pre, recipient_pre],
        instruction,
        vec![
            init_pda_witness(&keys, 0, None),
            InputAccountIdentity::Public,
        ],
        &program_with_deps,
    );

    let (output, _proof) = result.expect("PDA withdraw should succeed");
    assert_eq!(output.private_actions.len(), 1);
}

/// Shared regular private account: receives funds via `authenticated_transfer` directly,
/// no custom program needed. This demonstrates the non-PDA shared account flow where
/// keys are derived from GMS via `derive_keys_for_shared_account`. The shared account
/// uses the standard foreign private account path and works with auth-transfer's
/// transfer path like any other private account.
#[test]
fn shared_account_receives_via_simple_transfer() {
    let program = crate::test_methods::simple_balance_transfer();
    let shared_keys = test_private_account_keys_1();
    let shared_npk = shared_keys.npk();
    let shared_identifier: u128 = 42;

    // Sender: public account with balance, owned by auth-transfer
    let sender_id = AccountId::new([99; 32]);
    let sender = AccountWithMetadata::new(
        Account {
            program_owner: program.id().into(),
            balance: 1000,
            ..Account::default()
        },
        true,
        sender_id,
    );

    // Recipient: shared private account (new, foreign)
    let shared_account_id = AccountId::from((&shared_npk, &shared_keys.vpk(), shared_identifier));
    let recipient = AccountWithMetadata::new(Account::default(), true, shared_account_id);

    let balance_to_move: u128 = 100;
    let instruction = Program::serialize_instruction(balance_to_move).unwrap();

    let result = execute_and_prove(
        vec![sender, recipient],
        instruction,
        vec![
            InputAccountIdentity::Public,
            InputAccountIdentity::Private(PrivateWitness {
                vpk: shared_keys.vpk(),
                random_seed: [0; 32],
                identifier: shared_identifier,
                kind: WitnessKind::Regular {
                    ask: Some(shared_keys.ask),
                },
                nullifier: NullifierWitness::Init {
                    npk: shared_npk,
                    commitment_root: DUMMY_COMMITMENT_HASH,
                },
            }),
        ],
        &program.into(),
    );

    let (output, _proof) = result.expect("shared account receive should succeed");
    // Sender is public (no commitment), recipient is private (1 commitment)
    assert_eq!(output.private_actions.len(), 1);
}

/// A regular init with an npk derived from the held `nsk` and a non-default identifier
/// produces a ciphertext that decrypts to `PrivateAccountKind::Regular` carrying the correct
/// identifier.
#[test]
fn private_authorized_init_encrypts_regular_kind_with_identifier() {
    let program = crate::test_methods::noop();
    let keys = test_private_account_keys_1();
    let identifier: u128 = 99;
    let account_id = AccountId::for_regular_private_account(&keys.npk(), &keys.vpk(), identifier);
    let esk = EphemeralSecretKey::new(
        &account_id,
        &[0; 32],
        &Nonce::private_account_nonce_init(&account_id),
    );
    let ssk = SharedSecretKey::encapsulate_deterministic(&keys.vpk(), &esk).0;
    let pre = AccountWithMetadata::new(Account::default(), true, account_id);

    let (output, _) = execute_and_prove(
        vec![pre],
        Program::serialize_instruction(()).unwrap(),
        vec![InputAccountIdentity::Private(PrivateWitness {
            vpk: keys.vpk(),
            random_seed: [0; 32],
            identifier,
            kind: WitnessKind::Regular {
                ask: Some(keys.ask),
            },
            nullifier: NullifierWitness::Init {
                npk: NullifierPublicKey::from(&keys.nsk()),
                commitment_root: DUMMY_COMMITMENT_HASH,
            },
        })],
        &program.into(),
    )
    .unwrap();

    assert_eq!(
        decrypt_kind(&output, &ssk, 0),
        PrivateAccountKind::Regular(identifier)
    );
}

/// A regular init with a directly-supplied npk (the caller does not own the account) and a
/// non-default identifier produces a ciphertext that decrypts to `PrivateAccountKind::Regular`
/// carrying the correct identifier.
#[test]
fn private_foreign_init_encrypts_regular_kind_with_identifier() {
    let program = crate::test_methods::noop();
    let keys = test_private_account_keys_1();
    let identifier: u128 = 99;
    let recipient_id = AccountId::for_regular_private_account(&keys.npk(), &keys.vpk(), identifier);
    let esk = EphemeralSecretKey::new(
        &recipient_id,
        &[0; 32],
        &Nonce::private_account_nonce_init(&recipient_id),
    );
    let ssk = SharedSecretKey::encapsulate_deterministic(&keys.vpk(), &esk).0;
    let recipient = AccountWithMetadata::new(Account::default(), true, recipient_id);

    let (output, _) = execute_and_prove(
        vec![recipient],
        Program::serialize_instruction(()).unwrap(),
        vec![InputAccountIdentity::Private(PrivateWitness {
            vpk: keys.vpk(),
            random_seed: [0; 32],
            identifier,
            kind: WitnessKind::Regular {
                ask: Some(keys.ask),
            },
            nullifier: NullifierWitness::Init {
                npk: keys.npk(),
                commitment_root: DUMMY_COMMITMENT_HASH,
            },
        })],
        &program.into(),
    )
    .unwrap();

    assert_eq!(
        decrypt_kind(&output, &ssk, 0),
        PrivateAccountKind::Regular(identifier)
    );
}

/// A regular update with a non-default identifier produces a ciphertext that decrypts
/// to `PrivateAccountKind::Regular` carrying the correct identifier.
#[test]
fn private_authorized_update_encrypts_regular_kind_with_identifier() {
    let program = crate::test_methods::noop();
    let keys = test_private_account_keys_1();
    let identifier: u128 = 99;
    let account_id = AccountId::for_regular_private_account(&keys.npk(), &keys.vpk(), identifier);
    let esk = EphemeralSecretKey::new(
        &account_id,
        &[0; 32],
        &Nonce::default().private_account_nonce_increment(&keys.nsk()),
    );
    let ssk = SharedSecretKey::encapsulate_deterministic(&keys.vpk(), &esk).0;
    let account = Account {
        program_owner: program.id().into(),
        balance: 1,
        ..Account::default()
    };
    let commitment = Commitment::new(&account_id, &account);
    let mut commitment_set = CommitmentSet::with_capacity(1);
    commitment_set.extend(std::slice::from_ref(&commitment));

    let sender = AccountWithMetadata::new(account, true, account_id);

    let (output, _) = execute_and_prove(
        vec![sender],
        Program::serialize_instruction(()).unwrap(),
        vec![InputAccountIdentity::Private(PrivateWitness {
            vpk: keys.vpk(),
            random_seed: [0; 32],
            identifier,
            kind: WitnessKind::Regular {
                ask: Some(keys.ask),
            },
            nullifier: NullifierWitness::Update {
                view_tag: 0,
                nsk: keys.nsk(),
                membership_proof: commitment_set.get_proof_for(&commitment).unwrap(),
            },
        })],
        &program.into(),
    )
    .unwrap();

    assert_eq!(
        decrypt_kind(&output, &ssk, 0),
        PrivateAccountKind::Regular(identifier)
    );
}

/// Builds an on-chain regular private account owned by `program`, returning its id, pre-state
/// and a membership proof for its commitment.
fn seeded_regular_account(
    keys: &crate::state::tests::TestPrivateKeys,
    program: &Program,
    identifier: u128,
) -> (AccountId, AccountWithMetadata, lee_core::MembershipProof) {
    let account_id = AccountId::for_regular_private_account(&keys.npk(), &keys.vpk(), identifier);
    let account = Account {
        program_owner: program.id().into(),
        balance: 1,
        ..Account::default()
    };
    let commitment = Commitment::new(&account_id, &account);
    let mut commitment_set = CommitmentSet::with_capacity(1);
    commitment_set.extend(std::slice::from_ref(&commitment));
    let proof = commitment_set.get_proof_for(&commitment).unwrap();
    (
        account_id,
        AccountWithMetadata::new(account, false, account_id),
        proof,
    )
}

/// Spending without consenting. The witness carries no `ask`, so the pre-state is unauthorized,
/// and the nullifier is still produced from the `nsk`.
#[test]
fn private_regular_update_without_ask_is_spendable() {
    let program = crate::test_methods::noop();
    let keys = test_private_account_keys_1();
    let (_, pre, membership_proof) = seeded_regular_account(&keys, &program, 0);
    assert!(!pre.is_authorized);

    execute_and_prove(
        vec![pre],
        Program::serialize_instruction(()).unwrap(),
        vec![InputAccountIdentity::Private(PrivateWitness {
            vpk: keys.vpk(),
            random_seed: [0; 32],
            identifier: 0,
            kind: WitnessKind::Regular { ask: None },
            nullifier: NullifierWitness::Update {
                view_tag: 0,
                nsk: keys.nsk(),
                membership_proof,
            },
        })],
        &program.into(),
    )
    .unwrap();
}

/// Claiming authorization without supplying an `ask` is rejected.
#[test]
fn private_regular_witness_without_ask_cannot_assert_authorization() {
    let program = crate::test_methods::noop();
    let keys = test_private_account_keys_1();
    let (account_id, pre, membership_proof) = seeded_regular_account(&keys, &program, 0);
    let pre = AccountWithMetadata::new(pre.account, true, account_id);

    let result = execute_and_prove(
        vec![pre],
        Program::serialize_instruction(()).unwrap(),
        vec![InputAccountIdentity::Private(PrivateWitness {
            vpk: keys.vpk(),
            random_seed: [0; 32],
            identifier: 0,
            kind: WitnessKind::Regular { ask: None },
            nullifier: NullifierWitness::Update {
                view_tag: 0,
                nsk: keys.nsk(),
                membership_proof,
            },
        })],
        &program.into(),
    );

    assert!(matches!(result, Err(LeeError::CircuitProvingError(_))));
}

/// An `ask` that does not derive this account's `nsk` is not a credential for it.
#[test]
fn regular_update_with_wrong_ask_nsk_is_rejected() {
    let program = crate::test_methods::noop();
    let keys = test_private_account_keys_1();
    let foreign = test_private_account_keys_2();
    let (account_id, pre, membership_proof) = seeded_regular_account(&keys, &program, 0);
    let pre = AccountWithMetadata::new(pre.account, true, account_id);

    let result = execute_and_prove(
        vec![pre],
        Program::serialize_instruction(()).unwrap(),
        vec![InputAccountIdentity::Private(PrivateWitness {
            vpk: keys.vpk(),
            random_seed: [0; 32],
            identifier: 0,
            kind: WitnessKind::Regular {
                ask: Some(foreign.ask),
            },
            nullifier: NullifierWitness::Update {
                view_tag: 0,
                nsk: keys.nsk(),
                membership_proof,
            },
        })],
        &program.into(),
    );

    assert!(matches!(result, Err(LeeError::CircuitProvingError(_))));
}

/// An `ask` that does not derive this account's `npk` is not a credential for it.
#[test]
fn regular_init_with_non_chaining_ask_npk_is_rejected() {
    let program = crate::test_methods::noop();
    let keys = test_private_account_keys_1();
    let foreign = test_private_account_keys_2();
    let account_id = AccountId::for_regular_private_account(&keys.npk(), &keys.vpk(), 0);
    let pre = AccountWithMetadata::new(Account::default(), true, account_id);

    let result = execute_and_prove(
        vec![pre],
        Program::serialize_instruction(()).unwrap(),
        vec![InputAccountIdentity::Private(PrivateWitness {
            vpk: keys.vpk(),
            random_seed: [0; 32],
            identifier: 0,
            kind: WitnessKind::Regular {
                ask: Some(foreign.ask),
            },
            nullifier: NullifierWitness::Init {
                npk: keys.npk(),
                commitment_root: DUMMY_COMMITMENT_HASH,
            },
        })],
        &program.into(),
    );

    assert!(matches!(result, Err(LeeError::CircuitProvingError(_))));
}

/// A program that asserts authorization over its pre-states rejects a regular private account
/// whose witness supplied no `ask`.
#[test]
fn auth_asserting_program_rejects_unauthorized_regular_private_account() {
    let program = crate::test_methods::auth_asserting_noop();
    let keys = test_private_account_keys_1();
    let (_, pre, membership_proof) = seeded_regular_account(&keys, &program, 0);

    let result = execute_and_prove(
        vec![pre],
        Program::serialize_instruction(()).unwrap(),
        vec![InputAccountIdentity::Private(PrivateWitness {
            vpk: keys.vpk(),
            random_seed: [0; 32],
            identifier: 0,
            kind: WitnessKind::Regular { ask: None },
            nullifier: NullifierWitness::Update {
                view_tag: 0,
                nsk: keys.nsk(),
                membership_proof,
            },
        })],
        &program.into(),
    );

    assert!(matches!(result, Err(LeeError::ProgramProveFailed(_))));
}

/// Root-call private-PDA update attempt: `pda_spend_proxy` spends a PDA it owns via
/// `simple_balance_transfer`.
fn pda_update_attempt(
    declare_authorized: bool,
    derivation_identifier: u128,
    witness_identifier: u128,
) -> Result<lee_core::PrivacyPreservingCircuitOutput, LeeError> {
    let program = crate::test_methods::pda_spend_proxy();
    let simple_transfer = crate::test_methods::simple_balance_transfer();
    let keys = test_private_account_keys_1();
    let seed = PdaSeed::new([42; 32]);
    let simple_transfer_id: AccountId = simple_transfer.id().into();
    let pda_id = AccountId::for_private_pda(
        &AccountId::from(program.id()),
        &seed,
        &keys.npk(),
        &keys.vpk(),
        derivation_identifier,
    );
    let pda_account = Account {
        program_owner: simple_transfer_id,
        balance: 1,
        ..Account::default()
    };
    let pda_commitment = Commitment::new(&pda_id, &pda_account);
    let mut commitment_set = CommitmentSet::with_capacity(1);
    commitment_set.extend(std::slice::from_ref(&pda_commitment));

    let pda_pre = AccountWithMetadata::new(pda_account, declare_authorized, pda_id);
    let recipient_pre = AccountWithMetadata::new(Account::default(), true, AccountId::new([0; 32]));

    let program_with_deps = ProgramWithDependencies::new(
        program.clone(),
        program.id().into(),
        [(simple_transfer_id, simple_transfer)].into(),
    );

    execute_and_prove(
        vec![pda_pre, recipient_pre],
        Program::serialize_instruction((seed, 1_u128, simple_transfer_id)).unwrap(),
        vec![
            InputAccountIdentity::Private(PrivateWitness {
                vpk: keys.vpk(),
                random_seed: [0; 32],
                identifier: witness_identifier,
                kind: WitnessKind::Pda { binding: None },
                nullifier: NullifierWitness::Update {
                    view_tag: 0,
                    nsk: keys.nsk(),
                    membership_proof: commitment_set.get_proof_for(&pda_commitment).unwrap(),
                },
            }),
            InputAccountIdentity::Public,
        ],
        &program_with_deps,
    )
    .map(|(output, _proof)| output)
}

/// A private-PDA update with a non-default identifier produces a ciphertext that decrypts
/// to `PrivateAccountKind::Pda` carrying the correct `(program_id, seed, identifier)`.
#[test]
fn private_pda_update_encrypts_pda_kind_with_identifier() {
    let program_id: AccountId = crate::test_methods::pda_spend_proxy().id().into();
    let keys = test_private_account_keys_1();
    let seed = PdaSeed::new([42; 32]);
    let identifier: u128 = 99;

    let output = pda_update_attempt(false, identifier, identifier)
        .expect("a well-formed private PDA update must prove");

    let pda_id =
        AccountId::for_private_pda(&program_id, &seed, &keys.npk(), &keys.vpk(), identifier);
    let esk = EphemeralSecretKey::new(
        &pda_id,
        &[0; 32],
        &Nonce::default().private_account_nonce_increment(&keys.nsk()),
    );
    let ssk = SharedSecretKey::encapsulate_deterministic(&keys.vpk(), &esk).0;
    assert_eq!(
        decrypt_kind(&output, &ssk, 0),
        PrivateAccountKind::Pda {
            account_id: program_id,
            seed,
            identifier
        },
    );
}

#[test]
fn private_pda_update_at_root_call_may_not_declare_authorization() {
    let result = pda_update_attempt(true, 99, 99);

    assert!(matches!(result, Err(LeeError::CircuitProvingError(_))));
}

#[test]
fn private_pda_init_identifier_mismatch_fails() {
    let program = crate::test_methods::noop();
    let keys = test_private_account_keys_1();
    let npk = keys.npk();
    let seed = PdaSeed::new([42; 32]);
    let account_id =
        AccountId::for_private_pda(&AccountId::from(program.id()), &seed, &npk, &keys.vpk(), 5);
    let pre_state = AccountWithMetadata::new(Account::default(), false, account_id);

    let result = execute_and_prove(
        vec![pre_state],
        Program::serialize_instruction(()).unwrap(),
        vec![init_pda_witness(
            &keys,
            99,
            Some((program.id().into(), seed)),
        )],
        &program.into(),
    );

    assert!(matches!(result, Err(LeeError::CircuitProvingError(_))));
}

#[test]
fn private_pda_init_at_root_call_may_not_declare_authorization() {
    let program = crate::test_methods::noop();
    let keys = test_private_account_keys_1();
    let npk = keys.npk();
    let seed = PdaSeed::new([42; 32]);
    let identifier: u128 = 5;
    let account_id = AccountId::for_private_pda(
        &AccountId::from(program.id()),
        &seed,
        &npk,
        &keys.vpk(),
        identifier,
    );
    let pre_state = AccountWithMetadata::new(Account::default(), true, account_id);

    let result = execute_and_prove(
        vec![pre_state],
        Program::serialize_instruction(()).unwrap(),
        vec![InputAccountIdentity::Private(PrivateWitness {
            vpk: keys.vpk(),
            random_seed: [0; 32],
            identifier,
            kind: WitnessKind::Pda {
                binding: Some((program.id().into(), seed)),
            },
            nullifier: NullifierWitness::Init {
                npk,
                commitment_root: DUMMY_COMMITMENT_HASH,
            },
        })],
        &program.into(),
    );

    assert!(matches!(result, Err(LeeError::CircuitProvingError(_))));
}

#[test]
fn private_pda_update_identifier_mismatch_fails() {
    let result = pda_update_attempt(false, 5, 99);

    assert!(matches!(result, Err(LeeError::CircuitProvingError(_))));
}
