//! Measurement and equivalence harness for the memoized-`MemoryImage` execution path.
//!
//! Run with `--nocapture`. `RISC0_EXECUTOR=ipc` switches the baseline leg to the
//! out-of-process r0vm executor; the cached leg is unaffected by that variable.

use lee_core::{
    account::{AccountId, AccountInput, Cycles, Data},
    program::ProgramInput,
    to_borsh_frame, to_frame,
};
use risc0_binfmt::ProgramBinary;
use risc0_zkvm::{ExecutorEnv, ExecutorImpl, default_executor};

use crate::{
    error::LeeError,
    program::{DEFAULT_PUBLIC_CYCLE_BUDGET, Program, SessionOutcome},
};

fn transfer_pre_states() -> Vec<AccountInput> {
    vec![
        AccountInput::balance_only(AccountId::new([0; 32]), true, 77_665_544_332_211),
        AccountInput::balance_only(AccountId::new([1; 32]), false, 0),
    ]
}

/// An env carrying nothing but the cycle budget, for the guests that read no input.
fn bare_env(budget: Cycles) -> ExecutorEnv<'static> {
    let mut builder = ExecutorEnv::builder();
    builder.session_limit(Some(budget));
    builder.build().expect("env builds")
}

/// A fresh `ExecutorEnv` carrying the same inputs `Program::execute` would write.
fn env_for(
    program: &Program,
    pre_states: &[AccountInput],
    instruction: &[u8],
    budget: Cycles,
) -> ExecutorEnv<'static> {
    let mut builder = ExecutorEnv::builder();
    builder.session_limit(Some(budget));
    program
        .write_inputs(
            AccountId::from(program.id()),
            None,
            pre_states,
            instruction,
            &mut builder,
        )
        .expect("inputs write");
    builder.build().expect("env builds")
}

/// The pre-change code path: rebuild the image from the ELF on every call.
fn baseline(env: ExecutorEnv<'_>, elf: &[u8]) -> anyhow::Result<SessionOutcome> {
    let info = default_executor().execute(env, elf)?;
    Ok(SessionOutcome {
        journal: info.journal.bytes.clone(),
        cycles: info.cycles(),
    })
}

/// Journal bytes and cycle counts must match between the two paths, on several
/// real programs with several shapes of input.
#[test]
fn cached_path_matches_rebuild_path() {
    let cases: Vec<(&str, Program, Vec<AccountInput>, Vec<u8>)> = vec![
        (
            "simple_balance_transfer",
            crate::test_methods::simple_balance_transfer(),
            transfer_pre_states(),
            Program::serialize_instruction(11_223_344_556_677_u128).unwrap(),
        ),
        (
            "noop",
            crate::test_methods::noop(),
            transfer_pre_states(),
            Vec::new(),
        ),
        (
            "data_changer",
            crate::test_methods::data_changer(),
            vec![AccountInput::with_shard(
                AccountId::new([3; 32]),
                true,
                0,
                AccountId::from(crate::test_methods::data_changer().id()),
                Data::empty(),
            )],
            Program::serialize_instruction(vec![9_u8; 32]).unwrap(),
        ),
        (
            "foreign_shard_writer",
            crate::test_methods::foreign_shard_writer(),
            transfer_pre_states(),
            Program::serialize_instruction(vec![7_u8; 8]).unwrap(),
        ),
        (
            "malformed_journal",
            crate::test_methods::malformed_journal(),
            Vec::new(),
            Vec::new(),
        ),
    ];

    for (name, program, pre_states, instruction) in cases {
        let a = baseline(
            env_for(
                &program,
                &pre_states,
                &instruction,
                DEFAULT_PUBLIC_CYCLE_BUDGET,
            ),
            program.elf(),
        );
        let b = super::execute(
            env_for(
                &program,
                &pre_states,
                &instruction,
                DEFAULT_PUBLIC_CYCLE_BUDGET,
            ),
            program.elf(),
        );

        match (a, b) {
            (Ok(a), Ok(b)) => {
                assert_eq!(a.journal, b.journal, "{name}: journal bytes differ");
                assert_eq!(a.cycles, b.cycles, "{name}: cycle counts differ");
            }
            (Err(_), Err(_)) => {}
            (a, b) => panic!(
                "{name}: paths disagree on success. baseline_ok={} cached_ok={}",
                a.is_ok(),
                b.is_ok()
            ),
        }
    }
}

/// The session-limit bail must still be recognized in-process. Prints the raw
/// error text from both paths so any wording drift is visible.
#[test]
fn session_limit_still_maps_to_out_of_gas() {
    let program = crate::test_methods::simple_balance_transfer();
    let pre_states = transfer_pre_states();
    let instruction = Program::serialize_instruction(11_223_344_556_677_u128).unwrap();
    let budget: Cycles = 1_024;

    let base_err = baseline(
        env_for(&program, &pre_states, &instruction, budget),
        program.elf(),
    )
    .expect_err("tiny budget must bail");

    let cached_err = super::execute(
        env_for(&program, &pre_states, &instruction, budget),
        program.elf(),
    )
    .expect_err("tiny budget must bail");

    for (path, err) in [("baseline", &base_err), ("cached", &cached_err)] {
        assert!(
            format!("{err:#}").contains("Session limit exceeded"),
            "{path} no longer reports the session limit, the OutOfGas match breaks: {err:#}"
        );
    }

    // The mapping itself, through the real function.
    let mapped = Program::execute_session(
        env_for(&program, &pre_states, &instruction, budget),
        program.elf(),
        budget,
    )
    .expect_err("tiny budget must bail");
    assert!(
        matches!(mapped, LeeError::OutOfGas { budget: b } if b == budget),
        "session limit no longer maps to OutOfGas: {mapped:?}"
    );
}

/// A guest panic must not be mistaken for out-of-gas, including when the panic message
/// itself contains the session-limit phrase.
#[test]
fn guest_panic_is_not_out_of_gas() {
    let program = crate::test_methods::simple_balance_transfer();

    // No input at all: `read_lee_call` panics inside the guest.
    let cached_panic = super::execute(bare_env(DEFAULT_PUBLIC_CYCLE_BUDGET), program.elf())
        .expect_err("guest must panic on missing input");

    let base_panic = baseline(bare_env(DEFAULT_PUBLIC_CYCLE_BUDGET), program.elf())
        .expect_err("guest must panic on missing input");

    for (path, err) in [("baseline", &base_panic), ("cached", &cached_panic)] {
        assert!(
            format!("{err:#}").contains("Guest panicked"),
            "{path} no longer reports a guest panic, the spoofing guard breaks: {err:#}"
        );
    }

    let mapped = Program::execute_session(
        bare_env(DEFAULT_PUBLIC_CYCLE_BUDGET),
        program.elf(),
        DEFAULT_PUBLIC_CYCLE_BUDGET,
    )
    .expect_err("guest must panic on missing input");
    assert!(
        !matches!(mapped, LeeError::OutOfGas { .. }),
        "guest panic misclassified as OutOfGas: {mapped:?}"
    );

    // And the spoofing case the string match exists to defend against: a guest that
    // panics with the literal session-limit phrase.
    let spoof = crate::test_methods::panics_with_session_limit_text();
    let mut builder = ExecutorEnv::builder();
    builder.session_limit(Some(DEFAULT_PUBLIC_CYCLE_BUDGET));
    builder.write_slice(&to_borsh_frame(&lee_core::program::CallKind::Execute));
    let input = ProgramInput {
        self_account_id: spoof.id().into(),
        caller_account_id: None,
        pre_states: Vec::new(),
        instruction: Vec::<u8>::new(),
    };
    builder.write_slice(&to_frame(&borsh::to_vec(&input).unwrap()));
    let spoofed = Program::execute_session(
        builder.build().unwrap(),
        spoof.elf(),
        DEFAULT_PUBLIC_CYCLE_BUDGET,
    )
    .expect_err("spoofing guest must fail");
    assert!(
        !matches!(spoofed, LeeError::OutOfGas { .. }),
        "spoofed session-limit panic misclassified as OutOfGas: {spoofed:?}"
    );
}

/// The cache must key on the bytes, not on a caller-supplied id: two `Program`s sharing an
/// id but not an ELF must still each get their own image.
#[test]
fn cache_is_keyed_on_elf_bytes_not_program_id() {
    let a = crate::test_methods::simple_balance_transfer();
    let b = crate::test_methods::noop();

    // `new_unchecked` lets the id lie; the cache must not care.
    let liar = Program::new_unchecked(a.id(), std::borrow::Cow::Owned(b.elf().to_vec()));
    assert_eq!(liar.id(), a.id());
    assert_ne!(liar.elf(), a.elf());
    assert_eq!(super::slot(liar.elf()), super::slot(b.elf()));

    // Populate the cache under `a`'s id first, so an id-keyed cache would now be primed to
    // hand `a`'s image back for `liar`.
    let warm = super::execute(
        env_for(
            &a,
            &transfer_pre_states(),
            &Program::serialize_instruction(1_u128).unwrap(),
            DEFAULT_PUBLIC_CYCLE_BUDGET,
        ),
        a.elf(),
    )
    .unwrap();
    std::hint::black_box(warm);

    let pre_states = transfer_pre_states();
    let honest = super::execute(
        env_for(&b, &pre_states, &[], DEFAULT_PUBLIC_CYCLE_BUDGET),
        b.elf(),
    )
    .unwrap();
    let via_liar = super::execute(
        env_for(&b, &pre_states, &[], DEFAULT_PUBLIC_CYCLE_BUDGET),
        liar.elf(),
    )
    .unwrap();
    assert_eq!(honest.journal, via_liar.journal);
    assert_eq!(honest.cycles, via_liar.cycles);
}

/// A session that spans several continuation segments. `SessionInfo::cycles()` sums the
/// per-segment counts while the in-process path reads `Session::user_cycles`; on a single-segment
/// run those cannot disagree, so this is the case that actually tests the substitution.
#[test]
fn multi_segment_session_agrees_on_cycles_and_journal() {
    let program = crate::test_methods::multi_segment_burner();

    let base = baseline(bare_env(DEFAULT_PUBLIC_CYCLE_BUDGET), program.elf()).expect("burner runs");

    let cached =
        super::execute(bare_env(DEFAULT_PUBLIC_CYCLE_BUDGET), program.elf()).expect("burner runs");

    assert!(
        base.cycles > (1 << 20),
        "burner did not span multiple segments: {} cycles",
        base.cycles
    );
    assert_eq!(base.journal, cached.journal);
    assert_eq!(
        base.cycles, cached.cycles,
        "multi-segment cycle accounting differs"
    );
}

/// A malformed ELF is an error here. `LocalProver::execute` unwraps `ExecutorImpl::from_elf`, so
/// the same bytes abort the thread on the pre-change path whenever `prove` is on.
#[test]
fn malformed_elf_is_an_error_not_a_panic() {
    let program = crate::test_methods::simple_balance_transfer();
    let truncated = &program.elf()[..64];

    super::execute(bare_env(DEFAULT_PUBLIC_CYCLE_BUDGET), truncated)
        .expect_err("a truncated ProgramBinary must not build an image");
}

/// A guest whose ABI risc0 rejects must be rejected on the cached path too. `ExecutorImpl::new`
/// skips the check `from_elf` performs, so the cached path hand-copies it; this is what fails if
/// that copy ever drifts from upstream.
#[test]
fn incompatible_abi_is_rejected_on_both_paths() {
    let good = crate::test_methods::noop();
    let decoded = ProgramBinary::decode(good.elf()).expect("a committed guest decodes");

    let mut bad = ProgramBinary::new(decoded.user_elf, decoded.kernel_elf);
    bad.header.abi_version = semver::Version::new(2, 0, 0);
    let blob = bad.encode();

    let upstream = ExecutorImpl::from_elf(
        env_for(
            &good,
            &transfer_pre_states(),
            &[],
            DEFAULT_PUBLIC_CYCLE_BUDGET,
        ),
        &blob,
    );
    assert!(
        upstream.is_err(),
        "risc0 no longer rejects abi_version 2.0.0; the copied check needs revisiting"
    );

    let ours = super::execute(
        env_for(
            &good,
            &transfer_pre_states(),
            &[],
            DEFAULT_PUBLIC_CYCLE_BUDGET,
        ),
        &blob,
    );
    assert!(
        ours.is_err(),
        "the cached path accepted a guest risc0 rejects"
    );
}
