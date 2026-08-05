use std::collections::HashMap;

use lee_core::account::{Account, AccountId, Nonce};

use crate::{
    PrivateKey, PublicKey, V03State,
    error::{InvalidProgramBehaviorError, LeeError},
    program::Program,
    public_transaction::{Message, WitnessSet},
    validated_state_diff::ValidatedStateDiff,
};

fn public_state_from_balances(initial_data: &[(AccountId, u128)]) -> HashMap<AccountId, Account> {
    initial_data
        .iter()
        .copied()
        .map(|(account_id, balance)| {
            (
                account_id,
                Account {
                    program_owner: crate::test_methods::simple_balance_transfer().id(),
                    balance,
                    ..Account::default()
                },
            )
        })
        .collect()
}

#[test]
fn public_diff_reflects_a_successful_transfer() {
    // A successful native transfer must record the debited sender in
    // `public_diff()`.  Catches the mutation that replaces `public_diff` with
    // `HashMap::new()` (which would hide every account change).
    let from_key = PrivateKey::try_new([1_u8; 32]).unwrap();
    let from = AccountId::from(&PublicKey::new_from_private_key(&from_key));
    let to_key = PrivateKey::try_new([2_u8; 32]).unwrap();
    let to = AccountId::from(&PublicKey::new_from_private_key(&to_key));

    let state = V03State::new()
        .with_public_accounts(public_state_from_balances(&[(from, 100)]))
        .with_programs(std::iter::once(
            crate::test_methods::simple_balance_transfer(),
        ));
    let program_id = crate::test_methods::simple_balance_transfer().id();
    let message =
        Message::try_new(program_id, vec![from, to], vec![Nonce(0), Nonce(0)], 5_u128).unwrap();
    let witness_set = WitnessSet::for_message(&message, &[&from_key, &to_key]);
    let tx = crate::PublicTransaction::new(message, witness_set);

    let diff = ValidatedStateDiff::from_public_transaction(&tx, &state, 1, 0)
        .expect("a valid native transfer must validate");
    let public_diff = diff.public_diff();

    assert!(
        public_diff.contains_key(&from),
        "public_diff must contain the debited sender",
    );
    assert_eq!(
        public_diff[&from].balance, 95,
        "sender balance in the diff must reflect the debit",
    );
}

/// Regression test: a `PrivacyPreservingTransaction` carrying a structurally invalid
/// proof must be rejected with a clean `Err`.
#[test]
fn privacy_garbage_proof_is_rejected() {
    use lee_core::{
        Commitment,
        account::Account,
        program::{BlockValidityWindow, TimestampValidityWindow},
    };

    use crate::{
        PrivacyPreservingTransaction,
        privacy_preserving_transaction::{
            circuit::Proof, message::Message, witness_set::WitnessSet,
        },
    };

    let state = V03State::new();

    // Minimal message that passes every check up to proof verification: a single
    // commitment satisfies the non-empty requirement, no signers makes the
    // nonce/signature checks vacuously true, and unbounded validity windows are valid
    // for any block/timestamp.
    let account_id = AccountId::from(&PublicKey::new_from_private_key(
        &PrivateKey::try_new([1_u8; 32]).unwrap(),
    ));
    let commitment = Commitment::new(&account_id, &Account::default());
    let message = Message {
        public_account_ids: vec![],
        nonces: vec![],
        public_pre_states: vec![],
        public_diffs: vec![],
        encrypted_private_post_states: vec![],
        new_commitments: vec![commitment],
        new_nullifiers: vec![],
        block_validity_window: BlockValidityWindow::new_unbounded(),
        timestamp_validity_window: TimestampValidityWindow::new_unbounded(),
        signer_account_ids: vec![],
    };

    // Garbage proof bytes: not a valid borsh-encoded `InnerReceipt`.
    let garbage_proof = Proof::from_inner(vec![0xff_u8; 64]);
    let witness_set = WitnessSet::for_message(&message, garbage_proof, &[]);
    let tx = PrivacyPreservingTransaction::new(message, witness_set);

    let result = ValidatedStateDiff::from_privacy_preserving_transaction(&tx, &state, 1, 0);

    match result {
        Err(crate::error::LeeError::InvalidPrivacyPreservingProof) => {}
        Err(other) => panic!("expected InvalidPrivacyPreservingProof, got {other:?}"),
        Ok(_) => panic!("garbage proof was accepted instead of rejected"),
    }
}

/// End-to-end privacy transaction: a public sender sends to a newly-initialized private
/// recipient via `simple_balance_transfer`, proven by the circuit and then replayed by the
/// sequencer (`from_privacy_preserving_transaction`) against live state. Exercises the full
/// path this session's `AccountDiff` work added for the privacy circuit — not just the
/// circuit's own output shape (covered by `circuit::tests`), but the sequencer-side
/// `public_diffs` replay that actually applies the transfer.
#[test]
fn privacy_transaction_debits_public_sender_via_diff_replay() {
    use lee_core::{DUMMY_COMMITMENT_HASH, InputAccountIdentity, account::AccountWithMetadata};

    use crate::{
        PrivacyPreservingTransaction,
        privacy_preserving_transaction::{
            circuit::execute_and_prove, message::Message, witness_set::WitnessSet,
        },
        state::tests::test_private_account_keys_1,
    };

    let program = crate::test_methods::simple_balance_transfer();
    let recipient_keys = test_private_account_keys_1();

    let sender_key = PrivateKey::try_new([3_u8; 32]).unwrap();
    let sender_id = AccountId::from(&PublicKey::new_from_private_key(&sender_key));
    let sender_balance = 100_u128;
    let balance_to_move = 37_u128;

    let state = V03State::new()
        .with_public_accounts(public_state_from_balances(&[(sender_id, sender_balance)]))
        .with_programs(std::iter::once(program.clone()));

    let sender_pre =
        AccountWithMetadata::new(state.get_account_by_id(sender_id), true, sender_id);

    let recipient_account_id =
        AccountId::for_regular_private_account(&recipient_keys.npk(), &recipient_keys.vpk(), 0);
    let recipient_pre = AccountWithMetadata::new(Account::default(), true, recipient_account_id);

    let (circuit_output, proof) = execute_and_prove(
        vec![sender_pre, recipient_pre],
        Program::serialize_instruction(balance_to_move).unwrap(),
        vec![
            InputAccountIdentity::Public,
            InputAccountIdentity::PrivateForeignInit {
                vpk: recipient_keys.vpk(),
                random_seed: [0; 32],
                npk: recipient_keys.npk(),
                identifier: 0,
                commitment_root: DUMMY_COMMITMENT_HASH,
            },
        ],
        &program.clone().into(),
    )
    .expect("execute_and_prove should succeed");

    let message =
        Message::try_from_circuit_output(vec![sender_id], vec![Nonce(0)], circuit_output).unwrap();
    let witness_set = WitnessSet::for_message(&message, proof, &[&sender_key]);
    let tx = PrivacyPreservingTransaction::new(message, witness_set);

    let diff = ValidatedStateDiff::from_privacy_preserving_transaction(&tx, &state, 1, 0)
        .expect("a validly-signed privacy transfer must validate");
    let public_diff = diff.public_diff();

    assert_eq!(
        public_diff[&sender_id].balance,
        sender_balance - balance_to_move
    );
}

/// Two malicious programs (injector + launderer) attempt to drain a victim's balance
/// without the victim signing anything. The test passes when the attack is rejected
/// and the victim's balance is left untouched.
///
/// Attack flow:
///   Transaction (attacker signs) → P1 (`malicious_injector`)
///     → injects `victim(is_authorized=true)` into chained-call `pre_states` for P2
///   P2 (`malicious_launderer`)
///     → outputs empty pre/post states, forwarding the forged flag to `simple_balance_transfer`
///     → if `authorized_accounts` were built from the injected `pre_states`,
///       `{victim}.contains(victim)` would pass and the transfer would execute.
///
/// The validator must reject this: `authorized_accounts` must be derived from the
/// parent program's own validated `program_output.pre_states`, not from the chained-call
/// input, so a forged `is_authorized=true` flag is never trusted.
///
/// Public-transaction path only — unrelated to this session's `AccountDiff`/privacy-circuit
/// work, so no logic here changed; this is a straight port once the guest programs it depends
/// on (`malicious_injector`, `malicious_launderer`) were migrated to `AccountDiff`.
#[test]
fn malicious_programs_cannot_drain_victim_without_signature() {
    // p2_id, simple_balance_transfer_id, victim_id_raw, victim_balance, victim_nonce,
    // victim_program_owner, recipient_id_raw, amount.
    // Primitives only — AccountId/Account cannot round-trip through instruction_data
    // via risc0_zkvm::serde (SerializeDisplay issue).
    type InjectorInstruction = (
        lee_core::program::ProgramId, // p2_id
        lee_core::program::ProgramId, // simple_balance_transfer_id
        [u8; 32],                     // victim_id_raw
        u128,                         // victim_balance
        u128,                         // victim_nonce
        lee_core::program::ProgramId, // victim_program_owner
        [u8; 32],                     // recipient_id_raw
        u128,                         // amount
    );

    let attacker_key = PrivateKey::try_new([10; 32]).unwrap();
    let attacker_id = AccountId::from(&PublicKey::new_from_private_key(&attacker_key));

    let victim_key = PrivateKey::try_new([20; 32]).unwrap();
    let victim_id = AccountId::from(&PublicKey::new_from_private_key(&victim_key));

    let recipient_id = AccountId::new([42; 32]);

    let victim_balance = 5_000_u128;
    let state = V03State::new()
        .with_public_accounts(public_state_from_balances(&[
            (attacker_id, 100),
            (victim_id, victim_balance),
            (recipient_id, 0),
        ]))
        .with_programs([
            crate::test_methods::simple_balance_transfer(),
            crate::test_methods::malicious_injector(),
            crate::test_methods::malicious_launderer(),
        ]);

    // Read victim state from chain, exactly as the attacker would.
    let victim_account = state.get_account_by_id(victim_id);

    let instruction: InjectorInstruction = (
        crate::test_methods::malicious_launderer().id(),
        crate::test_methods::simple_balance_transfer().id(),
        *victim_id.value(),
        victim_account.balance,
        victim_account.nonce.0,
        victim_account.program_owner,
        *recipient_id.value(),
        victim_balance,
    );

    let message = Message::try_new(
        crate::test_methods::malicious_injector().id(),
        vec![attacker_id],
        vec![Nonce(0)],
        instruction,
    )
    .unwrap();

    let witness_set = WitnessSet::for_message(&message, &[&attacker_key]);
    let tx = crate::PublicTransaction::new(message, witness_set);

    let result = ValidatedStateDiff::from_public_transaction(&tx, &state, 1, 0);

    assert!(
        matches!(
            result,
            Err(LeeError::InvalidProgramBehavior(
                InvalidProgramBehaviorError::InvalidAccountAuthorization { account_id }
            )) if account_id == victim_id
        ),
        "attack transaction should be rejected with InvalidAccountAuthorization for the victim"
    );

    // Confirm the victim's balance is untouched.
    let victim_balance_after = state.get_account_by_id(victim_id).balance;
    let recipient_balance_after = state.get_account_by_id(recipient_id).balance;

    assert_eq!(
        victim_balance_after, victim_balance,
        "victim balance should be unchanged"
    );
    assert_eq!(
        recipient_balance_after, 0,
        "recipient should receive nothing"
    );
}

/// Privacy-path version of the authorization-injection attack. The test passes when the attack
/// is rejected.
///
/// Under the current `AccountDiff`/`signer_account_ids` design, `signer_account_ids` is derived
/// once, before the chain even starts, strictly from the *top-level* `pre_states` passed to
/// `execute_and_prove` — here, just the attacker's own private account. The victim is only ever
/// introduced later, inside `malicious_injector`'s chained call, so it can never be part of
/// `signer_account_ids` regardless of what P1 forges. The circuit's own Vacant-branch
/// consistency check (scoped to public accounts) derives the victim's expected `is_authorized`
/// from `signer_account_ids` membership, finds it absent, and asserts that against the witnessed
/// `is_authorized=true` — which fails, panicking inside the guest. So the attack is caught
/// during proving itself: `execute_and_prove` returns `Err(CircuitProvingError)`, and never
/// even reaches `from_privacy_preserving_transaction`. (Before `AccountDiff`, this same attack
/// was rejected one layer later, at proof verification against a reconstructed
/// `public_pre_states` — see git history for that version of this test.)
#[test]
fn privacy_malicious_programs_cannot_drain_public_victim() {
    use lee_core::{
        Commitment, InputAccountIdentity,
        account::{Account, AccountWithMetadata},
    };

    use crate::{
        privacy_preserving_transaction::circuit::{ProgramWithDependencies, execute_and_prove},
        state::{CommitmentSet, tests::test_private_account_keys_1},
    };

    type InjectorInstruction = (
        lee_core::program::ProgramId, // p2_id
        lee_core::program::ProgramId, // simple_balance_transfer_id
        [u8; 32],                     // victim_id_raw
        u128,                         // victim_balance
        u128,                         // victim_nonce
        lee_core::program::ProgramId, // victim_program_owner
        [u8; 32],                     // recipient_id_raw
        u128,                         // amount
    );

    // Attacker controls a private account.
    let attacker_keys = test_private_account_keys_1();
    let attacker_id =
        AccountId::for_regular_private_account(&attacker_keys.npk(), &attacker_keys.vpk(), 0);

    let victim_id = AccountId::new([20_u8; 32]);
    let recipient_id = AccountId::new([42_u8; 32]);
    let victim_balance = 5_000_u128;

    // genesis sets program_owner = simple_balance_transfer_program.id() on all accounts.
    let state = V03State::new()
        .with_public_accounts(public_state_from_balances(&[
            (victim_id, victim_balance),
            (recipient_id, 0),
        ]))
        .with_programs([
            crate::test_methods::simple_balance_transfer(),
            crate::test_methods::malicious_injector(),
            crate::test_methods::malicious_launderer(),
        ]);

    // Build attacker's private account and its local commitment tree.
    let attacker_account = Account {
        program_owner: crate::test_methods::simple_balance_transfer().id(),
        balance: 100,
        ..Account::default()
    };
    let attacker_commitment = Commitment::new(&attacker_id, &attacker_account);
    let mut commitment_set = CommitmentSet::with_capacity(1);
    commitment_set.extend(std::slice::from_ref(&attacker_commitment));
    let membership_proof = commitment_set
        .get_proof_for(&attacker_commitment)
        .expect("attacker commitment must be in the set");

    let attacker_pre = AccountWithMetadata::new(attacker_account, true, attacker_id);

    let victim_account = state.get_account_by_id(victim_id);
    let instruction: InjectorInstruction = (
        crate::test_methods::malicious_launderer().id(),
        crate::test_methods::simple_balance_transfer().id(),
        *victim_id.value(),
        victim_account.balance,
        victim_account.nonce.0,
        victim_account.program_owner,
        *recipient_id.value(),
        victim_balance,
    );
    let instruction_data = Program::serialize_instruction(instruction).unwrap();

    let p2 = crate::test_methods::malicious_launderer();
    let at = crate::test_methods::simple_balance_transfer();
    let program_with_deps = ProgramWithDependencies::new(
        crate::test_methods::malicious_injector(),
        [(p2.id(), p2), (at.id(), at)].into(),
    );

    // account_identities order must match self.pre_states as built by the circuit:
    //   [0] attacker — first seen in P1's program_output.pre_states
    //   [1] victim   — first seen in simple_balance_transfer's program_output.pre_states
    //   [2] recipient — first seen in simple_balance_transfer's program_output.pre_states
    let account_identities = vec![
        InputAccountIdentity::PrivateAuthorizedUpdate {
            vpk: attacker_keys.vpk(),
            random_seed: [0; 32],
            view_tag: 0,
            nsk: attacker_keys.nsk,
            membership_proof,
            identifier: 0,
        },
        InputAccountIdentity::Public, // victim
        InputAccountIdentity::Public, // recipient
    ];

    let result = execute_and_prove(
        vec![attacker_pre],
        instruction_data,
        account_identities,
        &program_with_deps,
    );

    assert!(
        matches!(result, Err(LeeError::CircuitProvingError(_))),
        "forged victim(is_authorized=true) should be caught inside the circuit itself, since \
         signer_account_ids is derived from the top-level pre_states only, and the victim is \
         only ever introduced via a chained call"
    );
}

/// Private-victim variant of the authorization-injection attack. The attacker has no `nsk` for
/// the victim's private account, so `PrivateAuthorizedUpdate` isn't an option — the only route
/// is to declare the victim `InputAccountIdentity::Public` (mask=0) and inject its data
/// directly, since the circuit has no access to chain state and can't detect the values are
/// fabricated. That's the exact same route `privacy_malicious_programs_cannot_drain_public_victim`
/// exercises, so the same mechanism catches it: the victim is only ever introduced via
/// `malicious_injector`'s chained call, never the top-level `pre_states` `signer_account_ids` is
/// derived from, so the circuit's Vacant-branch consistency check rejects the forged
/// `is_authorized=true` and `execute_and_prove` fails with `CircuitProvingError` before any
/// proof is produced. (Before `AccountDiff`, this was rejected one layer later — see git
/// history for that version, which exercised the `public_pre_states` reconstruction mismatch.)
#[test]
fn privacy_malicious_programs_cannot_drain_private_victim() {
    use lee_core::{
        Commitment, InputAccountIdentity,
        account::{Account, AccountWithMetadata},
    };

    use crate::{
        privacy_preserving_transaction::circuit::{ProgramWithDependencies, execute_and_prove},
        state::{
            CommitmentSet,
            tests::{test_private_account_keys_1, test_private_account_keys_2},
        },
    };

    type InjectorInstruction = (
        lee_core::program::ProgramId, // p2_id
        lee_core::program::ProgramId, // simple_balance_transfer_id
        [u8; 32],                     // victim_id_raw
        u128,                         // victim_balance
        u128,                         // victim_nonce
        lee_core::program::ProgramId, // victim_program_owner
        [u8; 32],                     // recipient_id_raw
        u128,                         // amount
    );

    // Attacker controls a private account.
    let attacker_keys = test_private_account_keys_1();
    let attacker_id =
        AccountId::for_regular_private_account(&attacker_keys.npk(), &attacker_keys.vpk(), 0);

    // Victim is a private account — not registered in public chain state.
    let victim_keys = test_private_account_keys_2();
    let victim_id =
        AccountId::for_regular_private_account(&victim_keys.npk(), &victim_keys.vpk(), 0);
    let victim_balance = 5_000_u128;

    let recipient_id = AccountId::new([42_u8; 32]);

    // Build attacker's private account and its local commitment tree.
    let attacker_account = Account {
        program_owner: crate::test_methods::simple_balance_transfer().id(),
        balance: 100,
        ..Account::default()
    };
    let attacker_commitment = Commitment::new(&attacker_id, &attacker_account);
    let mut commitment_set = CommitmentSet::with_capacity(1);
    commitment_set.extend(std::slice::from_ref(&attacker_commitment));
    let membership_proof = commitment_set
        .get_proof_for(&attacker_commitment)
        .expect("attacker commitment must be in the set");

    let attacker_pre = AccountWithMetadata::new(attacker_account, true, attacker_id);

    // The attacker supplies the victim's account data directly — it cannot be read from
    // public state. The injected balance and program_owner allow simple_balance_transfer
    // to succeed inside the circuit, which has no access to chain state and cannot detect
    // that these values are fabricated.
    let instruction: InjectorInstruction = (
        crate::test_methods::malicious_launderer().id(),
        crate::test_methods::simple_balance_transfer().id(),
        *victim_id.value(),
        victim_balance,
        0_u128,                                              // nonce
        crate::test_methods::simple_balance_transfer().id(), // program_owner
        *recipient_id.value(),
        victim_balance,
    );
    let instruction_data = Program::serialize_instruction(instruction).unwrap();

    let p2 = crate::test_methods::malicious_launderer();
    let at = crate::test_methods::simple_balance_transfer();
    let program_with_deps = ProgramWithDependencies::new(
        crate::test_methods::malicious_injector(),
        [(p2.id(), p2), (at.id(), at)].into(),
    );

    // account_identities order must match self.pre_states as built by the circuit:
    //   [0] attacker  — first seen in P1's program_output.pre_states
    //   [1] victim    — first seen in simple_balance_transfer's program_output.pre_states
    //   [2] recipient — first seen in simple_balance_transfer's program_output.pre_states
    //
    // Victim is marked Public: the attacker has no nsk for the victim's private account,
    // so PrivateAuthorizedUpdate is not an option.
    let account_identities = vec![
        InputAccountIdentity::PrivateAuthorizedUpdate {
            vpk: attacker_keys.vpk(),
            random_seed: [0; 32],
            view_tag: 0,
            nsk: attacker_keys.nsk,
            membership_proof,
            identifier: 0,
        },
        InputAccountIdentity::Public, // victim — attacker lacks victim's nsk
        InputAccountIdentity::Public, // recipient
    ];

    let result = execute_and_prove(
        vec![attacker_pre],
        instruction_data,
        account_identities,
        &program_with_deps,
    );

    assert!(
        matches!(result, Err(LeeError::CircuitProvingError(_))),
        "forged victim(is_authorized=true) should be caught inside the circuit itself, the \
         same way as the public-victim variant of this attack"
    );
}

/// Attempt to modify a still-default (unclaimed) public account's data without claiming it,
/// using `changer_claimer(should_claim = false)`. This was originally written to test rule 4
/// (`validate_execution`'s "data changes only allowed if owned by executing program or if
/// account pre state has default values" bypass) at sequencer-replay time, on the theory that
/// the circuit's own rule-4 check runs on untrusted witnessed data for public accounts and could
/// be forged. It doesn't reach that check at all: `derive_from_outputs` has its own, separate,
/// whole-chain sweep — "Check that all modified uninitialized accounts were claimed" — that
/// rejects this unconditionally, using only witnessed data (no live state needed), before
/// `execute_and_prove` can even produce a proof. See the companion
/// `privacy_data_modification_forgery_is_rejected_for_private_account` test for the private-
/// account case, which was written to confirm this isn't a public-only accident of check
/// ordering — the sweep iterates `execution_state.pre_states` uniformly, with no
/// `account_identity.is_public()` distinction anywhere in it.
#[test]
fn privacy_data_modification_forgery_is_rejected_for_public_account() {
    use lee_core::{InputAccountIdentity, account::AccountWithMetadata};

    use crate::privacy_preserving_transaction::circuit::execute_and_prove;

    let victim_id = AccountId::new([77_u8; 32]);
    let attacker_program = crate::test_methods::changer_claimer();

    // Witnessed as fully default (unclaimed) — matches live reality here, since this test no
    // longer depends on live state diverging from the witnessed pre-state at all.
    let forged_victim = AccountWithMetadata::new(Account::default(), false, victim_id);

    let data = vec![0xDE_u8, 0xAD, 0xBE, 0xEF];
    let instruction = Program::serialize_instruction((Some(data), false)).unwrap();

    let result = execute_and_prove(
        vec![forged_victim],
        instruction,
        vec![InputAccountIdentity::Public],
        &attacker_program.into(),
    );

    match result {
        Err(LeeError::CircuitProvingError(message)) => {
            assert!(
                message.contains("was modified but not claimed"),
                "expected the 'modified but not claimed' sweep to reject this, got a different \
                 CircuitProvingError: {message}"
            );
        }
        Err(other) => panic!("expected CircuitProvingError, got {other:?}"),
        Ok(_) => panic!("modifying an unclaimed account without claiming it was accepted"),
    }
}

/// Private-account counterpart to `privacy_data_modification_forgery_is_rejected_for_public_account`
/// — confirms the "modified but not claimed" sweep isn't accidentally public-only, e.g. as a side
/// effect of scoping the separate `is_authorized`-consistency check to public accounts earlier.
/// Uses a fresh private account (`PrivateAuthorizedInit`, so the caller genuinely owns it via
/// `nsk` — there's no live state to lie about here, this is just confirming the circuit's own
/// invariant holds for private accounts too, since it's the only enforcement they ever get).
#[test]
fn privacy_data_modification_forgery_is_rejected_for_private_account() {
    use lee_core::{DUMMY_COMMITMENT_HASH, InputAccountIdentity, account::AccountWithMetadata};

    use crate::{
        privacy_preserving_transaction::circuit::execute_and_prove,
        state::tests::test_private_account_keys_1,
    };

    let keys = test_private_account_keys_1();
    let account_id = AccountId::for_regular_private_account(&keys.npk(), &keys.vpk(), 0);
    let pre = AccountWithMetadata::new(Account::default(), true, account_id);

    let data = vec![0xDE_u8, 0xAD, 0xBE, 0xEF];
    let instruction = Program::serialize_instruction((Some(data), false)).unwrap();

    let result = execute_and_prove(
        vec![pre],
        instruction,
        vec![InputAccountIdentity::PrivateAuthorizedInit {
            vpk: keys.vpk(),
            random_seed: [0; 32],
            nsk: keys.nsk,
            identifier: 0,
            commitment_root: DUMMY_COMMITMENT_HASH,
        }],
        &crate::test_methods::changer_claimer().into(),
    );

    match result {
        Err(LeeError::CircuitProvingError(message)) => {
            assert!(
                message.contains("was modified but not claimed"),
                "expected the 'modified but not claimed' sweep to reject this, got a different \
                 CircuitProvingError: {message}"
            );
        }
        Err(other) => panic!("expected CircuitProvingError, got {other:?}"),
        Ok(_) => panic!(
            "modifying an unclaimed private account without claiming it was accepted \u{2014} \
             this would be a real gap, since private accounts have no sequencer-side backstop"
        ),
    }
}
