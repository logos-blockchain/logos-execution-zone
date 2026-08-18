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

/// Privacy-path version of the authorization-injection attack. The test passes when the attack
/// is rejected.
///
/// `signer_account_ids` is derived once, before the chain even starts, strictly from the
/// *top-level* `pre_states` passed to `execute_and_prove` — here, just the attacker's own
/// private account. The victim is only ever introduced later, inside `malicious_injector`'s
/// chained call, so it can never be part of `signer_account_ids` regardless of what P1 forges.
/// The circuit's own Vacant-branch consistency check (scoped to public accounts) derives the
/// victim's expected `is_authorized` from `signer_account_ids` membership, finds it absent, and
/// asserts that against the witnessed `is_authorized=true` — which fails, panicking inside the
/// guest. So the attack is caught during proving itself: `execute_and_prove` returns
/// `Err(CircuitProvingError)`, and never even reaches `from_privacy_preserving_transaction`.
#[test]
fn privacy_malicious_programs_cannot_drain_public_victim() {
    use lee_core::{
        Commitment, InputAccountIdentity, NullifierWitness, PrivateWitness, WitnessKind,
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
        InputAccountIdentity::Private(PrivateWitness {
            vpk: attacker_keys.vpk(),
            random_seed: [0; 32],
            identifier: 0,
            kind: WitnessKind::Regular {
                ask: Some(attacker_keys.ask),
            },
            nullifier: NullifierWitness::Update {
                view_tag: 0,
                nsk: attacker_keys.nsk(),
                membership_proof,
            },
        }),
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
    assert_eq!(state.get_account_by_id(victim_id).balance, victim_balance);
    assert_eq!(state.get_account_by_id(recipient_id).balance, 0);
}

/// Private-victim variant of the authorization-injection attack. The attacker has no `nsk` for
/// the victim's private account, so a regular update isn't an option — the only route is to
/// declare the victim `InputAccountIdentity::Public` and inject its data directly, since the
/// circuit has no access to chain state and can't detect the values are fabricated. That's the
/// exact same route `privacy_malicious_programs_cannot_drain_public_victim` exercises, so the
/// same mechanism catches it: the victim is only ever introduced via `malicious_injector`'s
/// chained call, never the top-level `pre_states` `signer_account_ids` is derived from, so the
/// circuit's Vacant-branch consistency check rejects the forged `is_authorized=true` and
/// `execute_and_prove` fails with `CircuitProvingError` before any proof is produced.
#[test]
fn privacy_malicious_programs_cannot_drain_private_victim() {
    use lee_core::{
        Commitment, InputAccountIdentity, NullifierWitness, PrivateWitness, WitnessKind,
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
    // so a regular update is not an option.
    let account_identities = vec![
        InputAccountIdentity::Private(PrivateWitness {
            vpk: attacker_keys.vpk(),
            random_seed: [0; 32],
            identifier: 0,
            kind: WitnessKind::Regular {
                ask: Some(attacker_keys.ask),
            },
            nullifier: NullifierWitness::Update {
                view_tag: 0,
                nsk: attacker_keys.nsk(),
                membership_proof,
            },
        }),
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

/// Regression test: a `PrivacyPreservingTransaction` carrying a structurally invalid
/// proof must be rejected with a clean `Err`.
#[test]
fn privacy_garbage_proof_is_rejected() {
    use lee_core::{
        Commitment, EncryptedAccountData, Nullifier, PrivateAction,
        account::Account,
        encryption::{Ciphertext, EphemeralPublicKey},
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
        public_pre_states: vec![],
        public_diffs: vec![],
        nonces: vec![],
        private_actions: vec![PrivateAction {
            nullifier: Nullifier::for_account_initialization(&account_id),
            root: [0; 32],
            commitment,
            encrypted_post_state: EncryptedAccountData {
                ciphertext: Ciphertext::from_inner(vec![]),
                epk: EphemeralPublicKey(vec![]),
                view_tag: 0,
            },
        }],
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
        Err(LeeError::InvalidPrivacyPreservingProof) => {}
        Err(other) => panic!("expected InvalidPrivacyPreservingProof, got {other:?}"),
        Ok(_) => panic!("garbage proof was accepted instead of rejected"),
    }
}

/// The race condition this whole `AccountDiff` design exists to fix: a public account touched
/// by a privacy transaction changes on-chain *after* the proof was generated but *before* the
/// sequencer validates it (e.g. an unrelated public transfer into/out of the same account
/// landing first). Proof validity no longer depends on a specific public-account snapshot — only
/// on what the circuit itself witnessed and output — so the proof still verifies, and the
/// diff it carries gets replayed against whatever the live balance actually is by the time the
/// sequencer processes it, not the stale balance captured at proving time.
#[test]
fn privacy_transaction_survives_public_state_changing_after_proving() {
    use lee_core::{
        DUMMY_COMMITMENT_HASH, InputAccountIdentity, NullifierWitness, PrivateWitness, WitnessKind,
        account::AccountWithMetadata,
    };

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
    let balance_at_proving_time = 100_u128;
    let balance_to_move = 37_u128;

    // State as it looked when the prover captured its pre-state.
    let state_at_proving_time = V03State::new()
        .with_public_accounts(public_state_from_balances(&[(
            sender_id,
            balance_at_proving_time,
        )]))
        .with_programs(std::iter::once(program.clone()));

    let sender_pre = AccountWithMetadata::new(
        state_at_proving_time.get_account_by_id(sender_id),
        true,
        sender_id,
    );

    let recipient_account_id =
        AccountId::for_regular_private_account(&recipient_keys.npk(), &recipient_keys.vpk(), 0);
    let recipient_pre = AccountWithMetadata::new(Account::default(), false, recipient_account_id);

    let (circuit_output, proof) = execute_and_prove(
        vec![sender_pre, recipient_pre],
        Program::serialize_instruction(balance_to_move).unwrap(),
        vec![
            InputAccountIdentity::Public,
            InputAccountIdentity::Private(PrivateWitness {
                vpk: recipient_keys.vpk(),
                random_seed: [0; 32],
                identifier: 0,
                kind: WitnessKind::Regular { ask: None },
                nullifier: NullifierWitness::Init {
                    npk: recipient_keys.npk(),
                    commitment_root: DUMMY_COMMITMENT_HASH,
                },
            }),
        ],
        &program.clone().into(),
    )
    .expect("execute_and_prove should succeed");

    let message = Message::from_circuit_output(vec![Nonce(0)], circuit_output);
    let witness_set = WitnessSet::for_message(&message, proof, &[&sender_key]);
    let tx = PrivacyPreservingTransaction::new(message, witness_set);

    // Simulates an unrelated public transaction landing on the sender's account between
    // proving and sequencer validation: live state now disagrees with what the prover
    // witnessed as `sender_pre`.
    let balance_at_validation_time = 250_u128;
    let state_at_validation_time = state_at_proving_time.with_public_accounts(
        public_state_from_balances(&[(sender_id, balance_at_validation_time)]),
    );

    let diff = ValidatedStateDiff::from_privacy_preserving_transaction(
        &tx,
        &state_at_validation_time,
        1,
        0,
    )
    .expect(
        "proof validity must not depend on live public state matching the witnessed \
                 pre-state",
    );
    let public_diff = diff.public_diff();

    assert_eq!(
        public_diff[&sender_id].balance,
        balance_at_validation_time - balance_to_move,
        "the diff must be replayed against live state at validation time, not the stale \
         balance captured when the proof was generated",
    );
}
