use std::collections::HashMap;

use fee_core::params::MAX_GAS_EXEC;
use lee_core::{
    account::{Account, AccountId, Nonce},
    program::{PdaSeed, ProgramId},
};

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
        Message::new_feeless(program_id, vec![from, to], vec![Nonce(0), Nonce(0)], 5_u128);
    let witness_set = WitnessSet::for_message(&message, &[&from_key, &to_key]);
    let tx = crate::PublicTransaction::new(message, witness_set);

    let (diff, _outcome) =
        ValidatedStateDiff::from_public_transaction(&tx, &state, 1, 0, MAX_GAS_EXEC)
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

/// Privacy-path version of the authorization-injection attack. The test passes when the
/// attack is rejected and the victim's balance is left untouched.
///
/// `execute_and_prove` succeeds because each inner receipt is individually valid and the
/// outer circuit faithfully commits whatever the attacker's program output says, including
/// `victim(is_authorized=true)`. The circuit has no access to chain state and cannot know
/// the victim never signed.
///
/// The host-side validator is what catches the attack: it independently reconstructs
/// `public_pre_states` from chain state using `signer_account_ids.contains(victim_id) = false`,
/// so it expects `victim(is_authorized=false)`. The committed journal and the reconstructed
/// expected output diverge, `receipt.verify` fails, and `from_privacy_preserving_transaction`
/// returns an error before any state is applied.
#[test]
fn privacy_malicious_programs_cannot_drain_public_victim() {
    use lee_core::{
        Commitment, InputAccountIdentity, NullifierWitness, PrivateWitness, WitnessKind,
        account::{Account, AccountWithMetadata},
    };

    use crate::{
        PrivacyPreservingTransaction,
        privacy_preserving_transaction::{
            circuit::{ProgramWithDependencies, execute_and_prove},
            message::Message,
            witness_set::WitnessSet,
        },
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

    // execute_and_prove succeeds: all inner receipts are valid.
    // The outer circuit commits victim(is_authorized=true) to its journal.
    let (circuit_output, proof) = execute_and_prove(
        vec![attacker_pre],
        instruction_data,
        account_identities,
        &program_with_deps,
    )
    .expect("execute_and_prove should succeed \u{2014} the programs execute correctly");

    // public_account_ids lists the Public entries from account_identities, in order.
    // The single ciphertext belongs to attacker's private account update.
    let message = Message::from_circuit_output(
        vec![], // no public signers, no nonces
        circuit_output,
    );

    let witness_set = WitnessSet::for_message(&message, proof, &[]); // no signatures
    let tx = PrivacyPreservingTransaction::new(message, witness_set);

    let result = ValidatedStateDiff::from_privacy_preserving_transaction(&tx, &state, 1, 0);

    assert!(
        matches!(result, Err(LeeError::InvalidPrivacyPreservingProof)),
        "attack privacy transaction should be rejected with InvalidPrivacyPreservingProof"
    );
    assert_eq!(state.get_account_by_id(victim_id).balance, victim_balance);
    assert_eq!(state.get_account_by_id(recipient_id).balance, 0);
}

/// Private-victim variant of the authorization-injection attack. The test passes when the
/// attack is rejected and the recipient's balance remains zero.
///
/// After the circuit's Vacant branch accepts the injected `victim(is_authorized=true)`
/// verbatim, the attacker must choose how to declare the victim in `account_identities`.
/// There are two routes, both closed:
///
/// - **mask=1 (regular update)**: the circuit derives `account_id =
///   AccountId::for_regular_private_account(&npk_from(nsk), identifier)` and asserts it matches
///   `pre_state.account_id`. Passing this check requires the victim's `nsk`, which the attacker
///   does not have. `execute_and_prove` panics inside the ZKVM and no proof is produced.
///
/// - **mask=0 (`Public`)**: the circuit places the account in `public_pre_states` and
///   `execute_and_prove` succeeds. The host-side validator then reconstructs `public_pre_states`
///   from chain state; `state.get_account_by_id(victim_id)` returns the default account (balance=0)
///   because the victim has no public state entry. The committed journal and the reconstructed
///   expected output diverge, `receipt.verify` fails, and `from_privacy_preserving_transaction`
///   returns an error before any state is applied. This test exercises this route.
#[test]
fn privacy_malicious_programs_cannot_drain_private_victim() {
    use lee_core::{
        Commitment, InputAccountIdentity, NullifierWitness, PrivateWitness, WitnessKind,
        account::{Account, AccountWithMetadata},
    };

    use crate::{
        PrivacyPreservingTransaction,
        privacy_preserving_transaction::{
            circuit::{ProgramWithDependencies, execute_and_prove},
            message::Message,
            witness_set::WitnessSet,
        },
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

    // Victim has no public state entry; only recipient is registered at genesis.
    let state = V03State::new()
        .with_public_accounts(public_state_from_balances(&[(recipient_id, 0)]))
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

    // execute_and_prove succeeds: simple_balance_transfer runs against the injected
    // victim(balance=5000, is_authorized=true) and produces valid inner receipts.
    // The outer circuit commits victim(is_authorized=true) to public_pre_states.
    let (circuit_output, proof) = execute_and_prove(
        vec![attacker_pre],
        instruction_data,
        account_identities,
        &program_with_deps,
    )
    .expect("execute_and_prove should succeed \u{2014} the programs execute correctly");

    // public_account_ids lists the Public entries from account_identities, in order.
    // The single ciphertext belongs to attacker's private account update.
    let message = Message::from_circuit_output(
        vec![], // no public signers, no nonces
        circuit_output,
    );

    let witness_set = WitnessSet::for_message(&message, proof, &[]); // no signatures
    let tx = PrivacyPreservingTransaction::new(message, witness_set);

    let result = ValidatedStateDiff::from_privacy_preserving_transaction(&tx, &state, 1, 0);

    assert!(
        matches!(result, Err(LeeError::InvalidPrivacyPreservingProof)),
        "attack on private victim should be rejected with InvalidPrivacyPreservingProof"
    );
    // Victim has no public balance to check; confirming the recipient received nothing
    // is sufficient to show no funds moved.
    assert_eq!(state.get_account_by_id(recipient_id).balance, 0);
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

    let message = Message::new_feeless(
        crate::test_methods::malicious_injector().id(),
        vec![attacker_id],
        vec![Nonce(0)],
        instruction,
    );

    let witness_set = WitnessSet::for_message(&message, &[&attacker_key]);
    let tx = crate::PublicTransaction::new(message, witness_set);

    let result = ValidatedStateDiff::from_public_transaction(&tx, &state, 1, 0, MAX_GAS_EXEC);

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
        public_actions: vec![],
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

/// Builds a `chain_caller` transaction that chains `num_chain_calls` balance transfers.
fn chained_transfer_transaction(
    from_key: &PrivateKey,
    to: AccountId,
    num_chain_calls: u32,
) -> crate::PublicTransaction {
    let from = AccountId::from(&PublicKey::new_from_private_key(from_key));
    let instruction: (u128, ProgramId, u32, Option<PdaSeed>) = (
        7,
        crate::test_methods::simple_balance_transfer().id(),
        num_chain_calls,
        None,
    );
    let message = Message::new_feeless(
        crate::test_methods::chain_caller().id(),
        // The `chain_caller` program permutes the account order in the chained call.
        vec![to, from],
        vec![Nonce(0)],
        instruction,
    );
    let witness_set = WitnessSet::for_message(&message, &[from_key]);
    crate::PublicTransaction::new(message, witness_set)
}

#[test]
fn chained_calls_share_a_single_cycle_budget() {
    // The chain of calls runs one zkVM session per call, all drawing on one budget: the reported
    // cycles must be their sum, and a budget that only covers a shorter chain must halt the longer
    // one part-way through with `OutOfGas`.
    let from_key = PrivateKey::try_new([1_u8; 32]).unwrap();
    let from = AccountId::from(&PublicKey::new_from_private_key(&from_key));
    let to = AccountId::new([2_u8; 32]);
    let state = V03State::new()
        .with_public_accounts(public_state_from_balances(&[(from, 1_000), (to, 0)]))
        .with_test_programs();

    let one_call = chained_transfer_transaction(&from_key, to, 1);
    let two_calls = chained_transfer_transaction(&from_key, to, 2);

    let (_, one_call_outcome) =
        ValidatedStateDiff::from_public_transaction(&one_call, &state, 1, 0, MAX_GAS_EXEC)
            .expect("a single chained transfer must validate");
    let (_, two_calls_outcome) =
        ValidatedStateDiff::from_public_transaction(&two_calls, &state, 1, 0, MAX_GAS_EXEC)
            .expect("two chained transfers must validate");

    assert!(
        two_calls_outcome.cycles > one_call_outcome.cycles,
        "cycles must accumulate over the chain: {} sessions' worth was not more than {}",
        two_calls_outcome.cycles,
        one_call_outcome.cycles,
    );

    // A budget sized for the shorter chain cannot pay for the extra session of the longer one.
    let result = ValidatedStateDiff::from_public_transaction(
        &two_calls,
        &state,
        1,
        0,
        one_call_outcome.cycles,
    );
    assert!(
        matches!(result, Err(LeeError::OutOfGas { budget }) if budget == one_call_outcome.cycles),
        "a chain outgrowing its budget must halt with OutOfGas",
    );
}

/// An out-of-gas transaction meters at **at least its whole budget**, so the fee path's
/// `min(cycles, gas_limit)` charges the full limit.
///
/// The executor discards the cycle count of the session it bails out of, so metering only the
/// sessions that ran to completion would report zero for the single-session shape — a transaction
/// that really burned its whole budget would then ride the block's execution cap for free. Both
/// shapes are covered here, and for the chain both failure timings are: whether the budget runs
/// out *inside* the second session or is already spent when the loop reaches it depends on where
/// the first session lands, and the guarantee has to hold either way.
#[test]
fn an_out_of_gas_transaction_meters_its_whole_budget() {
    let from_key = PrivateKey::try_new([1_u8; 32]).unwrap();
    let from = AccountId::from(&PublicKey::new_from_private_key(&from_key));
    let to = AccountId::new([2_u8; 32]);
    let state = V03State::new()
        .with_public_accounts(public_state_from_balances(&[(from, 1_000), (to, 0)]))
        .with_test_programs();

    // Single session: a budget of one cycle cannot fund it, so it halts having completed nothing.
    let one_call = chained_transfer_transaction(&from_key, to, 1);
    let (outcome, result) =
        ValidatedStateDiff::from_public_transaction_metered(&one_call, &state, 1, 0, 1);
    assert!(matches!(result, Err(LeeError::OutOfGas { budget: 1 })));
    assert_eq!(
        outcome.cycles.min(1),
        1,
        "a single-session halt must still be charged its whole budget, not zero",
    );

    // Chained: a budget sized for the shorter chain leaves the longer one short mid-way.
    let (_, one_call_outcome) =
        ValidatedStateDiff::from_public_transaction(&one_call, &state, 1, 0, MAX_GAS_EXEC)
            .expect("a single chained transfer must validate");
    let budget = one_call_outcome.cycles;
    let two_calls = chained_transfer_transaction(&from_key, to, 2);
    let (chain_outcome, chain_result) =
        ValidatedStateDiff::from_public_transaction_metered(&two_calls, &state, 1, 0, budget);
    assert!(matches!(chain_result, Err(LeeError::OutOfGas { .. })));
    assert!(
        chain_outcome.cycles >= budget,
        "an out-of-gas chain meters at least its budget: {} < {budget}",
        chain_outcome.cycles,
    );
    assert_eq!(chain_outcome.cycles.min(budget), budget);
}

/// A guest panic is metered at the **whole budget**: the executor bails without a `SessionInfo`,
/// so the session that failed took its own measurement with it, and the bound it was granted is
/// the only sound price for it.
///
/// TBA(revert-metering): the guest exit-code refactor (`.claude/lez-fees/EXIT-CODES.md`) will make
/// a *deliberate* revert exit with a code instead of panicking, which halts as `Ok(SessionInfo)`
/// and so bills its real cycles. This arm stays regardless — guests build with `panic=abort`, so
/// user-supplied bytecode can always choose to panic and must not be cheaper for it.
#[test]
fn a_guest_panic_is_metered_at_its_whole_budget() {
    let signer_key = PrivateKey::try_new([1_u8; 32]).unwrap();
    let signer = AccountId::from(&PublicKey::new_from_private_key(&signer_key));
    let unsigned = AccountId::new([2_u8; 32]);
    let state = V03State::new()
        .with_public_accounts(public_state_from_balances(&[
            (signer, 1_000),
            (unsigned, 0),
        ]))
        .with_test_programs();

    // `auth_asserting_noop` asserts every pre-state is authorized. The second account is not
    // signed for, so the assert trips and the guest panics — a real `sys_panic`, not an early
    // return.
    let panicking = |nonce: u128| {
        let message = Message::new_feeless(
            crate::test_methods::auth_asserting_noop().id(),
            vec![signer, unsigned],
            vec![Nonce(nonce)],
            (),
        );
        let witness_set = WitnessSet::for_message(&message, &[&signer_key]);
        crate::PublicTransaction::new(message, witness_set)
    };

    let budget = 5_000_000;
    let (outcome, result) =
        ValidatedStateDiff::from_public_transaction_metered(&panicking(0), &state, 1, 0, budget);
    assert!(
        matches!(result, Err(LeeError::ProgramExecutionFailed(_))),
        "the guest must panic, got {:?}",
        result.err(),
    );
    assert_eq!(
        outcome.cycles, budget,
        "a panicking session is charged the budget it was granted, not zero",
    );

    // The charge tracks the declared bound rather than being a flat penalty: a smaller budget, a
    // smaller charge. So it stays a price the payer chose and already reserved against.
    let smaller_budget = 2_000_000;
    let (smaller_outcome, _) = ValidatedStateDiff::from_public_transaction_metered(
        &panicking(0),
        &state,
        1,
        0,
        smaller_budget,
    );
    assert_eq!(smaller_outcome.cycles, smaller_budget);
}

/// A guest that halts cleanly without writing a decodable output keeps its **exact** cycles.
///
/// This shape is the one failure risc0 reports as `Ok(SessionInfo)`, so the count is real and is
/// strictly better information than the budget. It used to be discarded along with the
/// journal-decode error, billing a whole class of failures at zero execution gas.
#[test]
fn a_guest_that_writes_no_output_is_metered_at_its_real_cycles() {
    let from_key = PrivateKey::try_new([1_u8; 32]).unwrap();
    let from = AccountId::from(&PublicKey::new_from_private_key(&from_key));
    let state = V03State::new()
        .with_public_accounts(public_state_from_balances(&[(from, 1_000)]))
        .with_test_programs();

    // `missing_output` returns early unless it is handed exactly two accounts. One account, so it
    // takes the early return: the session halts at zero, having committed nothing.
    let message = Message::new_feeless(
        crate::test_methods::missing_output().id(),
        vec![from],
        vec![Nonce(0)],
        (),
    );
    let witness_set = WitnessSet::for_message(&message, &[&from_key]);
    let tx = crate::PublicTransaction::new(message, witness_set);

    let budget = 5_000_000;
    let (outcome, result) =
        ValidatedStateDiff::from_public_transaction_metered(&tx, &state, 1, 0, budget);
    assert!(
        matches!(result, Err(LeeError::MalformedProgramOutput { .. })),
        "a guest that writes no output must surface as a malformed output, got {:?}",
        result.err(),
    );
    assert!(
        outcome.cycles > 0,
        "the session ran, so it must be metered at something",
    );
    assert!(
        outcome.cycles < budget,
        "and at its real cost, well under the budget: {} is not below {budget}",
        outcome.cycles,
    );
}

/// A program-deployment transaction whose bytecode deploys cleanly, so the only thing under test
/// below is its witness set.
fn deployment_tx(
    fees: crate::FeeFields,
    witness: impl FnOnce(&crate::program_deployment_transaction::Message) -> WitnessSet,
) -> crate::ProgramDeploymentTransaction {
    let message = crate::program_deployment_transaction::Message::new(
        crate::test_methods::noop().elf().to_owned(),
        fees,
    );
    let witness_set = witness(&message);
    crate::ProgramDeploymentTransaction::new(message, witness_set)
}

/// The apply path — not just ingest — must reject a deployment whose witness signature does not
/// verify. Deployments also arrive inside peer blocks and are replayed from storage, neither of
/// which goes through `transaction_stateless_check`, so T8 could otherwise read a forged fee
/// witness as an authorization fact.
#[test]
fn deployment_with_an_invalid_witness_is_rejected_on_the_apply_path() {
    let deployer = PrivateKey::try_new([1; 32]).unwrap();
    let payer = AccountId::from(&PublicKey::new_from_private_key(&deployer));
    let fees = crate::FeeFields::new(payer, 60_000, 0, 1_000_000);

    // Control: the same transaction with a valid witness deploys.
    let valid = deployment_tx(fees, |message| {
        WitnessSet::for_message(message, &[&deployer])
    });
    let mut state = V03State::new();
    state
        .transition_from_program_deployment_transaction(&valid)
        .expect("a correctly witnessed deployment must apply");

    // Same message, same signer, but the signature bytes are garbage.
    let tampered = deployment_tx(fees, |message| {
        let mut witness_set = WitnessSet::for_message(message, &[&deployer]);
        witness_set.signatures_and_public_keys[0].0 = crate::Signature::new_for_tests([1; 64]);
        witness_set
    });
    assert!(
        matches!(
            ValidatedStateDiff::from_program_deployment_transaction(&tampered, &V03State::new()),
            Err(LeeError::InvalidInput(_))
        ),
        "a deployment with an invalid witness signature must not produce a diff"
    );
    let mut fresh_state = V03State::new();
    assert!(
        matches!(
            fresh_state.transition_from_program_deployment_transaction(&tampered),
            Err(LeeError::InvalidInput(_))
        ),
        "and must not apply to state"
    );
    assert!(
        fresh_state.programs().is_empty(),
        "a rejected deployment must leave no program behind"
    );
}

/// A sponsored deployment whose fee witness does not verify is rejected on the apply path too —
/// the fee witness is checked, not merely carried.
#[test]
fn deployment_with_an_invalid_fee_witness_is_rejected_on_the_apply_path() {
    let deployer = PrivateKey::try_new([1; 32]).unwrap();
    let sponsor = PrivateKey::try_new([3; 32]).unwrap();
    let forger = PrivateKey::try_new([4; 32]).unwrap();
    let sponsor_id = AccountId::from(&PublicKey::new_from_private_key(&sponsor));
    let fees = crate::FeeFields::new(sponsor_id, 60_000, 0, 1_000_000);

    // Control: a genuine sponsor signature deploys, and the payer is fee-authorized.
    let sponsored = deployment_tx(fees, |message| {
        WitnessSet::for_message(message, &[&deployer]).with_fee_signer(message, &sponsor)
    });
    assert!(crate::is_fee_authorized(
        sponsored.message(),
        sponsored.witness_set()
    ));
    let mut state = V03State::new();
    state
        .transition_from_program_deployment_transaction(&sponsored)
        .expect("a correctly sponsored deployment must apply");

    // The fee witness claims the sponsor's public key but was signed by somebody else.
    let forged = deployment_tx(fees, |message| {
        let mut witness_set = WitnessSet::for_message(message, &[&deployer]);
        witness_set.fee_witness = Some((
            crate::Signature::new(&forger, &message.hash()),
            PublicKey::new_from_private_key(&sponsor),
        ));
        witness_set
    });
    let mut fresh_state = V03State::new();
    assert!(
        matches!(
            fresh_state.transition_from_program_deployment_transaction(&forged),
            Err(LeeError::InvalidInput(_))
        ),
        "a forged fee witness must be rejected on the apply path"
    );
    assert!(fresh_state.programs().is_empty());
}

/// The existing unsigned-deployment shape stays valid: an empty witness set authorizes nobody but
/// is not itself a signature failure, so today's deployment flows keep working.
#[test]
fn deployment_without_a_witness_still_applies_but_authorizes_nobody() {
    let tx = deployment_tx(crate::FeeFields::ZERO, |_| {
        WitnessSet::from_raw_parts(vec![])
    });
    assert!(!crate::is_fee_authorized(tx.message(), tx.witness_set()));

    let mut state = V03State::new();
    state
        .transition_from_program_deployment_transaction(&tx)
        .expect("an unwitnessed deployment must still apply");
    assert_eq!(state.programs().len(), 1);
}
