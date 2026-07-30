use std::borrow::Cow;

use super::*;
use token_core::{Instruction, TokenHolding};

/// `programs::token()` returns a `Program` from a second, independent compilation of this same
/// `lee` crate (pulled in transitively through the `programs` dev-dependency), which is a
/// structurally identical but nominally different type from the one this test binary's own code
/// uses — passing it directly to `with_programs`/`execute_and_prove` fails to type-check
/// ("multiple different versions of crate `lee`"). Re-wrapping the id and raw ELF bytes in our
/// own `Program` sidesteps that; `amm`'s tests avoid the issue entirely by only ever reading
/// `.id()` off `programs::X()`, never the `Program` value itself.
fn real_token_program() -> Program {
    let foreign = programs::token();
    Program::new_unchecked(foreign.id(), Cow::Owned(foreign.elf().to_vec()))
}

/// A deshielded transfer's proof is generated against the public recipient's `data` (its token
/// holding) at proving time. If a public token transfer changes that account's holding before
/// the deshielded transfer lands on chain, the proof no longer matches the account's actual (now
/// stale) pre-state and must be rejected — none of its nullifiers or commitments may be applied.
///
/// Same race as
/// `privacy_preserving::transition_from_privacy_preserving_transaction_deshielded_fails_on_stale_public_prestate`,
/// but exercised against the real `token` program, where the moved value lives in `Account.data`
/// (a borsh-encoded `TokenHolding`) rather than in `Account.balance`.
#[test]
fn token_deshielded_transfer_fails_on_stale_public_data_prestate() {
    let token_program = real_token_program();
    let token_program_id = token_program.id();
    let definition_id = AccountId::new([9; 32]);

    let holding_account = |balance: u128| Account {
        program_owner: token_program_id,
        balance: 0,
        nonce: Nonce(0),
        data: Data::from(&TokenHolding::Fungible {
            definition_id,
            balance,
        }),
    };

    let sender_keys = test_private_account_keys_1();
    let sender_nonce = Nonce(0xdead_beef);
    let sender_private_account = Account {
        nonce: sender_nonce,
        ..holding_account(10)
    };

    let recipient_keys = test_public_account_keys_1();
    let payer_keys = test_public_account_keys_2();

    let mut state = V03State::new()
        .with_public_accounts([
            (recipient_keys.account_id(), holding_account(10)),
            (payer_keys.account_id(), holding_account(10)),
        ])
        .with_private_account(&sender_keys, &sender_private_account)
        .with_programs([token_program.clone()]);

    let amount_to_transfer = 5_u128;

    let sender_account_id =
        AccountId::for_regular_private_account(&sender_keys.npk(), &sender_keys.vpk(), 0);
    let sender_pre_commitment = Commitment::new(&sender_account_id, &sender_private_account);

    // Prove the deshielded token transfer while the recipient's holding still shows balance 10.
    // The proof binds this pre-state.
    let sender_pre = AccountWithMetadata::new(
        sender_private_account.clone(),
        true,
        (&sender_keys.npk(), &sender_keys.vpk(), 0),
    );
    let recipient_pre = AccountWithMetadata::new(
        state.get_account_by_id(recipient_keys.account_id()),
        false,
        recipient_keys.account_id(),
    );

    let (output, proof) = crate::privacy_preserving_transaction::circuit::execute_and_prove(
        vec![sender_pre, recipient_pre],
        Program::serialize_instruction(Instruction::Transfer {
            amount_to_transfer,
        })
        .unwrap(),
        vec![
            InputAccountIdentity::PrivateAuthorizedUpdate {
                vpk: sender_keys.vpk(),
                random_seed: [0; 32],
                view_tag: 0,
                nsk: sender_keys.nsk,
                membership_proof: state
                    .get_proof_for_commitment(&sender_pre_commitment)
                    .expect("sender's commitment must be in state"),
                identifier: 0,
            },
            InputAccountIdentity::Public,
        ],
        &token_program.into(),
    )
    .unwrap();

    let message =
        Message::try_from_circuit_output(vec![recipient_keys.account_id()], vec![], output)
            .unwrap();
    let witness_set = WitnessSet::for_message(&message, proof, &[]);
    let deshielding_tx = PrivacyPreservingTransaction::new(message, witness_set);

    let would_be_new_commitment = Commitment::new(
        &sender_account_id,
        &Account {
            data: Data::from(&TokenHolding::Fungible {
                definition_id,
                balance: 10 - amount_to_transfer,
            }),
            nonce: sender_nonce.private_account_nonce_increment(&sender_keys.nsk),
            ..sender_private_account.clone()
        },
    );
    let would_be_new_nullifier =
        Nullifier::for_account_update(&sender_pre_commitment, &sender_keys.nsk);

    // A public token transfer moves 5 from the payer to the recipient *before* the deshielding
    // transfer above is applied, invalidating the `data` pre-state the proof was generated
    // against.
    let public_message = public_transaction::Message::try_new(
        token_program_id,
        vec![payer_keys.account_id(), recipient_keys.account_id()],
        vec![Nonce(0)],
        Instruction::Transfer {
            amount_to_transfer,
        },
    )
    .unwrap();
    let public_witness_set =
        public_transaction::WitnessSet::for_message(&public_message, &[&payer_keys.signing_key]);
    let public_transfer = PublicTransaction::new(public_message, public_witness_set);

    state
        .transition_from_public_transaction(&public_transfer, 1, 0)
        .unwrap();

    let holding_of = |state: &V03State, id: AccountId| {
        TokenHolding::try_from(&state.get_account_by_id(id).data).unwrap()
    };
    assert_eq!(
        holding_of(&state, recipient_keys.account_id()),
        TokenHolding::Fungible {
            definition_id,
            balance: 15
        }
    );
    assert_eq!(
        holding_of(&state, payer_keys.account_id()),
        TokenHolding::Fungible {
            definition_id,
            balance: 5
        }
    );

    // The deshielding transfer's proof was generated against the recipient's stale holding
    // (balance 10), so it must now be rejected at the state level.
    let result = state.transition_from_privacy_preserving_transaction(&deshielding_tx, 2, 0);
    assert!(
        matches!(result, Err(LeeError::InvalidPrivacyPreservingProof)),
        "expected InvalidPrivacyPreservingProof for a stale public recipient data pre-state, got {result:?}"
    );

    // Holdings are exactly as the public transfer left them: the rejected deshielding transfer
    // had no effect.
    assert_eq!(
        holding_of(&state, recipient_keys.account_id()),
        TokenHolding::Fungible {
            definition_id,
            balance: 15
        }
    );
    assert_eq!(
        holding_of(&state, payer_keys.account_id()),
        TokenHolding::Fungible {
            definition_id,
            balance: 5
        }
    );

    // Neither the nullifier for the private sender's spent note nor the new commitment it would
    // have produced were applied to state.
    assert!(!state.private_state.1.contains(&would_be_new_nullifier));
    assert!(!state.private_state.0.contains(&would_be_new_commitment));
    // The sender's original (unspent) commitment is still present.
    assert!(state.private_state.0.contains(&sender_pre_commitment));
}
