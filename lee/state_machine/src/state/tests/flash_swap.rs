use super::*;

const INITIAL_BALANCE: u128 = 1000;
const AMOUNT_OUT: u128 = 100;

struct FlashSwap {
    state: V03State,
    vault_id: AccountId,
    receiver_id: AccountId,
    callback: Actor,
}

impl FlashSwap {
    fn new() -> Self {
        let initiator = crate::test_methods::flash_swap_initiator();
        let callback = crate::test_methods::flash_swap_callback();
        let callback_id = AccountId::from_builtin_program(callback.id());

        let vault_id = AccountId::for_public_pda(
            &AccountId::from_builtin_program(initiator.id()),
            &PdaSeed::new([0; 32]),
        );
        let receiver_id = AccountId::for_public_pda(&callback_id, &PdaSeed::new([1; 32]));

        let mut state = V03State::new().with_programs([callback, initiator]);
        state.force_insert_account(vault_id, Account::funded(INITIAL_BALANCE));
        state.force_insert_account(receiver_id, Account::default());

        Self {
            state,
            vault_id,
            receiver_id,
            callback: Actor::new(receiver_id, callback_id),
        }
    }

    fn initiate(
        &mut self,
        returned: Option<u128>,
        amount_out: u128,
        vault_balance: u128,
    ) -> Result<Vec<TransactionEvent>, LeeError> {
        let callback_message = CallbackMessage {
            return_funds: returned.is_some(),
            amount: returned.unwrap_or_default(),
            vault: self.vault_id,
            receiver: self.receiver_id,
        };
        let message = FlashSwapMessage::Initiate {
            vault: self.vault_id,
            receiver: self.receiver_id,
            callback: self.callback,
            amount_out,
            vault_balance,
            callback_message: borsh::to_vec(&callback_message).unwrap(),
        };
        let tx = flash_swap_tx(self.vault_id, self.receiver_id, self.callback, &message);
        self.state.transition_from_public_transaction(&tx, 1, 0)
    }

    fn assert_balances(&self, vault: u128, receiver: u128) {
        assert_eq!(
            self.state
                .get_account_by_id(self.vault_id)
                .data
                .native_balance(),
            Ok(vault)
        );
        assert_eq!(
            self.state
                .get_account_by_id(self.receiver_id)
                .data
                .native_balance(),
            Ok(receiver)
        );
    }
}

fn assert_vault_pin_failed(
    result: &Result<Vec<TransactionEvent>, LeeError>,
    vault_id: AccountId,
    expected: u128,
    actual: u128,
) {
    assert!(
        matches!(
            result,
            Err(LeeError::InvalidProgramBehavior(
                InvalidProgramBehaviorError::NativeTransferFailed(TransferError::BalanceMismatch {
                    account_id,
                    expected: pinned,
                    actual: held,
                })
            )) if *account_id == vault_id && *pinned == expected && *held == actual
        ),
        "expected the vault pin {expected} to fail against {actual}, got {result:?}"
    );
}

#[test]
fn flash_swap_successful() {
    let mut swap = FlashSwap::new();

    let result = swap.initiate(Some(AMOUNT_OUT), AMOUNT_OUT, INITIAL_BALANCE);

    assert!(result.is_ok(), "flash swap should succeed: {result:?}");
    // Vault balance restored, receiver back to 0
    swap.assert_balances(INITIAL_BALANCE, 0);
}

#[test_case::test_case(None; "returned nothing")]
#[test_case::test_case(Some(40); "returned less than taken")]
fn flash_swap_callback_keeps_funds_rollback(returned: Option<u128>) {
    let mut swap = FlashSwap::new();

    let result = swap.initiate(returned, AMOUNT_OUT, INITIAL_BALANCE);

    // The invariant's exact pin fails → entire tx rolls back.
    assert_vault_pin_failed(
        &result,
        swap.vault_id,
        INITIAL_BALANCE,
        INITIAL_BALANCE - AMOUNT_OUT + returned.unwrap_or_default(),
    );
    swap.assert_balances(INITIAL_BALANCE, 0);
}

#[test]
fn flash_swap_stale_vault_balance_proposal_rejected() {
    let mut swap = FlashSwap::new();

    // Callback returns funds correctly — only the proposed vault balance is wrong.
    let result = swap.initiate(Some(AMOUNT_OUT), AMOUNT_OUT, INITIAL_BALANCE + 1);

    // The guard rejects the mismatched proposal → entire tx rolls back.
    assert_vault_pin_failed(&result, swap.vault_id, INITIAL_BALANCE + 1, INITIAL_BALANCE);
    swap.assert_balances(INITIAL_BALANCE, 0);
}

#[test]
fn flash_swap_self_call_targets_correct_program() {
    // Zero-amount flash swap: the invariant self-send still runs and succeeds
    // because vault balance doesn't decrease.
    let mut swap = FlashSwap::new();

    let result = swap.initiate(Some(0), 0, INITIAL_BALANCE);

    assert!(
        result.is_ok(),
        "zero-amount flash swap should succeed: {result:?}"
    );
}

#[test]
fn flash_swap_standalone_invariant_check_rejected() {
    // Sending InvariantCheck directly (not as a self-send) should fail because its origin is
    // the root, not the initiator itself.
    let mut swap = FlashSwap::new();
    let initiator = Actor::new(
        swap.vault_id,
        AccountId::from_builtin_program(crate::test_methods::flash_swap_initiator().id()),
    );
    let tx = public_tx(
        initiator,
        vec![
            initiator,
            Actor::native_balance(swap.vault_id),
            Actor::native_balance(swap.receiver_id),
        ],
        vec![],
        FlashSwapMessage::InvariantCheck {
            vault: swap.vault_id,
            receiver: swap.receiver_id,
            vault_balance: INITIAL_BALANCE,
        },
        &[],
    );

    let result = swap.state.transition_from_public_transaction(&tx, 1, 0);
    assert!(
        matches!(result, Err(LeeError::ProgramExecutionFailed(_))),
        "standalone InvariantCheck should be rejected (origin is the root): {result:?}"
    );
}

fn forged_echo_result(field: ForgeField) -> Result<Vec<TransactionEvent>, LeeError> {
    let program_id = AccountId::from_builtin_program(crate::test_methods::forges_echo().id());
    let actor = Actor::new(AccountId::new([99; 32]), program_id);
    let mut state = V03State::new().with_programs([crate::test_methods::forges_echo()]);

    let tx = public_tx(actor, vec![actor], vec![], field, &[]);

    state.transition_from_public_transaction(&tx, 1, 0)
}

fn assert_forged_echo_rejected(result: &Result<Vec<TransactionEvent>, LeeError>) {
    let program_id = AccountId::from_builtin_program(crate::test_methods::forges_echo().id());
    assert!(
        matches!(
            result,
            Err(LeeError::InvalidProgramBehavior(InvalidProgramBehaviorError::Execution(
                ExecutionError::ExecutionValidation {
                    program_account_id,
                    source: ExecutionValidationError::TransitionInputMismatch { .. },
                }
            ))) if *program_account_id == program_id
        ),
        "expected the forged echo to be rejected, got {result:?}"
    );
}

#[test]
fn malicious_self_program_id_rejected_in_public_execution() {
    assert_forged_echo_rejected(&forged_echo_result(ForgeField::Receiver));
}

#[test]
fn malicious_caller_program_id_rejected_in_public_execution() {
    assert_forged_echo_rejected(&forged_echo_result(ForgeField::Origin));
}
