use super::*;

const INITIAL_BALANCE: u128 = 1000;
const AMOUNT_OUT: u128 = 100;
const RECEIVER_SEED: PdaSeed = PdaSeed::new([1; 32]);

struct FlashSwap {
    state: V03State,
    vault_id: AccountId,
    receiver_id: AccountId,
    callback: Actor,
}

impl FlashSwap {
    fn new() -> Self {
        Self::with_callback(crate::test_methods::flash_swap_callback())
    }

    fn with_callback(callback: Program) -> Self {
        let initiator = crate::test_methods::flash_swap_initiator();
        let callback_id = AccountId::from_builtin_program(callback.id());

        let vault_id = AccountId::for_public_pda(
            &AccountId::from_builtin_program(initiator.id()),
            &PdaSeed::new([0; 32]),
        );
        let receiver_id = AccountId::for_public_pda(&callback_id, &RECEIVER_SEED);

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
        self.submit(&self.loan(amount_out, vault_balance, &callback_message))
    }

    fn loan(
        &self,
        amount_out: u128,
        vault_balance: u128,
        callback_message: &impl BorshSerialize,
    ) -> FlashSwapMessage {
        FlashSwapMessage::Initiate {
            vault: self.vault_id,
            receiver: self.receiver_id,
            callback: self.callback,
            amount_out,
            vault_balance,
            callback_message: borsh::to_vec(callback_message).unwrap(),
        }
    }

    fn submit(&mut self, message: &FlashSwapMessage) -> Result<Vec<TransactionEvent>, LeeError> {
        let tx = flash_swap_tx(self.vault_id, self.receiver_id, self.callback, message);
        self.state.transition_from_public_transaction(&tx, 1, 0)
    }

    fn initiator(&self) -> Actor {
        Actor::new(
            self.vault_id,
            AccountId::from_builtin_program(crate::test_methods::flash_swap_initiator().id()),
        )
    }

    fn repay(&self, amount: u128) -> Call {
        lee_core::native_token::custody_transfer(
            self.receiver_id,
            RECEIVER_SEED,
            self.vault_id,
            amount,
        )
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

fn assert_initiator_refused(result: &Result<Vec<TransactionEvent>, LeeError>, reason: &str) {
    assert!(
        matches!(result, Err(LeeError::ProgramExecutionFailed(message)) if message.contains(reason)),
        "expected the initiator to refuse with {reason:?}, got {result:?}"
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

    // The second vault read finds the loan unpaid → entire tx rolls back.
    assert_initiator_refused(&result, "the vault must end where it started");
    swap.assert_balances(INITIAL_BALANCE, 0);
}

#[test]
fn flash_swap_stale_vault_balance_proposal_rejected() {
    let mut swap = FlashSwap::new();

    // Callback returns funds correctly — only the proposed vault balance is wrong.
    let result = swap.initiate(Some(AMOUNT_OUT), AMOUNT_OUT, INITIAL_BALANCE + 1);

    // The first vault read rejects the mismatched proposal → entire tx rolls back.
    assert_initiator_refused(&result, "the vault must hold the proposed balance");
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
fn flash_swap_unsolicited_reply_rejected() {
    // A genuine native reply that no pending read asked for must not drive the initiator.
    let mut swap = FlashSwap::new();
    let initiator = swap.initiator();
    let vault = Actor::native_balance(swap.vault_id);
    let tx = public_tx(
        vault,
        vec![vault, initiator],
        vec![],
        NativeMessage::ReadState(ReadState {
            reply_to: initiator,
        }),
        &[],
    );

    let result = swap.state.transition_from_public_transaction(&tx, 1, 0);
    assert_initiator_refused(&result, "a reply must answer a pending read");
}

#[test]
fn a_callback_may_start_a_nested_flash_swap() {
    let mut swap = FlashSwap::with_callback(crate::test_methods::scripted());
    // The outer callback borrows again from the same initiator before repaying its own loan.
    let inner = swap.loan(
        50,
        INITIAL_BALANCE - AMOUNT_OUT,
        &Script::default().send(swap.repay(50)),
    );
    let outer = swap.loan(
        AMOUNT_OUT,
        INITIAL_BALANCE,
        &Script::default()
            .call(swap.initiator(), &inner)
            .send(swap.repay(AMOUNT_OUT)),
    );

    let result = swap.submit(&outer);

    assert!(
        result.is_ok(),
        "both nested loans should be repaid: {result:?}"
    );
    swap.assert_balances(INITIAL_BALANCE, 0);
}

#[test]
fn a_callback_injecting_a_vault_reply_is_rolled_back() {
    let mut swap = FlashSwap::with_callback(crate::test_methods::scripted());
    // Having repaid, the callback has the vault answer the initiator before its own second read.
    let inject = Call::new(
        Actor::native_balance(swap.vault_id),
        &NativeMessage::ReadState(ReadState {
            reply_to: swap.initiator(),
        }),
    );
    let loan = swap.loan(
        AMOUNT_OUT,
        INITIAL_BALANCE,
        &Script::default().send(swap.repay(AMOUNT_OUT)).send(inject),
    );

    let result = swap.submit(&loan);

    assert_initiator_refused(&result, "a reply must answer a pending read");
    swap.assert_balances(INITIAL_BALANCE, 0);
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
