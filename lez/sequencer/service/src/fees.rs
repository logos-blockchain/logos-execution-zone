//! Fee admission and pricing for the RPC ingest path.
//!
//! Admission is **anti-spam, not consensus**: the block transition
//! (`chain_state::check_charged_tx`) and the block builder are what actually enforce these rules.
//! What this adds is a door: a transaction no block can ever include is turned away at submission
//! instead of sitting in the mempool, and a client is told which rule it broke instead of watching
//! its transaction silently never land. The rejection itself is a
//! [`sequencer_service_protocol::AdmissionRejection`], so a client reads the values that decided it
//! out of the error's `data` field rather than out of prose.
//!
//! Two of the checks are advisory by nature. Base fees move every block and balances move every
//! transaction, so `max_fee >= fee_reserve` and "the payer can fund the reserve" are judged against
//! the head state at submission time and can go stale either way afterwards. The rest are static
//! properties of the transaction and cannot.

use chain_state::charged_fee_view;
use common::transaction::LeeTransaction;
use fee_core::{
    FeeError, FeeState, FeeTxView, InvalidBlockError, PayerId, fee_reserve,
    params::{MAX_GAS_EXEC, MAX_GAS_STOR},
    stepped_base_fees, validate_static_tx,
};
use jsonrpsee::types::ErrorObjectOwned;
use sequencer_core::BlockResource;
use sequencer_service_protocol::{AdmissionRejection, CapResource, FeeStateQuote};

/// The JSON-RPC error a rejection is returned as: its own code, the rendered reason, and the
/// rejection itself in `data` for a client that would rather not parse the reason.
#[must_use]
pub fn rejection_error(rejection: &AdmissionRejection) -> ErrorObjectOwned {
    ErrorObjectOwned::owned(rejection.code(), rejection.to_string(), Some(rejection))
}

/// Screens a submitted transaction against the head state.
///
/// Fee-exempt classes skip the charged checks — the full vault sweep is exactly the transaction of
/// an account that cannot yet pay. The cap check covers every class that consumes block space,
/// which is all of them *except* system transactions: those are cap-exempt here for the same reason
/// the block transition's `validate_block_storage_cap` skips them. A system-shaped transaction
/// therefore passes both, bounded only by the request's size check (see the note on
/// `common::transaction::is_system_transaction`).
///
/// # Errors
///
/// The first check that fails, with what it compared.
pub fn screen(tx: &LeeTransaction, state: &lee::V03State) -> Result<(), AdmissionRejection> {
    // Classification decodes the transaction, so it is done once here and threaded onward.
    let charged = charged_fee_view(tx, state);
    if let Some(view) = charged {
        let LeeTransaction::Public(public_tx) = tx else {
            unreachable!("only public transactions are charged");
        };
        screen_charged(public_tx, &view, state)?;
    }

    // The builder's own pre-screen and this one read the same bound, so nothing admitted here is
    // dropped there as unbuildable.
    if let Some(bound) = sequencer_core::static_cap_bound(tx, state, charged)
        && let Some(resource) = sequencer_core::exceeds_empty_block(bound)
    {
        return Err(AdmissionRejection::ExceedsBlockCap {
            resource: match resource {
                BlockResource::ExecutionGas => CapResource::ExecutionGas,
                BlockResource::StorageGas => CapResource::StorageGas,
            },
            gas_exec: bound.gas_exec,
            gas_stor: bound.gas_stor,
            max_gas_exec: MAX_GAS_EXEC,
            max_gas_stor: MAX_GAS_STOR,
        });
    }

    Ok(())
}

/// The charged-transaction checks, in the order `chain_state::check_charged_tx` runs them, plus
/// the payer-balance check that only a live head state can answer.
fn screen_charged(
    public_tx: &lee::PublicTransaction,
    view: &FeeTxView,
    state: &lee::V03State,
) -> Result<(), AdmissionRejection> {
    let fee_state = state.fee_state();

    if let Err(err) = validate_static_tx(view, fee_state) {
        return Err(static_rejection(err));
    }

    if public_tx
        .witness_set()
        .signatures_and_public_keys()
        .is_empty()
    {
        return Err(AdmissionRejection::FeeWitnessOnly);
    }

    let payer = public_tx.message().payer;
    if !lee::is_fee_authorized(public_tx.message(), public_tx.witness_set()) {
        return Err(AdmissionRejection::UnauthorizedPayer { payer });
    }

    let fee_reserve = fee_reserve(view, fee_state);
    let balance = state.get_account_by_id(payer).balance;
    if balance < fee_reserve {
        return Err(AdmissionRejection::PayerCannotFund {
            payer,
            balance,
            fee_reserve,
        });
    }

    Ok(())
}

/// One static fee-validity failure, as the rejection carrying its comparands.
///
/// `validate_static_tx` produces only the four arms named below; the rest of `fee_core`'s error
/// enum belongs to block-level checks admission never runs, and falls through to the catch-all so
/// the mapping stays total without a wildcard.
fn static_rejection(err: FeeError) -> AdmissionRejection {
    let FeeError::InvalidBlock(invalid) = err else {
        return AdmissionRejection::OtherFeeValidity {
            reason: err.to_string(),
        };
    };
    match invalid {
        InvalidBlockError::EmptyDataBytes => AdmissionRejection::EmptyDataBytes,
        InvalidBlockError::DataBytesExceedsMax { data_bytes, max } => {
            AdmissionRejection::DataBytesExceedsMax { data_bytes, max }
        }
        InvalidBlockError::GasLimitExceedsMax { gas_limit, max } => {
            AdmissionRejection::GasLimitExceedsMax { gas_limit, max }
        }
        InvalidBlockError::FeeReserveExceedsMaxFee {
            fee_reserve,
            max_fee,
        } => AdmissionRejection::MaxFeeBelowReserve {
            fee_reserve,
            max_fee,
        },
        InvalidBlockError::StorageCapExceeded { .. }
        | InvalidBlockError::GasCapExceeded { .. }
        | InvalidBlockError::GasAccumulationOverflow
        | InvalidBlockError::UnauthorizedPayer
        | InvalidBlockError::EmptyPublicSignerSet => AdmissionRejection::OtherFeeValidity {
            reason: invalid.to_string(),
        },
    }
}

/// Prices the next block off `fee_state`.
///
/// The next-block figures are a band rather than a single estimate: the block being filled is not
/// observable at query time, so what is quoted is one update step at an empty block and one at a
/// block filled to its caps. Every possible next-block base fee lies between them, which is
/// exactly what a wallet needs to size `max_fee` for a transaction that may wait. Both steps go
/// through the same `fee_core` helper the block transition moves the real fee state with.
#[must_use]
pub fn fee_quote(fee_state: &FeeState) -> FeeStateQuote {
    let (exec_floor, stor_floor) = stepped_base_fees(fee_state, 0, 0);
    let (exec_ceiling, stor_ceiling) = stepped_base_fees(fee_state, MAX_GAS_EXEC, MAX_GAS_STOR);

    FeeStateQuote {
        base_fee_exec: fee_state.base_fee_exec,
        base_fee_stor: fee_state.base_fee_stor,
        next_base_fee_exec_floor: exec_floor,
        next_base_fee_exec_ceiling: exec_ceiling,
        next_base_fee_stor_floor: stor_floor,
        next_base_fee_stor_ceiling: stor_ceiling,
        // A private transaction's gas is protocol constants, so its price depends on nothing but
        // the base fees; the payer here is the placeholder `fee_reserve` ignores for that arm.
        private_fee_quote: fee_reserve(
            &FeeTxView::Private {
                payer: PayerId([0_u8; 32]),
            },
            fee_state,
        ),
        max_gas_exec: MAX_GAS_EXEC,
        max_gas_stor: MAX_GAS_STOR,
    }
}

#[cfg(test)]
mod tests {
    use common::test_utils::{
        TEST_GAS_LIMIT, create_transaction_native_token_transfer,
        create_transaction_native_token_transfer_with_fees, test_fee_fields,
    };
    use lee::{
        AccountId, FeeFields, PrivateKey, PublicKey, V03State, program_deployment_transaction,
        public_transaction::{Message, WitnessSet},
    };
    use testnet_initial_state::{initial_pub_accounts_private_keys, initial_state};

    use super::*;

    fn key(seed: u8) -> PrivateKey {
        PrivateKey::try_new([seed; 32]).expect("valid key")
    }

    fn account_of(private_key: &PrivateKey) -> AccountId {
        AccountId::from(&PublicKey::new_from_private_key(private_key))
    }

    /// A funded account of the initial state, and the key that signs for it.
    fn funded() -> (AccountId, PrivateKey) {
        let accounts = initial_pub_accounts_private_keys();
        (accounts[0].account_id, accounts[0].pub_sign_key.clone())
    }

    fn recipient() -> AccountId {
        initial_pub_accounts_private_keys()[1].account_id
    }

    fn wire_size(tx: &LeeTransaction) -> u64 {
        u64::try_from(borsh::object_length(tx).expect("serializes")).expect("fits")
    }

    /// What the consensus gate says about the same transaction, for the checks both run.
    fn consensus_verdict(tx: &LeeTransaction, state: &V03State) -> Result<(), String> {
        let view = charged_fee_view(tx, state).expect("charged");
        let LeeTransaction::Public(public_tx) = tx else {
            unreachable!("only public transactions are charged");
        };
        chain_state::check_charged_tx(public_tx, &view, state.fee_state())
    }

    #[test]
    fn a_funded_transfer_is_admitted() {
        let state = initial_state();
        let (from, sign_key) = funded();
        let tx = create_transaction_native_token_transfer(from, 0, recipient(), 10, &sign_key);

        screen(&tx, &state).expect("a well-formed, funded transfer is admitted");
        // Admission must be at least as strict as the gate the builder and the block transition
        // run, so nothing it admits is unbuildable.
        consensus_verdict(&tx, &state).expect("and the consensus gate agrees");
    }

    #[test]
    fn a_gas_limit_beyond_the_block_cap_is_rejected() {
        let state = initial_state();
        let (from, sign_key) = funded();
        let tx = create_transaction_native_token_transfer_with_fees(
            from,
            0,
            recipient(),
            10,
            &sign_key,
            FeeFields::new(from, MAX_GAS_EXEC + 1, 0, u128::MAX),
        );

        let err = screen(&tx, &state).expect_err("no block can execute that much gas");
        assert!(
            matches!(
                err,
                AdmissionRejection::GasLimitExceedsMax {
                    gas_limit,
                    max: MAX_GAS_EXEC,
                } if gas_limit == MAX_GAS_EXEC + 1,
            ),
            "expected the gas-limit bound to fire, got: {err}",
        );
        assert!(consensus_verdict(&tx, &state).is_err());
    }

    #[test]
    fn a_max_fee_below_the_reserve_is_rejected() {
        let state = initial_state();
        let (from, sign_key) = funded();
        let tx = create_transaction_native_token_transfer_with_fees(
            from,
            0,
            recipient(),
            10,
            &sign_key,
            FeeFields::new(from, TEST_GAS_LIMIT, 7, 1),
        );

        let fee_state = state.fee_state();
        let expected = u128::from(TEST_GAS_LIMIT) * u128::from(fee_state.base_fee_exec)
            + u128::from(wire_size(&tx)) * u128::from(fee_state.base_fee_stor)
            + 7;

        let err = screen(&tx, &state).expect_err("a max_fee of 1 covers nothing");
        assert!(
            matches!(
                err,
                AdmissionRejection::MaxFeeBelowReserve {
                    fee_reserve,
                    max_fee: 1,
                } if fee_reserve == expected,
            ),
            "expected the reserve {expected} against a max_fee of 1, got: {err}",
        );
        assert!(consensus_verdict(&tx, &state).is_err());
    }

    /// The payer is authorized (it signs as the fee witness) but holds nothing, so the reservation
    /// the next block would take cannot succeed.
    #[test]
    fn a_payer_that_cannot_fund_the_reserve_is_rejected() {
        let state = initial_state();
        let (from, sign_key) = funded();
        let sponsor = key(9);
        let message = Message::try_new(
            programs::authenticated_transfer().id(),
            vec![from, recipient()],
            vec![0_u128.into()],
            authenticated_transfer_core::Instruction::Transfer { amount: 10 },
            FeeFields::new(account_of(&sponsor), TEST_GAS_LIMIT, 0, u128::MAX),
        )
        .expect("message builds");
        let witness_set =
            WitnessSet::for_message(&message, &[&sign_key]).with_fee_signer(&message, &sponsor);
        let tx = LeeTransaction::Public(lee::PublicTransaction::new(message, witness_set));

        let err = screen(&tx, &state).expect_err("a sponsor with no balance cannot fund it");
        assert!(
            matches!(
                err,
                AdmissionRejection::PayerCannotFund {
                    payer,
                    balance: 0,
                    ..
                } if payer == account_of(&sponsor),
            ),
            "expected an unfundable payer, got: {err}",
        );
        // Balance is not the consensus gate's business: this one is admission-only, and the block
        // transition rejects it later at the reservation itself.
        consensus_verdict(&tx, &state).expect("the static gate has nothing against it");
    }

    /// Fee-witness-only: nothing but the payer's fee authorization accompanies the transaction, so
    /// including it would burn no nonce and it would stay includable for ever.
    #[test]
    fn a_fee_witness_only_transaction_is_rejected() {
        let state = initial_state();
        let (from, sign_key) = funded();
        let message = Message::try_new(
            programs::authenticated_transfer().id(),
            vec![from, recipient()],
            vec![0_u128.into()],
            authenticated_transfer_core::Instruction::Transfer { amount: 10 },
            test_fee_fields(from),
        )
        .expect("message builds");
        // No signer signatures at all: the payer's fee witness is the only one.
        let witness_set = WitnessSet::from_raw_parts(vec![]).with_fee_signer(&message, &sign_key);
        let tx = LeeTransaction::Public(lee::PublicTransaction::new(message, witness_set));

        let err = screen(&tx, &state).expect_err("a fee witness alone authorizes no state access");
        assert!(
            matches!(err, AdmissionRejection::FeeWitnessOnly),
            "expected the fee-witness-only rejection, got: {err}",
        );
        assert!(
            consensus_verdict(&tx, &state).is_err(),
            "and the consensus gate rejects it too, only later",
        );
    }

    #[test]
    fn a_payer_nothing_authorizes_is_rejected() {
        let state = initial_state();
        let (from, sign_key) = funded();
        let stranger = account_of(&key(9));
        let tx = create_transaction_native_token_transfer_with_fees(
            from,
            0,
            recipient(),
            10,
            &sign_key,
            FeeFields::new(stranger, TEST_GAS_LIMIT, 0, u128::MAX),
        );

        let err = screen(&tx, &state).expect_err("nobody authorized the stranger to pay");
        assert!(
            matches!(err, AdmissionRejection::UnauthorizedPayer { payer } if payer == stranger),
            "expected an unauthorized payer, got: {err}",
        );
        assert!(consensus_verdict(&tx, &state).is_err());
    }

    /// The bootstrap case: a full vault sweep is fee-exempt, so none of the charged checks may run
    /// against it — its whole point is that the sweeper holds nothing yet.
    #[test]
    fn a_full_vault_sweep_by_an_unfunded_account_is_admitted() {
        let mut state = initial_state();
        let sweeper_key = key(9);
        let sweeper = account_of(&sweeper_key);
        let vault_id = vault_core::compute_vault_account_id(programs::vault().id(), sweeper);
        state.force_insert_account(
            vault_id,
            lee::Account {
                program_owner: programs::vault().id(),
                balance: 500_000_000,
                ..lee::Account::default()
            },
        );

        let message = Message::try_new(
            programs::vault().id(),
            vec![sweeper, vault_id],
            vec![0_u128.into()],
            vault_core::Instruction::Claim {
                amount: 500_000_000,
            },
            // A sweep is exempt whatever it declares, and a wallet with nothing to pay with signs
            // a zero `max_fee`: neither the reserve check nor the balance check may see this.
            FeeFields::new(sweeper, TEST_GAS_LIMIT, 0, 0),
        )
        .expect("message builds");
        let witness_set = WitnessSet::for_message(&message, &[&sweeper_key]);
        let tx = LeeTransaction::Public(lee::PublicTransaction::new(message, witness_set));

        assert!(
            charged_fee_view(&tx, &state).is_none(),
            "a full sweep is fee-exempt",
        );
        screen(&tx, &state).expect("so admission must let it through");
    }

    /// A private transaction is uncharged but capped. Its *execution* gas is the protocol constant
    /// `PRIVATE_VERIFY_GAS`, so whether any private transaction clears that cap is a property of
    /// the constant rather than of the transaction; its storage gas is still its real serialized
    /// length (`chain_state::classify`, TBA(INCREMENTIAL)), so the storage assertion below guards
    /// the re-pin to `PRIVATE_GAS_STOR` rather than pinning what runs today. Either constant
    /// re-pinned past its cap would make every private transaction permanently inadmissible, and
    /// nothing else in the tree would notice.
    #[test]
    fn a_private_transaction_is_admitted_and_its_constants_fit_a_block() {
        use lee::privacy_preserving_transaction::{
            Message as PrivateMessage, PrivacyPreservingTransaction,
            WitnessSet as PrivateWitnessSet, circuit::Proof,
        };
        use lee_core::program::{BlockValidityWindow, TimestampValidityWindow};

        const {
            assert!(
                fee_core::params::PRIVATE_VERIFY_GAS <= MAX_GAS_EXEC,
                "a private transaction's constant execution gas must fit a block",
            );
            assert!(
                fee_core::params::PRIVATE_GAS_STOR <= MAX_GAS_STOR,
                "and so must its constant storage gas",
            );
        }

        let state = initial_state();
        let tx = LeeTransaction::PrivacyPreserving(PrivacyPreservingTransaction::new(
            PrivateMessage {
                public_actions: vec![],
                nonces: vec![],
                private_actions: vec![],
                block_validity_window: BlockValidityWindow::new_unbounded(),
                timestamp_validity_window: TimestampValidityWindow::new_unbounded(),
            },
            PrivateWitnessSet::from_raw_parts(vec![], Proof::from_inner(vec![])),
        ));

        assert!(
            charged_fee_view(&tx, &state).is_none(),
            "private transactions are uncharged today",
        );
        screen(&tx, &state).expect("and admissible: no fee field of theirs is screened");
    }

    /// System transactions are fee-exempt *and* cap-exempt, here as in the block transition
    /// (`validate_block_storage_cap` skips them too), so admission has nothing to compare and lets
    /// one through unscreened — the arm neither check reaches.
    ///
    /// Built the way a *user* would: the shape is craftable and the classification is structural,
    /// so this also pins the accepted consequence documented on `is_system_transaction` — an
    /// unsigned deposit-shaped transaction rides free, bounded only by the ingest size check, and
    /// is then rejected by the bridge program for not matching a real L1 event.
    #[test]
    fn a_system_shaped_transaction_is_admitted_unscreened() {
        let state = initial_state();
        let recipient = account_of(&key(9));
        let message = Message::try_new(
            programs::bridge().id(),
            vec![
                system_accounts::bridge_account_id(),
                vault_core::compute_vault_account_id(programs::vault().id(), recipient),
                bridge_core::deposit_receipt_account_id(programs::bridge().id(), [7_u8; 32]),
            ],
            vec![],
            bridge_core::Instruction::Deposit {
                l1_deposit_op_id: [7_u8; 32],
                vault_program_id: programs::vault().id(),
                recipient_id: recipient,
                amount: 1_000,
            },
            FeeFields::ZERO,
        )
        .expect("message builds");
        // Unsigned: what makes it system-shaped, and what a sequencer injection looks like.
        let tx = LeeTransaction::Public(lee::PublicTransaction::new(
            message,
            WitnessSet::from_raw_parts(vec![]),
        ));

        assert!(common::transaction::is_system_transaction(&tx));
        assert!(charged_fee_view(&tx, &state).is_none());
        assert!(
            sequencer_core::static_cap_bound(&tx, &state, None).is_none(),
            "cap-exempt, so the cap check has nothing to compare either",
        );
        screen(&tx, &state).expect("nothing to screen");
    }

    /// Uncharged is not uncapped: a deployment that no block could carry is turned away at the
    /// door, where before it would have sat in the mempool for ever.
    #[test]
    fn an_uncharged_transaction_over_the_storage_cap_is_rejected() {
        let state = initial_state();
        let deployer = key(9);
        let message = program_deployment_transaction::Message::new(
            vec![0_u8; usize::try_from(MAX_GAS_STOR).expect("fits") + 1],
            FeeFields::new(account_of(&deployer), 0, 0, 0),
        );
        let witness_set = WitnessSet::for_message(&message, &[&deployer]);
        let tx = LeeTransaction::ProgramDeployment(lee::ProgramDeploymentTransaction::new(
            message,
            witness_set,
        ));

        assert!(
            charged_fee_view(&tx, &state).is_none(),
            "deployments are not charged today",
        );
        let err = screen(&tx, &state).expect_err("but they are capped");
        assert!(
            matches!(
                err,
                AdmissionRejection::ExceedsBlockCap {
                    resource: CapResource::StorageGas,
                    ..
                }
            ),
            "expected the storage cap to be the one that fired, got: {err}",
        );
    }

    /// SPECS §Overview worked example: at the genesis base fees of 8/8 a private transaction's
    /// fixed gas prices out at 5,070,616, and the next block's fees can only stay at the minimum
    /// or rise by the guaranteed +1 step.
    #[test]
    fn the_quote_prices_the_head_fee_state() {
        let state = initial_state();
        let quote = fee_quote(state.fee_state());

        assert_eq!(quote.base_fee_exec, 8);
        assert_eq!(quote.base_fee_stor, 8);
        assert_eq!(quote.next_base_fee_exec_floor, 8);
        assert_eq!(quote.next_base_fee_exec_ceiling, 9);
        assert_eq!(quote.next_base_fee_stor_floor, 8);
        assert_eq!(quote.next_base_fee_stor_ceiling, 9);
        assert_eq!(quote.private_fee_quote, 5_070_616);
        assert_eq!(quote.max_gas_exec, MAX_GAS_EXEC);
        assert_eq!(quote.max_gas_stor, MAX_GAS_STOR);
    }

    /// The quote is what a wallet prices `max_fee` off, so the reserve it computes from those two
    /// numbers must be the one admission compares against.
    #[test]
    fn a_reserve_computed_from_the_quote_matches_the_one_admission_uses() {
        let state = initial_state();
        let (from, sign_key) = funded();
        let tx = create_transaction_native_token_transfer_with_fees(
            from,
            0,
            recipient(),
            10,
            &sign_key,
            FeeFields::new(from, TEST_GAS_LIMIT, 3, u128::MAX),
        );
        let quote = fee_quote(state.fee_state());

        let by_hand = u128::from(TEST_GAS_LIMIT) * u128::from(quote.base_fee_exec)
            + u128::from(wire_size(&tx)) * u128::from(quote.base_fee_stor)
            + 3;
        let view = charged_fee_view(&tx, &state).expect("charged");
        assert_eq!(fee_reserve(&view, state.fee_state()), by_hand);

        // One unit of headroom below it is exactly what admission rejects.
        let too_tight = create_transaction_native_token_transfer_with_fees(
            from,
            0,
            recipient(),
            10,
            &sign_key,
            FeeFields::new(from, TEST_GAS_LIMIT, 3, by_hand - 1),
        );
        assert!(matches!(
            screen(&too_tight, &state).expect_err("one unit short"),
            AdmissionRejection::MaxFeeBelowReserve { .. }
        ));
        screen(&tx, &state).expect("and the same transaction with room to spare is admitted");
    }
}
