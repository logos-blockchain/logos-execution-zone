//! Fee admission and pricing for the RPC ingest path.
//!
//! Admission is **anti-spam, not consensus**: the block transition
//! (`chain_state::apply::settle_charged_transaction`) enforces these rules
//! authoritatively. What this adds is a door — a transaction no block could
//! ever include is turned away at submission instead of sitting in the
//! mempool, and the client is told which rule it broke as a typed
//! [`AdmissionRejection`] instead of watching its transaction silently never
//! land.
//!
//! Two of the checks are advisory by nature: base fees move every block and
//! balances move every transaction, so the `max_fee >= fee_reserve` and
//! payer-affordability verdicts are judged against the head state at
//! submission time and can go stale either way afterwards. The rest are
//! static properties of the transaction and cannot.

use chain_state::{
    apply::opening_fee_state,
    classify::{ClassifyError, FeeClass, classify},
};
use common::transaction::LeeTransaction;
use fee_core::{
    assess::fee_reserve,
    market,
    validity::{FeeError, validate_static_tx},
};
use sequencer_service_protocol::{AdmissionRejection, FeeStateQuote};

/// Screens a submitted transaction against the head state.
///
/// The checks run in the order `settle_charged_transaction` runs the same
/// ones, plus the payer-affordability check that only a live state can
/// answer. Fee-exempt classes pass unscreened: exempt transactions pay
/// nothing and contribute nothing to the block gas totals under the interim
/// policy.
///
/// # Errors
///
/// The first check that fails, with the values that decided it.
pub fn screen(tx: &LeeTransaction, state: &lee::V03State) -> Result<(), AdmissionRejection> {
    let class = classify(tx, false, state).map_err(|err| match err {
        ClassifyError::Unserializable(err) => AdmissionRejection::OtherFeeValidity {
            reason: format!("unserializable transaction: {err}"),
        },
        ClassifyError::MissingFeeDeclaration => AdmissionRejection::MissingFeeDeclaration,
    })?;
    let FeeClass::Charged(view) = class else {
        return Ok(());
    };
    let LeeTransaction::Public(public_tx) = tx else {
        unreachable!("only public transactions classify as charged");
    };
    let fee_state = opening_fee_state(state);

    validate_static_tx(&view, &fee_state).map_err(static_rejection)?;

    let payer = view.payer();
    if !lee::is_fee_authorized(public_tx.message(), public_tx.witness_set()) {
        return Err(AdmissionRejection::UnauthorizedPayer { payer });
    }

    let fee_reserve = fee_reserve(&view, &fee_state);
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
/// The accumulator arms belong to block-level totals admission never sums;
/// they fall through to the catch-all so the mapping stays total without a
/// wildcard.
fn static_rejection(err: FeeError) -> AdmissionRejection {
    match err {
        FeeError::DataBytesOutOfRange { data_bytes } => AdmissionRejection::DataBytesOutOfRange {
            data_bytes,
            max: market::MAX_GAS_STOR,
        },
        FeeError::GasLimitAboveCap { gas_limit } => AdmissionRejection::GasLimitExceedsMax {
            gas_limit,
            max: market::MAX_GAS_EXEC,
        },
        FeeError::MaxFeeBelowReserve {
            fee_reserve,
            max_fee,
        } => AdmissionRejection::MaxFeeBelowReserve {
            fee_reserve,
            max_fee,
        },
        FeeError::ExecGasCapExceeded { .. } | FeeError::StorGasCapExceeded { .. } => {
            AdmissionRejection::OtherFeeValidity {
                reason: err.to_string(),
            }
        }
    }
}

/// Prices the next block off the head state's fee market.
///
/// The next-block figures are a band rather than a single estimate: the block
/// being filled is not observable at query time, so the quote steps the
/// market once at an empty block and once at a block filled to its caps.
/// Every possible next-block base fee lies between them, which is exactly
/// what a wallet needs to size `max_fee` for a transaction that may wait.
/// Both steps go through the same `fee_core` arithmetic the block transition
/// moves the real fee state with.
#[must_use]
pub fn fee_quote(state: &lee::V03State) -> FeeStateQuote {
    let fee_state = opening_fee_state(state);
    let step_exec = |gas_used: u64| {
        market::next_base_fee(
            fee_state.base_fee_exec,
            gas_used,
            market::TARGET_GAS_EXEC,
            market::D_EXEC,
            market::BASE_FEE_EXEC_MIN,
            market::BASE_FEE_EXEC_MAX,
        )
    };
    let step_stor = |gas_used: u64| {
        market::next_base_fee(
            fee_state.base_fee_stor,
            gas_used,
            market::TARGET_GAS_STOR,
            market::D_STOR,
            market::BASE_FEE_STOR_MIN,
            market::BASE_FEE_STOR_MAX,
        )
    };

    FeeStateQuote {
        height: fee_state.height,
        base_fee_exec: fee_state.base_fee_exec,
        base_fee_stor: fee_state.base_fee_stor,
        next_base_fee_exec_floor: step_exec(0),
        next_base_fee_exec_ceiling: step_exec(market::MAX_GAS_EXEC),
        next_base_fee_stor_floor: step_stor(0),
        next_base_fee_stor_ceiling: step_stor(market::MAX_GAS_STOR),
        max_gas_exec: market::MAX_GAS_EXEC,
        max_gas_stor: market::MAX_GAS_STOR,
    }
}

#[cfg(test)]
mod tests {
    use common::test_utils::{
        create_transaction_native_token_transfer,
        create_transaction_native_token_transfer_with_fees,
        create_transaction_native_token_transfer_without_fee,
    };
    use fee_core::BlockFeeSummary;
    use lee::{AccountId, FeeDeclaration, PrivateKey, PublicKey};
    use testnet_initial_state::{initial_pub_accounts_private_keys, initial_state};

    use super::*;

    /// The gas limit test transactions declare (`test_fee_declaration`).
    const TEST_GAS_LIMIT: u64 = 2_000_000;

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
        u64::try_from(borsh::to_vec(tx).expect("serializes").len()).expect("fits")
    }

    /// What the block transition says about the same transaction: admission
    /// must be at least as strict for the checks both run, so nothing it
    /// admits is unbuildable.
    fn settle_verdict(tx: &LeeTransaction, state: &lee::V03State) -> Result<(), String> {
        let mut scratch = state.clone();
        let opening = opening_fee_state(state);
        let mut summary = BlockFeeSummary::default();
        chain_state::apply::settle_transaction(tx, &mut scratch, &opening, 2, 200, 0, &mut summary)
            .map(drop)
            .map_err(|err| err.to_string())
    }

    #[test]
    fn a_funded_transfer_is_admitted() {
        let state = initial_state(true);
        let (from, sign_key) = funded();
        let tx = create_transaction_native_token_transfer(from, 0, recipient(), 10, &sign_key);

        screen(&tx, &state).expect("a well-formed, funded transfer is admitted");
        settle_verdict(&tx, &state).expect("and the block transition agrees");
    }

    #[test]
    fn a_transfer_without_a_fee_is_rejected() {
        let state = initial_state(true);
        let (from, sign_key) = funded();
        // Omitting the fee would be executed for free if admitted; the door
        // turns it away, and the block transition agrees.
        let tx = create_transaction_native_token_transfer_without_fee(
            from,
            0,
            recipient(),
            10,
            &sign_key,
        );

        assert_eq!(
            screen(&tx, &state).expect_err("a fee-less transfer is turned away at the door"),
            AdmissionRejection::MissingFeeDeclaration,
        );
        assert!(settle_verdict(&tx, &state).is_err());
    }

    #[test]
    fn a_gas_limit_beyond_the_block_cap_is_rejected() {
        let state = initial_state(true);
        let (from, sign_key) = funded();
        let tx = create_transaction_native_token_transfer_with_fees(
            from,
            0,
            recipient(),
            10,
            &sign_key,
            FeeDeclaration::new(from, market::MAX_GAS_EXEC + 1, 0, u128::MAX >> 1),
        );

        let err = screen(&tx, &state).expect_err("no block can execute that much gas");
        assert_eq!(
            err,
            AdmissionRejection::GasLimitExceedsMax {
                gas_limit: market::MAX_GAS_EXEC + 1,
                max: market::MAX_GAS_EXEC,
            },
        );
        assert!(settle_verdict(&tx, &state).is_err());
    }

    #[test]
    fn a_max_fee_below_the_reserve_is_rejected() {
        let state = initial_state(true);
        let (from, sign_key) = funded();
        let tx = create_transaction_native_token_transfer_with_fees(
            from,
            0,
            recipient(),
            10,
            &sign_key,
            FeeDeclaration::new(from, TEST_GAS_LIMIT, 7, 1),
        );

        // At the genesis base fees of 8/8 the reserve prices the declared
        // gas limit, the serialized bytes, and the tip.
        let fee_state = opening_fee_state(&state);
        let expected = u128::from(TEST_GAS_LIMIT) * u128::from(fee_state.base_fee_exec)
            + u128::from(wire_size(&tx)) * u128::from(fee_state.base_fee_stor)
            + 7;

        let err = screen(&tx, &state).expect_err("a max_fee of 1 covers nothing");
        assert_eq!(
            err,
            AdmissionRejection::MaxFeeBelowReserve {
                fee_reserve: expected,
                max_fee: 1,
            },
        );
        assert!(settle_verdict(&tx, &state).is_err());
    }

    /// The payer signs the transaction (self-pay) but holds nothing, so the
    /// reservation the next block would take cannot succeed.
    #[test]
    fn a_payer_that_cannot_fund_the_reserve_is_rejected() {
        let state = initial_state(true);
        let broke_key = key(9);
        let broke = account_of(&broke_key);
        let tx = create_transaction_native_token_transfer_with_fees(
            broke,
            0,
            recipient(),
            10,
            &broke_key,
            FeeDeclaration::new(broke, TEST_GAS_LIMIT, 0, u128::MAX >> 1),
        );

        let err = screen(&tx, &state).expect_err("a payer with no balance cannot fund it");
        assert!(
            matches!(
                err,
                AdmissionRejection::PayerCannotFund {
                    payer,
                    balance: 0,
                    ..
                } if payer == broke,
            ),
            "expected an unfundable payer, got: {err}",
        );
        // Affordability is admission-only: the block transition rejects this
        // one later, at the reserve debit itself.
        assert!(settle_verdict(&tx, &state).is_err());
    }

    #[test]
    fn a_payer_nothing_authorizes_is_rejected() {
        let state = initial_state(true);
        let (from, sign_key) = funded();
        let stranger = account_of(&key(9));
        let tx = create_transaction_native_token_transfer_with_fees(
            from,
            0,
            recipient(),
            10,
            &sign_key,
            FeeDeclaration::new(stranger, TEST_GAS_LIMIT, 0, u128::MAX >> 1),
        );

        let err = screen(&tx, &state).expect_err("nobody authorized the stranger to pay");
        assert!(
            matches!(err, AdmissionRejection::UnauthorizedPayer { payer } if payer == stranger),
            "expected an unauthorized payer, got: {err}",
        );
        assert!(settle_verdict(&tx, &state).is_err());
    }

    /// The bootstrap case: a full vault sweep is fee-exempt, so none of the
    /// charged checks may run against it — its whole point is that the
    /// sweeper holds nothing yet.
    #[test]
    fn a_full_vault_sweep_by_an_unfunded_account_is_admitted() {
        let mut state = initial_state(true);
        let sweeper_key = key(9);
        let sweeper = account_of(&sweeper_key);
        let vault_id = vault_core::compute_vault_account_id(programs::vault().id(), sweeper);
        state.force_insert_account(
            vault_id,
            lee::Account {
                program_owner: programs::vault().id().into(),
                balance: 500_000_000,
                ..lee::Account::default()
            },
        );

        let message = lee::public_transaction::Message::try_new_with_fees(
            programs::vault().id(),
            vec![sweeper, vault_id],
            vec![0_u128.into()],
            vault_core::Instruction::Claim {
                amount: 500_000_000,
            },
            // A sweep is exempt whatever it declares, and a wallet with
            // nothing to pay with signs a zero max_fee: neither the reserve
            // check nor the balance check may see this.
            FeeDeclaration::new(sweeper, TEST_GAS_LIMIT, 0, 0),
        )
        .expect("message builds");
        let witness_set =
            lee::public_transaction::WitnessSet::for_message(&message, &[&sweeper_key]);
        let tx = LeeTransaction::Public(lee::PublicTransaction::new(message, witness_set));

        screen(&tx, &state).expect("a full sweep must be admitted unscreened");
    }

    /// Private transactions are fee-exempt under the interim policy, so
    /// admission has nothing to check against one.
    #[test]
    fn a_private_transaction_is_admitted_unscreened() {
        use lee::privacy_preserving_transaction::{
            Message as PrivateMessage, PrivacyPreservingTransaction,
            WitnessSet as PrivateWitnessSet, circuit::Proof,
        };

        let state = initial_state(true);
        let tx = LeeTransaction::PrivacyPreserving(PrivacyPreservingTransaction::new(
            PrivateMessage::default(),
            PrivateWitnessSet::from_raw_parts(vec![], Proof::from_inner(vec![])),
        ));

        screen(&tx, &state).expect("private transactions are uncharged and unscreened");
    }

    /// Deployments are exempt *and* uncapped in the delivered interim policy
    /// (they contribute nothing to the block gas totals), so even one larger
    /// than the storage cap passes — a deliberate divergence from the
    /// reference design, where uncharged transactions were still capped.
    /// The block size limit at ingest is what bounds it.
    #[test]
    fn an_oversized_deployment_is_admitted_unscreened() {
        let state = initial_state(true);
        let bytecode = vec![0_u8; usize::try_from(market::MAX_GAS_STOR).expect("fits") + 1];
        let tx = LeeTransaction::ProgramDeployment(lee::ProgramDeploymentTransaction::new(
            lee::program_deployment_transaction::Message::new(bytecode),
        ));

        screen(&tx, &state).expect("deployments are uncharged and uncapped today");
    }

    /// SPECS §Overview worked example: at the genesis base fees of 8/8 the
    /// next block's fees can only stay at the minimum or rise by the
    /// guaranteed +1 step.
    #[test]
    fn the_quote_prices_the_head_fee_state() {
        let state = initial_state(true);
        let quote = fee_quote(&state);

        assert_eq!(quote.height, 0);
        assert_eq!(quote.base_fee_exec, 8);
        assert_eq!(quote.base_fee_stor, 8);
        assert_eq!(quote.next_base_fee_exec_floor, 8);
        assert_eq!(quote.next_base_fee_exec_ceiling, 9);
        assert_eq!(quote.next_base_fee_stor_floor, 8);
        assert_eq!(quote.next_base_fee_stor_ceiling, 9);
        assert_eq!(quote.max_gas_exec, market::MAX_GAS_EXEC);
        assert_eq!(quote.max_gas_stor, market::MAX_GAS_STOR);
    }

    /// The quote is what a wallet prices `max_fee` off, so the reserve it
    /// implies must be the one admission compares against: one unit of
    /// headroom below it is exactly what admission rejects.
    #[test]
    fn a_reserve_computed_from_the_quote_matches_the_one_admission_uses() {
        let state = initial_state(true);
        let (from, sign_key) = funded();
        let quote = fee_quote(&state);
        let build = |max_fee: u128| {
            create_transaction_native_token_transfer_with_fees(
                from,
                0,
                recipient(),
                10,
                &sign_key,
                FeeDeclaration::new(from, TEST_GAS_LIMIT, 3, max_fee),
            )
        };

        let probe = build(u128::MAX >> 1);
        let by_hand = u128::from(TEST_GAS_LIMIT) * u128::from(quote.base_fee_exec)
            + u128::from(wire_size(&probe)) * u128::from(quote.base_fee_stor)
            + 3;

        // The wire size is invariant under max_fee (u128 is fixed-width), so
        // the reserve computed off the probe prices the tight build too.
        screen(&build(by_hand), &state).expect("max_fee equal to the reserve is admitted");
        assert!(matches!(
            screen(&build(by_hand - 1), &state).expect_err("one unit short"),
            AdmissionRejection::MaxFeeBelowReserve { .. }
        ));
    }
}
