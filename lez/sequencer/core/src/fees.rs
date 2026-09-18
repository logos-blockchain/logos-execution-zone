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
use lee::AccountId;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("designated payer {payer:?} authorized nothing in this transaction")]
    UnauthorizedPayer { payer: AccountId },

    #[error("payer {payer:?} holds {balance} but the fee reserve is {fee_reserve}")]
    PayerCannotFund {
        payer: AccountId,
        balance: u128,
        fee_reserve: u128,
    },

    #[error("transaction fee classification failed")]
    Classification(#[from] ClassifyError),

    #[error(transparent)]
    FeeCore(#[from] FeeError),
}

pub type Result<T, E = Error> = std::result::Result<T, E>;

/// The fee market priced off the head state, for wallets sizing `max_fee`.
pub struct FeeStateQuote {
    /// The block height the quoted state settled at, for staleness checks.
    pub height: u64,
    pub base_fee_exec: u64,
    pub base_fee_stor: u64,
    pub next_base_fee_exec_floor: u64,
    pub next_base_fee_exec_ceiling: u64,
    pub next_base_fee_stor_floor: u64,
    pub next_base_fee_stor_ceiling: u64,
    pub max_gas_exec: u64,
    pub max_gas_stor: u64,
}

/// Screens a submitted transaction against the head state.
pub fn screen(tx: &LeeTransaction, state: &lee::V03State) -> Result<()> {
    let class = classify(tx, false)?;
    let FeeClass::Charged(view) = class else {
        return Ok(());
    };
    let LeeTransaction::Public(public_tx) = tx else {
        unreachable!("only public transactions classify as charged");
    };
    let fee_state = opening_fee_state(state);

    validate_static_tx(&view, &fee_state)?;

    let payer = view.payer();
    if !lee::is_fee_authorized(public_tx.message(), public_tx.witness_set()) {
        return Err(Error::UnauthorizedPayer { payer });
    }

    let fee_reserve = fee_reserve(&view, &fee_state);
    let balance = state.get_account_by_id(payer).data.balance;
    if balance < fee_reserve {
        return Err(Error::PayerCannotFund {
            payer,
            balance,
            fee_reserve,
        });
    }

    Ok(())
}

/// Prices the next block off the head state's fee market.
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

        assert!(matches!(
            screen(&tx, &state).expect_err("a fee-less transfer is turned away at the door"),
            Error::Classification(ClassifyError::MissingFeeDeclaration)
        ));
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
        assert!(matches!(
            err,
            Error::FeeCore(FeeError::GasLimitAboveCap { gas_limit })
            if gas_limit == market::MAX_GAS_EXEC + 1
        ));
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
        assert!(matches!(
            err,
            Error::FeeCore(FeeError::MaxFeeBelowReserve {
                fee_reserve,
                max_fee,
            }) if fee_reserve == expected && max_fee == 1
        ));
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
                Error::PayerCannotFund {
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
            matches!(err, Error::UnauthorizedPayer { payer } if payer == stranger),
            "expected an unauthorized payer, got: {err}",
        );
        assert!(settle_verdict(&tx, &state).is_err());
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
            Error::FeeCore(FeeError::MaxFeeBelowReserve { .. })
        ));
    }
}
