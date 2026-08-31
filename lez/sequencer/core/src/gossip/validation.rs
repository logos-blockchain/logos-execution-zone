//! Pure decision function for an inbound gossiped transaction.
//!
//! The same stateless admission the RPC performs, minus mempool/seen-cache
//! side effects (those live in the drive task). Testable without a swarm.

use common::transaction::LeeTransaction;

/// Reserve ~200 bytes for block header overhead, mirroring the RPC check.
const BLOCK_HEADER_OVERHEAD: u64 = 200;

#[derive(Debug)]
// `Accept` is intentionally left unboxed: it is the common outcome and the enum
// is short-lived per gossiped message, so boxing it would only add a heap
// allocation on the hot validation path.
pub enum TxEvaluation {
    /// Structurally valid and authenticated; forward and admit.
    Accept(LeeTransaction),
    /// Malformed / forbidden; do not forward. `GossipSub` peer scoring is not
    /// configured, so this does not currently penalize the propagating peer.
    Reject(String),
}

/// Decodes and stateless-checks a gossiped transaction the same way the RPC
/// admits a submitted one: size check, signature/witness check, then the
/// sequencer-only-program guard.
#[must_use]
pub fn evaluate_transaction(data: &[u8], max_block_size: u64) -> TxEvaluation {
    let tx_size = u64::try_from(data.len()).unwrap_or(u64::MAX);
    let max_tx_size = max_block_size.saturating_sub(BLOCK_HEADER_OVERHEAD);
    if tx_size > max_tx_size {
        return TxEvaluation::Reject(format!("transaction too large: {tx_size} > {max_tx_size}"));
    }

    let tx: LeeTransaction = match borsh::from_slice(data) {
        Ok(tx) => tx,
        Err(err) => return TxEvaluation::Reject(format!("undecodable transaction: {err}")),
    };

    let authenticated = match tx.transaction_stateless_check() {
        Ok(tx) => tx,
        Err(err) => return TxEvaluation::Reject(format!("stateless check failed: {err:?}")),
    };

    if let LeeTransaction::Public(public_tx) = &authenticated
        && crate::is_sequencer_only_program(public_tx.message().program_id)
    {
        return TxEvaluation::Reject("sequencer-only program".to_owned());
    }

    TxEvaluation::Accept(authenticated)
}

#[cfg(test)]
mod tests {
    use testnet_initial_state::{initial_pub_accounts_private_keys, initial_public_user_accounts};

    use super::*;

    fn valid_transaction() -> LeeTransaction {
        let acc1 = initial_public_user_accounts()[0].account_id;
        let acc2 = initial_public_user_accounts()[1].account_id;
        let sign_key1 = initial_pub_accounts_private_keys()[0].pub_sign_key.clone();
        common::test_utils::create_transaction_native_token_transfer(acc1, 0, acc2, 10, &sign_key1)
    }

    #[test]
    fn well_formed_transaction_is_accepted() {
        let tx = valid_transaction();
        let bytes = borsh::to_vec(&tx).unwrap();
        assert!(matches!(
            evaluate_transaction(&bytes, 1 << 20),
            TxEvaluation::Accept(_)
        ));
    }

    #[test]
    fn garbage_bytes_are_rejected() {
        assert!(matches!(
            evaluate_transaction(&[0xff, 0xff, 0xff], 1 << 20),
            TxEvaluation::Reject(_)
        ));
    }

    #[test]
    fn oversize_transaction_is_rejected() {
        let tx = valid_transaction();
        let bytes = borsh::to_vec(&tx).unwrap();
        assert!(matches!(
            evaluate_transaction(&bytes, 1),
            TxEvaluation::Reject(_)
        ));
    }
}
