#![expect(
    clippy::multiple_inherent_impl,
    reason = "We prefer to group methods by functionality rather than by type for encoding"
)]

pub use fees::{FeeDeclaration, SignedMessage, is_fee_authorized};
pub use lee_core::{
    GENESIS_BLOCK_ID, SharedSecretKey,
    account::{
        Account, AccountData, AccountId, AccountInput, Balance, Cycles, Data, Fee, Gas,
        ProgramShardSelector,
    },
    encryption::EphemeralPublicKey,
    program::ProgramId,
};
pub use privacy_preserving_circuit::{
    PRIVACY_PRESERVING_CIRCUIT_ELF, PRIVACY_PRESERVING_CIRCUIT_ID,
};
pub use privacy_preserving_transaction::{
    PrivacyPreservingTransaction,
    circuit::{ProvingInput, execute_and_prove},
};
pub use public_transaction::PublicTransaction;
pub use signature::{PrivateKey, PublicKey, Signature};
pub use state::V03State;
pub use validated_state_diff::{ExecutionOutcome, ValidatedStateDiff};

pub mod encoding;
pub mod error;
pub mod fees;
mod merkle_tree;
pub mod privacy_preserving_transaction;
pub mod program;
pub mod public_transaction;
mod signature;
mod state;
#[cfg(feature = "test-utils")]
pub mod test_utils;
mod validated_state_diff;

mod privacy_preserving_circuit {
    include!(concat!(
        env!("OUT_DIR"),
        "/lee/privacy_preserving_circuit/mod.rs"
    ));
}

#[cfg(test)]
mod test_methods {
    use std::borrow::Cow;

    use crate::program::Program;

    #[must_use]
    pub const fn simple_balance_transfer() -> Program {
        Program::new_unchecked(
            test_methods::SIMPLE_BALANCE_TRANSFER_ID,
            Cow::Borrowed(test_methods::SIMPLE_BALANCE_TRANSFER_ELF),
        )
    }

    #[cfg(feature = "prove")]
    #[must_use]
    pub const fn multi_segment_burner() -> Program {
        Program::new_unchecked(
            test_methods::MULTI_SEGMENT_BURNER_ID,
            Cow::Borrowed(test_methods::MULTI_SEGMENT_BURNER_ELF),
        )
    }

    #[cfg(feature = "prove")]
    #[must_use]
    pub const fn panics_with_session_limit_text() -> Program {
        Program::new_unchecked(
            test_methods::PANICS_WITH_SESSION_LIMIT_TEXT_ID,
            Cow::Borrowed(test_methods::PANICS_WITH_SESSION_LIMIT_TEXT_ELF),
        )
    }

    #[must_use]
    pub const fn malformed_journal() -> Program {
        Program::new_unchecked(
            test_methods::MALFORMED_JOURNAL_ID,
            Cow::Borrowed(test_methods::MALFORMED_JOURNAL_ELF),
        )
    }

    #[must_use]
    pub const fn dropped_account() -> Program {
        Program::new_unchecked(
            test_methods::DROPPED_ACCOUNT_ID,
            Cow::Borrowed(test_methods::DROPPED_ACCOUNT_ELF),
        )
    }

    #[must_use]
    pub const fn data_changer() -> Program {
        Program::new_unchecked(
            test_methods::DATA_CHANGER_ID,
            Cow::Borrowed(test_methods::DATA_CHANGER_ELF),
        )
    }

    #[must_use]
    pub const fn foreign_shard_writer() -> Program {
        Program::new_unchecked(
            test_methods::FOREIGN_SHARD_WRITER_ID,
            Cow::Borrowed(test_methods::FOREIGN_SHARD_WRITER_ELF),
        )
    }

    #[must_use]
    pub const fn minter() -> Program {
        Program::new_unchecked(
            test_methods::MINTER_ID,
            Cow::Borrowed(test_methods::MINTER_ELF),
        )
    }

    #[must_use]
    pub const fn burner() -> Program {
        Program::new_unchecked(
            test_methods::BURNER_ID,
            Cow::Borrowed(test_methods::BURNER_ELF),
        )
    }

    #[must_use]
    pub const fn auth_asserting_noop() -> Program {
        Program::new_unchecked(
            test_methods::AUTH_ASSERTING_NOOP_ID,
            Cow::Borrowed(test_methods::AUTH_ASSERTING_NOOP_ELF),
        )
    }

    #[must_use]
    pub const fn private_pda_delegator() -> Program {
        Program::new_unchecked(
            test_methods::PRIVATE_PDA_DELEGATOR_ID,
            Cow::Borrowed(test_methods::PRIVATE_PDA_DELEGATOR_ELF),
        )
    }

    #[must_use]
    pub const fn selective_pda_delegator() -> Program {
        Program::new_unchecked(
            test_methods::SELECTIVE_PDA_DELEGATOR_ID,
            Cow::Borrowed(test_methods::SELECTIVE_PDA_DELEGATOR_ELF),
        )
    }

    #[must_use]
    pub const fn shard_forwarder() -> Program {
        Program::new_unchecked(
            test_methods::SHARD_FORWARDER_ID,
            Cow::Borrowed(test_methods::SHARD_FORWARDER_ELF),
        )
    }

    #[must_use]
    pub const fn non_delegating_forwarder() -> Program {
        Program::new_unchecked(
            test_methods::NON_DELEGATING_FORWARDER_ID,
            Cow::Borrowed(test_methods::NON_DELEGATING_FORWARDER_ELF),
        )
    }

    #[must_use]
    pub const fn noop() -> Program {
        Program::new_unchecked(test_methods::NOOP_ID, Cow::Borrowed(test_methods::NOOP_ELF))
    }

    #[must_use]
    pub const fn chain_caller() -> Program {
        Program::new_unchecked(
            test_methods::CHAIN_CALLER_ID,
            Cow::Borrowed(test_methods::CHAIN_CALLER_ELF),
        )
    }

    #[must_use]
    pub const fn event_emitter() -> Program {
        Program::new_unchecked(
            test_methods::EVENT_EMITTER_ID,
            Cow::Borrowed(test_methods::EVENT_EMITTER_ELF),
        )
    }

    #[must_use]
    pub const fn validity_window() -> Program {
        Program::new_unchecked(
            test_methods::VALIDITY_WINDOW_ID,
            Cow::Borrowed(test_methods::VALIDITY_WINDOW_ELF),
        )
    }

    #[must_use]
    pub const fn flash_swap_initiator() -> Program {
        Program::new_unchecked(
            test_methods::FLASH_SWAP_INITIATOR_ID,
            Cow::Borrowed(test_methods::FLASH_SWAP_INITIATOR_ELF),
        )
    }

    #[must_use]
    pub const fn flash_swap_callback() -> Program {
        Program::new_unchecked(
            test_methods::FLASH_SWAP_CALLBACK_ID,
            Cow::Borrowed(test_methods::FLASH_SWAP_CALLBACK_ELF),
        )
    }

    #[must_use]
    pub const fn malicious_self_program_id() -> Program {
        Program::new_unchecked(
            test_methods::MALICIOUS_SELF_PROGRAM_ID_ID,
            Cow::Borrowed(test_methods::MALICIOUS_SELF_PROGRAM_ID_ELF),
        )
    }

    #[must_use]
    pub const fn malicious_caller_program_id() -> Program {
        Program::new_unchecked(
            test_methods::MALICIOUS_CALLER_PROGRAM_ID_ID,
            Cow::Borrowed(test_methods::MALICIOUS_CALLER_PROGRAM_ID_ELF),
        )
    }

    #[must_use]
    pub const fn pda_spend_proxy() -> Program {
        Program::new_unchecked(
            test_methods::PDA_SPEND_PROXY_ID,
            Cow::Borrowed(test_methods::PDA_SPEND_PROXY_ELF),
        )
    }

    #[must_use]
    pub const fn validity_window_chain_caller() -> Program {
        Program::new_unchecked(
            test_methods::VALIDITY_WINDOW_CHAIN_CALLER_ID,
            Cow::Borrowed(test_methods::VALIDITY_WINDOW_CHAIN_CALLER_ELF),
        )
    }

    #[must_use]
    #[inline]
    pub const fn simple_transfer_proxy() -> Program {
        Program::new_unchecked(
            test_methods::SIMPLE_TRANSFER_PROXY_ID,
            Cow::Borrowed(test_methods::SIMPLE_TRANSFER_PROXY_ELF),
        )
    }

    #[must_use]
    pub const fn references_undeclared_account() -> Program {
        Program::new_unchecked(
            test_methods::REFERENCES_UNDECLARED_ACCOUNT_ID,
            Cow::Borrowed(test_methods::REFERENCES_UNDECLARED_ACCOUNT_ELF),
        )
    }

    #[must_use]
    pub const fn injects_undeclared_pre_state() -> Program {
        Program::new_unchecked(
            test_methods::INJECTS_UNDECLARED_PRE_STATE_ID,
            Cow::Borrowed(test_methods::INJECTS_UNDECLARED_PRE_STATE_ELF),
        )
    }

    #[must_use]
    pub const fn reorders_and_forwards() -> Program {
        Program::new_unchecked(
            test_methods::REORDERS_AND_FORWARDS_ID,
            Cow::Borrowed(test_methods::REORDERS_AND_FORWARDS_ELF),
        )
    }

    #[must_use]
    pub const fn asserts_specific_account_authorized() -> Program {
        Program::new_unchecked(
            test_methods::ASSERTS_SPECIFIC_ACCOUNT_AUTHORIZED_ID,
            Cow::Borrowed(test_methods::ASSERTS_SPECIFIC_ACCOUNT_AUTHORIZED_ELF),
        )
    }

    #[must_use]
    pub const fn reordering_transfer() -> Program {
        Program::new_unchecked(
            test_methods::REORDERING_TRANSFER_ID,
            Cow::Borrowed(test_methods::REORDERING_TRANSFER_ELF),
        )
    }
}
