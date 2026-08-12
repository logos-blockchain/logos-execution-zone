#![expect(
    clippy::multiple_inherent_impl,
    reason = "We prefer to group methods by functionality rather than by type for encoding"
)]

pub use fee_core::FeeState;
pub use fees::{
    FeeFields, SYSTEM_PAYER, SignedMessage, fee_authorized_account_ids, is_fee_authorized,
};
pub use lee_core::{
    GENESIS_BLOCK_ID, SharedSecretKey,
    account::{Account, AccountId, Balance, Data},
    encryption::EphemeralPublicKey,
    program::ProgramId,
};
pub use privacy_preserving_circuit::{
    PRIVACY_PRESERVING_CIRCUIT_ELF, PRIVACY_PRESERVING_CIRCUIT_ID,
};
pub use privacy_preserving_transaction::{
    PrivacyPreservingTransaction, circuit::execute_and_prove,
};
pub use program_deployment_transaction::ProgramDeploymentTransaction;
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
pub mod program_deployment_transaction;
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

    #[must_use]
    pub const fn nonce_changer() -> Program {
        Program::new_unchecked(
            test_methods::NONCE_CHANGER_ID,
            Cow::Borrowed(test_methods::NONCE_CHANGER_ELF),
        )
    }

    #[must_use]
    pub const fn extra_output() -> Program {
        Program::new_unchecked(
            test_methods::EXTRA_OUTPUT_ID,
            Cow::Borrowed(test_methods::EXTRA_OUTPUT_ELF),
        )
    }

    #[must_use]
    pub const fn missing_output() -> Program {
        Program::new_unchecked(
            test_methods::MISSING_OUTPUT_ID,
            Cow::Borrowed(test_methods::MISSING_OUTPUT_ELF),
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
    pub const fn program_owner_changer() -> Program {
        Program::new_unchecked(
            test_methods::PROGRAM_OWNER_CHANGER_ID,
            Cow::Borrowed(test_methods::PROGRAM_OWNER_CHANGER_ELF),
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
    pub const fn pda_claimer() -> Program {
        Program::new_unchecked(
            test_methods::PDA_CLAIMER_ID,
            Cow::Borrowed(test_methods::PDA_CLAIMER_ELF),
        )
    }

    #[must_use]
    pub const fn two_pda_claimer() -> Program {
        Program::new_unchecked(
            test_methods::TWO_PDA_CLAIMER_ID,
            Cow::Borrowed(test_methods::TWO_PDA_CLAIMER_ELF),
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
    pub const fn modified_transfer_program() -> Program {
        Program::new_unchecked(
            test_methods::MODIFIED_TRANSFER_ID,
            Cow::Borrowed(test_methods::MODIFIED_TRANSFER_ELF),
        )
    }

    #[must_use]
    pub const fn malicious_authorization_changer() -> Program {
        Program::new_unchecked(
            test_methods::MALICIOUS_AUTHORIZATION_CHANGER_ID,
            Cow::Borrowed(test_methods::MALICIOUS_AUTHORIZATION_CHANGER_ELF),
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
    pub const fn claimer() -> Program {
        Program::new_unchecked(
            test_methods::CLAIMER_ID,
            Cow::Borrowed(test_methods::CLAIMER_ELF),
        )
    }

    #[must_use]
    pub const fn changer_claimer() -> Program {
        Program::new_unchecked(
            test_methods::CHANGER_CLAIMER_ID,
            Cow::Borrowed(test_methods::CHANGER_CLAIMER_ELF),
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
    pub const fn malicious_injector() -> Program {
        Program::new_unchecked(
            test_methods::MALICIOUS_INJECTOR_ID,
            Cow::Borrowed(test_methods::MALICIOUS_INJECTOR_ELF),
        )
    }

    #[must_use]
    pub const fn malicious_launderer() -> Program {
        Program::new_unchecked(
            test_methods::MALICIOUS_LAUNDERER_ID,
            Cow::Borrowed(test_methods::MALICIOUS_LAUNDERER_ELF),
        )
    }
}
