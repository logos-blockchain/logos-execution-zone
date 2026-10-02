#![expect(
    clippy::multiple_inherent_impl,
    reason = "We prefer to group methods by functionality rather than by type for encoding"
)]

pub use fees::{FeeDeclaration, SignedMessage, is_fee_authorized};
pub use lee_core::{
    GENESIS_BLOCK_ID, ProvingInput, SharedSecretKey,
    account::{Account, AccountData, AccountId, Actor, ActorState, Balance, Cycles, Fee, Gas},
    encryption::EphemeralPublicKey,
    execution_state::{Boundary, BoundaryStep, Delivery, PublicExecutionContext, TransactionEntry},
    native_token,
    program::{
        Call, Cast, MessageBody, MessageData, MessageEnvelope, MessageId, ProgramId, StoredMessage,
    },
};
pub use privacy_preserving_circuit::{
    PRIVACY_PRESERVING_CIRCUIT_ELF, PRIVACY_PRESERVING_CIRCUIT_ID,
};
pub use privacy_preserving_transaction::{
    PrivacyPreservingTransaction,
    circuit::{Simulation, execute_and_prove, execute_and_prove_with_crossings},
};
pub use public_transaction::{PublicIdentity, PublicTransaction};
pub use signature::{PrivateKey, PublicKey, Signature};
pub use state::V03State;
pub use validated_state_diff::{ExecutionCharge, ValidatedStateDiff};

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

/// Not a guarantee: a `[profile.release] debug-assertions = true` override slips past this.
#[cfg(all(feature = "test-utils", not(debug_assertions)))]
compile_error!(
    "`test-utils` exposes validation-bypassing state-mutation helpers and must never be \
     enabled in a release build."
);

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
    pub const fn exits_nonzero() -> Program {
        Program::new_unchecked(
            test_methods::EXITS_NONZERO_ID,
            Cow::Borrowed(test_methods::EXITS_NONZERO_ELF),
        )
    }

    #[must_use]
    pub const fn scripted() -> Program {
        Program::new_unchecked(
            test_methods::SCRIPTED_ID,
            Cow::Borrowed(test_methods::SCRIPTED_ELF),
        )
    }

    #[must_use]
    pub const fn forges_echo() -> Program {
        Program::new_unchecked(
            test_methods::FORGES_ECHO_ID,
            Cow::Borrowed(test_methods::FORGES_ECHO_ELF),
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
}
