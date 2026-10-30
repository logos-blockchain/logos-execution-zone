//! Bridge operations the sequencer builds itself.

use std::collections::BTreeMap;

use bridge_core::BridgeAmount;
use lee::{
    AccountId, Actor, PublicAccountEvidence, PublicTransaction, public_transaction::Message,
};

/// Whom a bridge deposit credits.
pub enum Credited<'recipient> {
    /// A public account, declared with the admission evidence it carries.
    Public(&'recipient PublicAccountEvidence),
    /// A private address, left undeclared so its credit is published under its recovery binding.
    Private(AccountId),
}

impl Credited<'_> {
    fn account_id(&self) -> AccountId {
        match self {
            Self::Public(evidence) => evidence.account_id(),
            Self::Private(address) => *address,
        }
    }

    const fn evidence(&self) -> Option<&PublicAccountEvidence> {
        match self {
            Self::Public(evidence) => Some(evidence),
            Self::Private(_) => None,
        }
    }
}

/// A bridge `Deposit` of `amount` under `op_id`, crediting `credited`.
///
/// # Errors
///
/// Returns an error when the deposit message fails to serialize.
pub fn deposit_tx(
    op_id: [u8; 32],
    credited: &Credited<'_>,
    amount: BridgeAmount,
) -> Result<PublicTransaction, lee::error::LeeError> {
    let receipt = receipt_actor(op_id);
    let recipient_id = credited.account_id();
    let message = Message {
        admission_evidence: std::iter::once(PublicAccountEvidence::Pda {
            program: programs::bridge_account_id(),
            seed: bridge_core::deposit_receipt_seed(op_id),
        })
        .chain(credited.evidence().cloned())
        .collect(),
        ..Message::try_new(
            receipt,
            deposit_actors(receipt, credited),
            BTreeMap::new(),
            bridge_core::Message::Deposit {
                l1_deposit_op_id: op_id,
                recipient_id,
                amount,
            },
        )?
    };
    let witness_set = lee::public_transaction::WitnessSet::from_raw_parts(Vec::new());

    Ok(PublicTransaction::new(message, witness_set))
}

/// The deposit-receipt actor a `Deposit` for `op_id` is addressed to.
fn receipt_actor(op_id: [u8; 32]) -> Actor {
    let bridge_program_id = programs::bridge_account_id();
    Actor::new(
        bridge_core::deposit_receipt_account_id(bridge_program_id, op_id),
        bridge_program_id,
    )
}

/// The receipt, then the bridge custody and the public recipient the deposit's transfer moves
/// balance between. A private recipient is not declared: its credit is published to it.
fn deposit_actors(receipt: Actor, credited: &Credited<'_>) -> Vec<Actor> {
    let custody = Actor::native_balance(system_accounts::bridge_account_id());
    match credited {
        Credited::Public(evidence) => vec![
            receipt,
            custody,
            Actor::native_balance(evidence.account_id()),
        ],
        Credited::Private(_) => vec![receipt, custody],
    }
}
