//! Bridge operations the sequencer builds itself.

use std::collections::BTreeMap;

use borsh::BorshDeserialize as _;
use bridge_core::{BridgeAmount, DepositMetadata};
use lee::{
    AccountId, Actor, Authority, PublicAccountEvidence, PublicTransaction,
    public_transaction::Message,
};

/// Whom a bridge deposit credits.
pub enum Credited<'recipient> {
    /// A public account, declared with the admission evidence it carries.
    Public(&'recipient PublicAccountEvidence),
    /// A private address, left undeclared so its credit is published under its recovery binding.
    Private(AccountId),
}

impl Credited<'_> {
    /// `None` for public evidence that names no account.
    fn account_id(&self) -> Option<AccountId> {
        match self {
            Self::Public(evidence) => evidence.account_id(),
            Self::Private(address) => Some(*address),
        }
    }

    const fn evidence(&self) -> Option<&PublicAccountEvidence> {
        match self {
            Self::Public(evidence) => Some(evidence),
            Self::Private(_) => None,
        }
    }
}

/// The mint of the L1 deposit `op_id` carrying `metadata`, the one transaction every node accepts
/// for it.
pub fn deposit_mint(
    op_id: [u8; 32],
    amount: BridgeAmount,
    metadata: &[u8],
) -> anyhow::Result<PublicTransaction> {
    let metadata = DepositMetadata::try_from_slice(metadata)?;
    Ok(deposit_tx(
        op_id,
        &Credited::Public(metadata.recipient.evidence()),
        amount,
    )?)
}

/// A bridge `Deposit` of `amount` under `op_id`, crediting `credited`.
///
/// # Errors
///
/// Returns an error when the deposit message fails to serialize, or the recipient's evidence
/// names no account.
pub fn deposit_tx(
    op_id: [u8; 32],
    credited: &Credited<'_>,
    amount: BridgeAmount,
) -> Result<PublicTransaction, lee::error::LeeError> {
    let receipt = receipt_actor(op_id);
    let recipient_id = credited.account_id().ok_or_else(|| {
        lee::error::LeeError::InvalidInput(
            "the deposit recipient's evidence names no account".into(),
        )
    })?;
    let message = Message {
        admission_evidence: std::iter::once(PublicAccountEvidence::Pda {
            program: programs::bridge_account_id(),
            seed: bridge_core::deposit_receipt_seed(op_id),
        })
        .chain(credited.evidence().cloned())
        .collect(),
        ..Message::try_new(
            receipt,
            deposit_actors(receipt, credited, recipient_id),
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
fn deposit_actors(
    receipt: Actor,
    credited: &Credited<'_>,
    recipient_id: AccountId,
) -> Vec<(Actor, Authority)> {
    let custody = Actor::native_balance(system_accounts::bridge_account_id());
    match credited {
        Credited::Public(_) => vec![
            (receipt, Authority::None),
            (custody, Authority::None),
            (Actor::native_balance(recipient_id), Authority::None),
        ],
        Credited::Private(_) => vec![(receipt, Authority::None), (custody, Authority::None)],
    }
}
