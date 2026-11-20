//! The vault's deposits on Bedrock, which back every mint of the bridge after genesis.

use std::sync::LazyLock;

use borsh::BorshDeserialize as _;
use bridge_core::{BridgeAmount, DepositMetadata, DepositRecipient};
use common::{block::Block, transaction::LeeTransaction};
use lee::GENESIS_BLOCK_ID;
use logos_blockchain_zone_sdk::{
    InscriptionSteps,
    core::mantle::ops::channel::{inscribe::Step, program_step::ProgramDeposit},
    groth16::fr_to_bytes,
    node_types::{ProgramId, ProgramVerificationKey, derive_program_id},
};
use sequencer_bridge::{Credited, deposit_tx};

/// The id Bedrock gives the vault program.
pub static VAULT_PROGRAM: LazyLock<ProgramId> = LazyLock::new(|| derive_program_id(&vault_key()));

/// What the zone mints for a deposit the vault took in.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VaultMint {
    /// The first nullifier of the deposit. Bedrock spends a note once, so no other deposit
    /// shares it.
    pub id: [u8; 32],
    /// Read from the deposit's inscription, a borsh [`DepositMetadata`].
    pub recipient: DepositRecipient,
    pub amount: BridgeAmount,
}

impl VaultMint {
    /// `None` for a deposit that names no recipient or spends no note.
    #[must_use]
    pub fn of(deposit: &ProgramDeposit) -> Option<Self> {
        let recipient = DepositMetadata::try_from_slice(deposit.inscription.as_ref())
            .ok()?
            .recipient;
        let nullifier = deposit.inputs.iter().next()?;
        Some(Self {
            id: fr_to_bytes(&nullifier.0),
            recipient,
            amount: deposit.value,
        })
    }

    /// The transaction a block mints it with, byte for byte.
    #[must_use]
    pub fn transaction(&self) -> Option<LeeTransaction> {
        deposit_tx(
            self.id,
            &Credited::Public(self.recipient.evidence()),
            self.amount,
        )
        .ok()
        .map(LeeTransaction::Public)
    }
}

/// The key the vault program is registered under.
#[must_use]
pub fn vault_key() -> ProgramVerificationKey {
    ProgramVerificationKey::try_from_bytes(vault_circuit::DEMO_VERIFICATION_KEY)
        .expect("the vault key is a valid program key")
}

/// Whether `block` mints exactly the deposits the vault took in with the inscription carrying
/// it, in their order. Genesis mints its supply with no deposit behind it.
#[must_use]
pub fn mints_backed(block: &Block, steps: &InscriptionSteps) -> bool {
    let mut taken = Vec::new();
    for mini_block in steps.mini_blocks.iter() {
        for step in mini_block.iter() {
            let Step::ProgramDeposit(deposit) = step else {
                continue;
            };
            if deposit.program_id != *VAULT_PROGRAM {
                continue;
            }
            let Some(mint) = VaultMint::of(deposit).and_then(|mint| mint.transaction()) else {
                return false;
            };
            taken.push(mint);
        }
    }
    if block.header.block_id == GENESIS_BLOCK_ID {
        return taken.is_empty();
    }
    block
        .body
        .transactions
        .iter()
        .filter(|tx| is_bridge_deposit(tx))
        .eq(&taken)
}

fn is_bridge_deposit(tx: &LeeTransaction) -> bool {
    tx.public_call().is_some_and(|(to, message)| {
        to.program_account_id == programs::bridge_account_id()
            && matches!(
                borsh::from_slice(message),
                Ok(bridge_core::Message::Deposit { .. })
            )
    })
}

#[cfg(test)]
mod tests {
    use common::test_utils::produce_dummy_block;
    use logos_blockchain_zone_sdk::{
        core::mantle::{
            notes::{NoteNullifier, OutputCommitments},
            ops::channel::inscribe::{MiniBlock, MiniBlocks},
        },
        groth16::Fr,
        node_types::Inscription,
    };

    use super::*;

    fn deposit(program_id: ProgramId, nullifier: u64, value: u64) -> ProgramDeposit {
        let metadata = DepositMetadata {
            recipient: DepositRecipient::Identified(lee::PublicAccountEvidence::Pda {
                program: lee::AccountId::new([7; 32]),
                seed: bridge_core::deposit_receipt_seed([9; 32]),
            }),
        };
        ProgramDeposit {
            program_id,
            inputs: [NoteNullifier(Fr::from(nullifier))].into(),
            outputs: OutputCommitments::default(),
            commitment_merkle_root: Fr::from(0_u64),
            value,
            intent: Fr::from(0_u64),
            inscription: Inscription::try_new(borsh::to_vec(&metadata).unwrap(), 128).unwrap(),
        }
    }

    fn steps(deposits: &[ProgramDeposit]) -> InscriptionSteps {
        let mini_blocks = MiniBlock::try_from(
            deposits
                .iter()
                .cloned()
                .map(Step::ProgramDeposit)
                .collect::<Vec<_>>(),
        )
        .map_or_else(|_| MiniBlocks::default(), |block| [block].into());
        InscriptionSteps {
            mini_blocks,
            ..InscriptionSteps::default()
        }
    }

    fn block(mints: &[&ProgramDeposit]) -> Block {
        let txs = mints
            .iter()
            .map(|deposit| VaultMint::of(deposit).unwrap().transaction().unwrap())
            .collect();
        produce_dummy_block(2, None, txs)
    }

    #[test]
    fn a_block_mints_exactly_the_deposits_of_its_inscription() {
        let first = deposit(*VAULT_PROGRAM, 1, 10);
        let second = deposit(*VAULT_PROGRAM, 2, 20);
        let both = steps(&[first.clone(), second.clone()]);

        assert!(mints_backed(&block(&[&first, &second]), &both));
        assert!(mints_backed(&block(&[]), &steps(&[])));

        // A mint with no deposit behind it, a deposit left unminted, another amount, another
        // order.
        assert!(!mints_backed(&block(&[&first]), &steps(&[])));
        assert!(!mints_backed(&block(&[&first]), &both));
        assert!(!mints_backed(
            &block(&[&deposit(*VAULT_PROGRAM, 1, 11), &second]),
            &both
        ));
        assert!(!mints_backed(&block(&[&second, &first]), &both));
    }

    #[test]
    fn a_deposit_to_another_program_backs_no_mint() {
        let other = deposit(Fr::from(5_u64), 1, 10);

        assert!(mints_backed(
            &block(&[]),
            &steps(std::slice::from_ref(&other))
        ));
        assert!(!mints_backed(&block(&[&other]), &steps(&[other])));
    }

    #[test]
    fn genesis_mints_unbacked() {
        let minted = deposit(*VAULT_PROGRAM, 1, 10);
        let genesis = produce_dummy_block(
            GENESIS_BLOCK_ID,
            None,
            vec![VaultMint::of(&minted).unwrap().transaction().unwrap()],
        );

        assert!(mints_backed(&genesis, &steps(&[])));
    }
}
