pub mod initialize;
pub mod register;
pub mod slash;
pub mod state;

use program_methods::FORUM_MEMBERSHIP_PROOF_ID;
use risc0_zkvm::Receipt;
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize)]
pub struct ProofOutput {
    pub registry_root: [u8; 32],
    pub message_hash: [u8; 32],
    pub tracing_tag: [u8; 32],
}

pub enum MembershipInstruction {
    Initialize { k_strikes: u32, n_moderators: u32, m_moderators: u32 },
    Register { commitment: nssa_core::Commitment, stake_amount: u64 },
    VerifyPost { zk_receipt: Receipt, },
    Slash { slashed_nsk: [u8; 32], },
}

pub fn process_instruction(
    forum: &mut state::ForumInstance, 
    instruction: MembershipInstruction,
) -> Result<(), &'static str> {
    match instruction {
        MembershipInstruction::Initialize { k_strikes, n_moderators, m_moderators } => {
            *forum = initialize::process_initialize(k_strikes, n_moderators, m_moderators)?;
            Ok(())
        }
        MembershipInstruction::Register { commitment, stake_amount } => {
            register::process_register(forum, commitment, stake_amount)?;
            Ok(())
        }
        MembershipInstruction::VerifyPost { zk_receipt } => {
            // 1. RISC Zero cryptographic verification
            zk_receipt.verify(FORUM_MEMBERSHIP_PROOF_ID)
                .map_err(|_| "ZK Verification Failed: Receipt tidak valid")?;

            // 2. Decode journal
            let journal: ProofOutput = zk_receipt.journal.decode()
                .map_err(|_| "Failed to decode ZK journal")?;

            // 3. Match it with the on-chain root
            if journal.registry_root != forum.registry.root() {
                return Err("ZK Error: The Merkle Tree root does not match the on-chain state");
            }

            println!("[CONTRACT] Anonymous post verified with Tag: {:?}", journal.tracing_tag);
            Ok(())
        }
        MembershipInstruction::Slash { slashed_nsk } => {
            let nsk_obj = nssa_core::NullifierSecretKey::from(slashed_nsk);
            slash::process_slash(forum, &nsk_obj)?;
            Ok(())
        }
    }
}