use common::HashType;
use lee::{AccountId, program::Program};
use lee_core::program::{DEFAULT_PROGRAM_ID, SystemInstruction};

use crate::{AccountIdentity, ExecutionFailureKind, WalletCore};

pub struct SystemProgram<'wallet>(pub &'wallet WalletCore);

impl SystemProgram<'_> {
    pub async fn clear(
        &self,
        account: AccountIdentity,
        new_owner: Option<AccountId>,
    ) -> Result<HashType, ExecutionFailureKind> {
        let instruction = SystemInstruction::Clear { new_owner };
        let instruction_data =
            Program::serialize_instruction(instruction).expect("Instruction should serialize");

        self.0
            .send_pub_tx(vec![account], instruction_data, DEFAULT_PROGRAM_ID)
            .await
    }
}
