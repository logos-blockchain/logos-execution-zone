use common::HashType;
use lee::program::Program;
use lee_core::program::{DEFAULT_PROGRAM_ID, SystemInstruction};

use crate::{AccountIdentity, ExecutionFailureKind, WalletCore};

pub struct SystemProgram<'wallet>(pub &'wallet WalletCore);

impl SystemProgram<'_> {
    pub async fn clear(&self, account: AccountIdentity) -> Result<HashType, ExecutionFailureKind> {
        let instruction_data = Program::serialize_instruction(SystemInstruction::Clear)?;

        self.0
            .send_pub_tx(vec![account], instruction_data, DEFAULT_PROGRAM_ID)
            .await
    }
}
