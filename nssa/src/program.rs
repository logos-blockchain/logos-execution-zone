use borsh::{BorshDeserialize, BorshSerialize};
use nssa_core::{
    account::AccountWithMetadata,
    program::{InstructionData, ProgramId, ProgramOutput},
};
use risc0_zkvm::{ExecutorEnv, ExecutorEnvBuilder, default_executor, serde::to_vec};
use serde::Serialize;

use crate::{
    error::NssaError,
    program_methods::{AMM_ELF, AUTHENTICATED_TRANSFER_ELF, PINATA_ELF, TOKEN_ELF},
};

/// Maximum number of cycles for a public execution.
/// TODO: Make this variable when fees are implemented.
const MAX_NUM_CYCLES_PUBLIC_EXECUTION: u64 = 1024 * 1024 * 32; // 32M cycles

#[derive(Clone, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct Program {
    id: ProgramId,
    elf: Vec<u8>,
}

impl Program {
    pub fn new(bytecode: Vec<u8>) -> Result<Self, NssaError> {
        let binary = risc0_binfmt::ProgramBinary::decode(&bytecode)
            .map_err(NssaError::InvalidProgramBytecode)?;
        let id = binary
            .compute_image_id()
            .map_err(NssaError::InvalidProgramBytecode)?
            .into();
        Ok(Self { elf: bytecode, id })
    }

    #[must_use]
    pub const fn id(&self) -> ProgramId {
        self.id
    }

    #[must_use]
    pub fn elf(&self) -> &[u8] {
        &self.elf
    }

    pub fn serialize_instruction<T: Serialize>(
        instruction: T,
    ) -> Result<InstructionData, NssaError> {
        to_vec(&instruction).map_err(|e| NssaError::InstructionSerializationError(e.to_string()))
    }

    pub(crate) fn execute(
        &self,
        pre_states: &[AccountWithMetadata],
        instruction_data: &InstructionData,
    ) -> Result<ProgramOutput, NssaError> {
        // Write inputs to the program
        let mut env_builder = ExecutorEnv::builder();
        env_builder.session_limit(Some(MAX_NUM_CYCLES_PUBLIC_EXECUTION));
        Self::write_inputs(pre_states, instruction_data, &mut env_builder)?;
        let env = env_builder.build().unwrap();

        // Execute the program (without proving)
        let executor = default_executor();
        let session_info = executor
            .execute(env, self.elf())
            .map_err(|e| NssaError::ProgramExecutionFailed(e.to_string()))?;

        // Get outputs
        let program_output = session_info
            .journal
            .decode()
            .map_err(|e| NssaError::ProgramExecutionFailed(e.to_string()))?;

        Ok(program_output)
    }

    /// Writes inputs to `env_builder` in the order expected by the programs.
    pub(crate) fn write_inputs(
        pre_states: &[AccountWithMetadata],
        instruction_data: &[u32],
        env_builder: &mut ExecutorEnvBuilder,
    ) -> Result<(), NssaError> {
        let pre_states = pre_states.to_vec();
        env_builder
            .write(&(pre_states, instruction_data))
            .map_err(|e| NssaError::ProgramWriteInputFailed(e.to_string()))?;
        Ok(())
    }

    #[must_use]
    pub fn authenticated_transfer_program() -> Self {
        // This unwrap won't panic since the `AUTHENTICATED_TRANSFER_ELF` comes from risc0 build of
        // `program_methods`
        Self::new(AUTHENTICATED_TRANSFER_ELF.to_vec()).unwrap()
    }

    #[must_use]
    pub fn token() -> Self {
        // This unwrap won't panic since the `TOKEN_ELF` comes from risc0 build of
        // `program_methods`
        Self::new(TOKEN_ELF.to_vec()).unwrap()
    }

    #[must_use]
    pub fn amm() -> Self {
        Self::new(AMM_ELF.to_vec()).expect("The AMM program must be a valid Risc0 program")
    }
}

// TODO: Testnet only. Refactor to prevent compilation on mainnet.
impl Program {
    #[must_use]
    pub fn pinata() -> Self {
        // This unwrap won't panic since the `PINATA_ELF` comes from risc0 build of
        // `program_methods`
        Self::new(PINATA_ELF.to_vec()).unwrap()
    }

    #[must_use]
    #[expect(clippy::non_ascii_literal, reason = "More readable")]
    pub fn pinata_token() -> Self {
        use crate::program_methods::PINATA_TOKEN_ELF;
        Self::new(PINATA_TOKEN_ELF.to_vec()).expect("Piñata program must be a valid R0BF file")
    }
}

#[cfg(test)]
mod tests {
    use nssa_core::account::{Account, AccountId, AccountWithMetadata};

    use crate::{
        program::Program,
        program_methods::{
            AUTHENTICATED_TRANSFER_ELF, AUTHENTICATED_TRANSFER_ID, PINATA_ELF, PINATA_ID,
            TOKEN_ELF, TOKEN_ID,
        },
    };

    impl Program {
        /// A program that changes the nonce of an account.
        #[must_use]
        pub fn nonce_changer_program() -> Self {
            use test_program_methods::{NONCE_CHANGER_ELF, NONCE_CHANGER_ID};

            Self {
                id: NONCE_CHANGER_ID,
                elf: NONCE_CHANGER_ELF.to_vec(),
            }
        }

        /// A program that produces more output accounts than the inputs it received.
        #[must_use]
        pub fn extra_output_program() -> Self {
            use test_program_methods::{EXTRA_OUTPUT_ELF, EXTRA_OUTPUT_ID};

            Self {
                id: EXTRA_OUTPUT_ID,
                elf: EXTRA_OUTPUT_ELF.to_vec(),
            }
        }

        /// A program that produces less output accounts than the inputs it received.
        #[must_use]
        pub fn missing_output_program() -> Self {
            use test_program_methods::{MISSING_OUTPUT_ELF, MISSING_OUTPUT_ID};

            Self {
                id: MISSING_OUTPUT_ID,
                elf: MISSING_OUTPUT_ELF.to_vec(),
            }
        }

        /// A program that changes the program owner of an account to [0, 1, 2, 3, 4, 5, 6, 7].
        #[must_use]
        pub fn program_owner_changer() -> Self {
            use test_program_methods::{PROGRAM_OWNER_CHANGER_ELF, PROGRAM_OWNER_CHANGER_ID};

            Self {
                id: PROGRAM_OWNER_CHANGER_ID,
                elf: PROGRAM_OWNER_CHANGER_ELF.to_vec(),
            }
        }

        /// A program that transfers balance without caring about authorizations.
        #[must_use]
        pub fn simple_balance_transfer() -> Self {
            use test_program_methods::{SIMPLE_BALANCE_TRANSFER_ELF, SIMPLE_BALANCE_TRANSFER_ID};

            Self {
                id: SIMPLE_BALANCE_TRANSFER_ID,
                elf: SIMPLE_BALANCE_TRANSFER_ELF.to_vec(),
            }
        }

        /// A program that modifies the data of an account.
        #[must_use]
        pub fn data_changer() -> Self {
            use test_program_methods::{DATA_CHANGER_ELF, DATA_CHANGER_ID};

            Self {
                id: DATA_CHANGER_ID,
                elf: DATA_CHANGER_ELF.to_vec(),
            }
        }

        /// A program that mints balance.
        #[must_use]
        pub fn minter() -> Self {
            use test_program_methods::{MINTER_ELF, MINTER_ID};

            Self {
                id: MINTER_ID,
                elf: MINTER_ELF.to_vec(),
            }
        }

        /// A program that burns balance.
        #[must_use]
        pub fn burner() -> Self {
            use test_program_methods::{BURNER_ELF, BURNER_ID};

            Self {
                id: BURNER_ID,
                elf: BURNER_ELF.to_vec(),
            }
        }

        #[must_use]
        pub fn chain_caller() -> Self {
            use test_program_methods::{CHAIN_CALLER_ELF, CHAIN_CALLER_ID};

            Self {
                id: CHAIN_CALLER_ID,
                elf: CHAIN_CALLER_ELF.to_vec(),
            }
        }

        #[must_use]
        pub fn claimer() -> Self {
            use test_program_methods::{CLAIMER_ELF, CLAIMER_ID};

            Self {
                id: CLAIMER_ID,
                elf: CLAIMER_ELF.to_vec(),
            }
        }

        #[must_use]
        pub fn changer_claimer() -> Self {
            use test_program_methods::{CHANGER_CLAIMER_ELF, CHANGER_CLAIMER_ID};

            Self {
                id: CHANGER_CLAIMER_ID,
                elf: CHANGER_CLAIMER_ELF.to_vec(),
            }
        }

        #[must_use]
        pub fn noop() -> Self {
            use test_program_methods::{NOOP_ELF, NOOP_ID};

            Self {
                id: NOOP_ID,
                elf: NOOP_ELF.to_vec(),
            }
        }

        #[must_use]
        pub fn malicious_authorization_changer() -> Self {
            use test_program_methods::{
                MALICIOUS_AUTHORIZATION_CHANGER_ELF, MALICIOUS_AUTHORIZATION_CHANGER_ID,
            };

            Self {
                id: MALICIOUS_AUTHORIZATION_CHANGER_ID,
                elf: MALICIOUS_AUTHORIZATION_CHANGER_ELF.to_vec(),
            }
        }

        #[must_use]
        pub fn modified_transfer_program() -> Self {
            use test_program_methods::MODIFIED_TRANSFER_ELF;
            // This unwrap won't panic since the `MODIFIED_TRANSFER_ELF` comes from risc0 build of
            // `program_methods`
            Self::new(MODIFIED_TRANSFER_ELF.to_vec()).unwrap()
        }
    }

    #[test]
    fn program_execution() {
        let program = Program::simple_balance_transfer();
        let balance_to_move: u128 = 11_223_344_556_677;
        let instruction_data = Program::serialize_instruction(balance_to_move).unwrap();
        let sender = AccountWithMetadata::new(
            Account {
                balance: 77_665_544_332_211,
                ..Account::default()
            },
            true,
            AccountId::new([0; 32]),
        );
        let recipient =
            AccountWithMetadata::new(Account::default(), false, AccountId::new([1; 32]));

        let expected_sender_post = Account {
            balance: 77_665_544_332_211 - balance_to_move,
            ..Account::default()
        };
        let expected_recipient_post = Account {
            balance: balance_to_move,
            ..Account::default()
        };
        let program_output = program
            .execute(&[sender, recipient], &instruction_data)
            .unwrap();

        let [sender_post, recipient_post] = program_output.post_states.try_into().unwrap();

        assert_eq!(sender_post.account(), &expected_sender_post);
        assert_eq!(recipient_post.account(), &expected_recipient_post);
    }

    #[test]
    fn builtin_programs() {
        let auth_transfer_program = Program::authenticated_transfer_program();
        let token_program = Program::token();
        let pinata_program = Program::pinata();

        assert_eq!(auth_transfer_program.id, AUTHENTICATED_TRANSFER_ID);
        assert_eq!(auth_transfer_program.elf, AUTHENTICATED_TRANSFER_ELF);
        assert_eq!(token_program.id, TOKEN_ID);
        assert_eq!(token_program.elf, TOKEN_ELF);
        assert_eq!(pinata_program.id, PINATA_ID);
        assert_eq!(pinata_program.elf, PINATA_ELF);
    }
}
