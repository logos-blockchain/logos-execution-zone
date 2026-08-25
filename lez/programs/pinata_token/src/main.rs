use lee_core::{
    account::{AccountDiff, BalanceDiff, Data},
    program::{
        AccountDiffOutput, ChainedCall, PdaSeed, ProgramCall, ProgramInput, ProgramOutput,
        read_lee_call,
    },
};
use risc0_zkvm::sha::{Impl, Sha256 as _};

const PRIZE: u128 = 150;

type Instruction = u128;

struct Challenge {
    difficulty: u8,
    seed: [u8; 32],
}

impl Challenge {
    fn new(bytes: &[u8]) -> Self {
        assert_eq!(bytes.len(), 33);
        let difficulty = bytes[0];
        assert!(difficulty <= 32);

        let mut seed = [0; 32];
        seed.copy_from_slice(&bytes[1..]);
        Self { difficulty, seed }
    }

    // Checks if the leftmost `self.difficulty` number of bytes of SHA256(self.data || solution) are
    // zero.
    fn validate_solution(&self, solution: Instruction) -> bool {
        let mut bytes = [0; 32 + 16];
        bytes[..32].copy_from_slice(&self.seed);
        bytes[32..].copy_from_slice(&solution.to_le_bytes());
        let digest: [u8; 32] = Impl::hash_bytes(&bytes).as_bytes().try_into().unwrap();
        let difficulty = usize::from(self.difficulty);
        digest[..difficulty].iter().all(|&b| b == 0)
    }

    fn next_data(self) -> Data {
        let mut result = [0; 33];
        result[0] = self.difficulty;
        result[1..].copy_from_slice(Impl::hash_bytes(&self.seed).as_bytes());
        result.to_vec().try_into().expect("should fit")
    }
}

/// A pinata program.
fn main() {
    // Read input accounts.
    // It is expected to receive three accounts: [pinata_definition, pinata_token_holding,
    // winner_token_holding]
    let ProgramCall::Execute(
        ProgramInput {
            self_program_id,
            caller_program_id,
            pre_states,
            instruction: solution,
        },
        instruction_data,
    ) = read_lee_call::<Instruction>();

    let Ok(
        [
            pinata_definition,
            pinata_token_holding,
            winner_token_holding,
        ],
    ) = <[_; 3]>::try_from(pre_states)
    else {
        return;
    };

    let data = Challenge::new(&pinata_definition.account.data);

    if !data.validate_solution(solution) {
        return;
    }

    let pinata_definition_diff = AccountDiff {
        id: pinata_definition.account_id,
        diff_balance: BalanceDiff::Add(0),
        diff_data: Some(data.next_data()),
    };

    // Flip authorization to true for chained call
    let mut pinata_token_holding_for_chain_call = pinata_token_holding.clone();
    pinata_token_holding_for_chain_call.is_authorized = true;

    let chained_call = ChainedCall::new(
        pinata_token_holding.account.program_owner.into(),
        vec![
            pinata_token_holding_for_chain_call,
            winner_token_holding.clone(),
        ],
        &token_core::Instruction::Transfer {
            amount_to_transfer: PRIZE,
        },
    )
    .with_pda_seeds(vec![PdaSeed::new([0; 32])]);

    let pinata_token_holding_id = pinata_token_holding.account_id;
    let winner_token_holding_id = winner_token_holding.account_id;

    ProgramOutput::new(
        self_program_id,
        caller_program_id,
        instruction_data,
        vec![
            pinata_definition,
            pinata_token_holding,
            winner_token_holding,
        ],
        vec![
            AccountDiffOutput::new(pinata_definition_diff),
            AccountDiffOutput::new(AccountDiff::unchanged(pinata_token_holding_id)),
            AccountDiffOutput::new(AccountDiff::unchanged(winner_token_holding_id)),
        ],
    )
    .with_chained_calls(vec![chained_call])
    .write();
}
