use std::convert::Infallible;

use lee_core::{
    account::{Account, AccountDiff, BalanceDiff, Data},
    program::{
        AccountDiffOutput, Claim, ProgramCall, ProgramInput, ProgramOutput, read_lee_call,
        write_update_from_diff_output,
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

    fn next_data(self) -> [u8; 33] {
        let mut result = [0; 33];
        result[0] = self.difficulty;
        result[1..].copy_from_slice(Impl::hash_bytes(&self.seed).as_bytes());
        result
    }
}

/// A pinata program.
fn main() {
    // Read input accounts.
    // It is expected to receive only two accounts: [pinata_account, winner_account]
    let (
        ProgramInput {
            self_program_id,
            caller_program_id,
            pre_states,
            instruction: solution,
        },
        instruction_words,
    ) = match read_lee_call::<Instruction>() {
        ProgramCall::Execute(input, instruction_words) => (input, instruction_words),
        ProgramCall::UpdateFromDiff {
            pre_state,
            diff_data,
        } => {
            let data = update_from_diff(pre_state.clone(), diff_data.clone())
                .expect("update_from_diff should not fail");
            write_update_from_diff_output(pre_state, diff_data, data);
            return;
        }
    };

    let Ok([pinata, winner]) = <[_; 2]>::try_from(pre_states) else {
        return;
    };

    let data = Challenge::new(&pinata.account.data);

    if !data.validate_solution(solution) {
        return;
    }

    let pinata_post = AccountDiffOutput::new_claimed_if_default(
        AccountDiff {
            id: pinata.account_id,
            diff_balance: BalanceDiff::Sub(PRIZE),
            diff_data: Some(
                data.next_data()
                    .to_vec()
                    .try_into()
                    .expect("challenge data fits in account data"),
            ),
        },
        pinata.account.program_owner.into(),
        Claim::Authorized,
    );
    let winner_post = AccountDiffOutput::new(AccountDiff {
        id: winner.account_id,
        diff_balance: BalanceDiff::Add(PRIZE),
        diff_data: None,
    });

    ProgramOutput::new(
        self_program_id,
        caller_program_id,
        instruction_words,
        vec![pinata, winner],
        vec![pinata_post, winner_post],
    )
    .write();
}

fn update_from_diff(_pre_state: Account, diff_data: Data) -> Result<Data, Infallible> {
    Ok(diff_data)
}
