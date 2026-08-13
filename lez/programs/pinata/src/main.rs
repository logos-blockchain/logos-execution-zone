use lee_core::program::{
    AccountPostState, ChainedCall, ProgramInput, ProgramOutput, read_lee_inputs,
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
    let (
        ProgramInput {
            self_program_id,
            caller_program_id,
            pre_states,
            instruction: solution,
        },
        instruction_words,
    ) = read_lee_inputs::<Instruction>();

    let Ok([challenge, prize_pda, winner]) = <[_; 3]>::try_from(pre_states) else {
        return;
    };

    assert_eq!(
        prize_pda.account_id,
        pinata_core::compute_pinata_prize_account_id(self_program_id),
        "Second account must be the prize-pool PDA"
    );

    let data = Challenge::new(&challenge.account.data);

    if !data.validate_solution(solution) {
        return;
    }

    let mut challenge_post = challenge.account.clone();
    let prize_pda_post = prize_pda.account.clone();
    let winner_post = winner.account.clone();
    challenge_post.data = data
        .next_data()
        .to_vec()
        .try_into()
        .expect("33 bytes should fit into Data");

    let mut prize_authorized = prize_pda.clone();
    prize_authorized.is_authorized = true;

    let chained_call = ChainedCall::new(
        prize_authorized.account.program_owner,
        vec![prize_authorized, winner.clone()],
        &authenticated_transfer_core::Instruction::Transfer { amount: PRIZE },
    )
    .with_pda_seeds(vec![pinata_core::compute_pinata_prize_seed()]);

    ProgramOutput::new(
        self_program_id,
        caller_program_id,
        instruction_words,
        vec![challenge, prize_pda, winner],
        vec![
            AccountPostState::new(challenge_post),
            AccountPostState::new(prize_pda_post),
            AccountPostState::new(winner_post),
        ],
    )
    .with_chained_calls(vec![chained_call])
    .write();
}
