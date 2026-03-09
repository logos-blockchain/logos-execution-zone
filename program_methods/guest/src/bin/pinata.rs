use nssa_core::program::{AccountPostState, ProgramInput, read_nssa_inputs, write_nssa_outputs};
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
            pre_states,
            instruction: solution,
        },
        instruction_words,
    ) = read_nssa_inputs::<Instruction>();

    let Ok([pinata, winner]) = <[_; 2]>::try_from(pre_states) else {
        return;
    };

    let data = Challenge::new(&pinata.account.data);

    if !data.validate_solution(solution) {
        return;
    }

    let mut pinata_post = pinata.account.clone();
    let mut winner_post = winner.account.clone();
    pinata_post.balance = pinata_post
        .balance
        .checked_sub(PRIZE)
        .expect("Not enough balance in the pinata");
    pinata_post.data = data
        .next_data()
        .to_vec()
        .try_into()
        .expect("33 bytes should fit into Data");
    winner_post.balance = winner_post
        .balance
        .checked_add(PRIZE)
        .expect("Overflow when adding prize to winner");

    write_nssa_outputs(
        instruction_words,
        vec![pinata, winner],
        vec![
            AccountPostState::new_claimed_if_default(pinata_post),
            AccountPostState::new(winner_post),
        ],
    );
}
