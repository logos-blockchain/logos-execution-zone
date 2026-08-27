use lee_core::{
    account::{AccountDiff, BalanceDiff, Data},
    program::{AccountDiffOutput, ChainedCall, PdaSeed, ProgramCall, read_lee_call},
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
    let ProgramCall::Execute {
        input,
        instruction: solution,
    } = read_lee_call::<Instruction>();

    let [
        pinata_definition,
        pinata_token_holding,
        winner_token_holding,
    ] = input.pre_states.as_slice()
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

    let chained_call = ChainedCall::new(
        pinata_token_holding.account.program_owner.into(),
        vec![
            pinata_token_holding.account_id,
            winner_token_holding.account_id,
        ],
        &token_core::Instruction::Transfer {
            amount_to_transfer: PRIZE,
        },
    )
    .with_pda_seeds(vec![PdaSeed::new([0; 32])]);

    let post_states = vec![
        AccountDiffOutput::new(pinata_definition_diff),
        AccountDiffOutput::unchanged(pinata_token_holding.account_id),
        AccountDiffOutput::unchanged(winner_token_holding.account_id),
    ];

    input
        .into_output(post_states)
        .with_chained_calls(vec![chained_call])
        .write();
}
