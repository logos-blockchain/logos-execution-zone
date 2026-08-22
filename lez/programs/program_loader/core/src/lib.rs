pub use lee_core::program::PdaSeed;
use lee_core::{
    account::{Account, AccountId, AccountWithMetadata, Data},
    program::{AccountPostState, Claim, ProgramId},
};
use serde::{Deserialize, Serialize};

const DEPLOY_SEED_DOMAIN_SEPARATOR: AccountId =
    AccountId::new(*b"/LEZ/v0.3/LoaderDeploySeed/00000");

#[derive(Serialize, Deserialize)]
pub enum Instruction {
    /// Deploys a new program, claiming its `ProgramData` account as a PDA of the loader.
    ///
    /// Required accounts (1):
    /// - The target `ProgramData` PDA account (must be `Account::default()`)
    Deploy { bytecode: Vec<u8> },
}

#[derive(Debug, PartialEq, Eq, borsh::BorshSerialize, borsh::BorshDeserialize)]
pub struct ProgramData {
    pub image_id: ProgramId,
    pub segment_number: u32,
    pub update_auth: AccountId,
    pub elf_segment: Vec<u8>,
}

impl TryFrom<&Data> for ProgramData {
    type Error = std::io::Error;

    fn try_from(data: &Data) -> Result<Self, Self::Error> {
        borsh::BorshDeserialize::try_from_slice(data.as_ref())
    }
}

impl From<&ProgramData> for Data {
    fn from(program_data: &ProgramData) -> Self {
        let mut data = Vec::with_capacity(std::mem::size_of_val(program_data));
        borsh::BorshSerialize::serialize(program_data, &mut data)
            .expect("borsh serialization should not fail");
        Self::try_from(data).expect("elf must fit under DATA_MAX_LENGTH")
    }
}

/// Derives the PDA seed for a deployed program's `ProgramData` account.
///
/// Domain-separated from other PDA-seed derivations in the codebase so that a `deploy_pda_seed`
/// output can never collide with a seed meant for a different purpose, even if the input triple
/// happened to coincide.
#[must_use]
pub fn deploy_pda_seed(
    image_id: ProgramId,
    segment_number: u32,
    update_auth: AccountId,
) -> PdaSeed {
    use risc0_zkvm::sha::{Impl, Sha256 as _};

    let mut bytes = [0_u8; 32 + 32 + 4 + 32];
    bytes[0..32].copy_from_slice(DEPLOY_SEED_DOMAIN_SEPARATOR.as_ref());
    let image_id_bytes: &[u8] =
        bytemuck::try_cast_slice(&image_id).expect("ProgramId should be castable to &[u8]");
    bytes[32..64].copy_from_slice(image_id_bytes);
    bytes[64..68].copy_from_slice(&segment_number.to_le_bytes());
    bytes[68..].copy_from_slice(update_auth.as_ref());

    PdaSeed::new(
        Impl::hash_bytes(&bytes)
            .as_bytes()
            .try_into()
            .expect("Hash output must be exactly 32 bytes long"),
    )
}

#[must_use]
pub fn deploy_account_id(
    loader_program_id: ProgramId,
    image_id: ProgramId,
    segment_number: u32,
    update_auth: AccountId,
) -> AccountId {
    AccountId::for_public_pda(
        &loader_program_id,
        &deploy_pda_seed(image_id, segment_number, update_auth),
    )
}

/// Executes the `Deploy` instruction: verifies `bytecode` decodes as a valid RISC0 program
/// binary, derives its `ProgramData` PDA, and claims it.
#[must_use]
pub fn execute_deploy(
    self_program_id: ProgramId,
    pre_states: Vec<AccountWithMetadata>,
    bytecode: Vec<u8>,
) -> Vec<AccountPostState> {
    let image_id: ProgramId = risc0_binfmt::compute_image_id(&bytecode)
        .expect("bytecode must decode as a valid RISC0 program binary")
        .into();
    let segment_number = 0_u32;
    let update_auth = AccountId::default();
    let seed = deploy_pda_seed(image_id, segment_number, update_auth);
    let pda = AccountId::for_public_pda(&self_program_id, &seed);

    let [target] = pre_states
        .try_into()
        .expect("Deploy requires exactly 1 account");

    assert_eq!(target.account_id, pda, "wrong deployment target account");
    assert_eq!(
        target.account,
        Account::default(),
        "program already deployed"
    );

    let program_data = ProgramData {
        image_id,
        segment_number,
        update_auth,
        elf_segment: bytecode,
    };

    vec![AccountPostState::new_claimed(
        Account {
            data: Data::from(&program_data),
            ..Account::default()
        },
        Claim::Pda(seed),
    )]
}
