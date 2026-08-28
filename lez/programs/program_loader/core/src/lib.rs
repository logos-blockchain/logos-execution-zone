use borsh::{BorshDeserialize, BorshSerialize};
pub use lee_core::program::{PdaSeed, ProgramData};
use lee_core::{
    account::{Account, AccountId, AccountWithMetadata, Data},
    program::{AccountPostState, Claim, ProgramId},
};

const DEPLOY_HEADER_SEED_DOMAIN_SEPARATOR: AccountId =
    AccountId::new(*b"/LEZ/v0.3/LoaderDeployHeaderSeed");
const DEPLOY_SEGMENT_SEED_DOMAIN_SEPARATOR: AccountId =
    AccountId::new(*b"/LEZ/v0.3/LoaderDeploySegmentSee");

#[derive(BorshSerialize, BorshDeserialize)]
pub enum Instruction {
    /// Deploys a new program: writes its `ProgramData` header and one bytecode segment, each
    /// claimed as a PDA of the loader.
    ///
    /// Required accounts (2), in order:
    /// - The target `ProgramData` header PDA account (must be `Account::default()`)
    /// - The target segment PDA account holding the raw bytecode (must be `Account::default()`)
    Deploy { bytecode: Vec<u8> },
}

/// Derives the PDA seed for a deployed program's `ProgramData` header account.
///
/// Combines the program's content-derived identity (`image_id`), its position in a (currently
/// always single-segment) split (`segment_number`), and who may redeploy it (`update_auth`).
///
/// Domain-separated from other PDA-seed derivations in the codebase, including
/// [`segment_pda_seed`], so a header seed can never collide with a segment seed (or
/// anything else) even when the input triple coincides.
#[must_use]
pub fn header_pda_seed(
    image_id: ProgramId,
    segment_number: u32,
    update_auth: AccountId,
) -> PdaSeed {
    pda_seed(
        DEPLOY_HEADER_SEED_DOMAIN_SEPARATOR,
        image_id,
        segment_number,
        update_auth,
    )
}

/// Derives the PDA seed for a deployed program's bytecode segment account.
///
/// Same inputs as [`header_pda_seed`], domain-separated so the two never collide. Kept as
/// a distinct account from the header specifically so that authenticating a program's identity
/// (e.g. for privacy-preserving proof verification) never has to touch its bytecode: the only
/// account-authentication primitive available is whole-account equality, so what's bundled into
/// one account sets the floor for how cheap that authentication can be.
#[must_use]
pub fn segment_pda_seed(
    image_id: ProgramId,
    segment_number: u32,
    update_auth: AccountId,
) -> PdaSeed {
    pda_seed(
        DEPLOY_SEGMENT_SEED_DOMAIN_SEPARATOR,
        image_id,
        segment_number,
        update_auth,
    )
}

fn pda_seed(
    domain_separator: AccountId,
    image_id: ProgramId,
    segment_number: u32,
    update_auth: AccountId,
) -> PdaSeed {
    use risc0_zkvm::sha::{Impl, Sha256 as _};

    let mut bytes = [0_u8; 32 + 32 + 4 + 32];
    bytes[0..32].copy_from_slice(domain_separator.as_ref());
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
pub fn header_account_id(
    loader_account_id: AccountId,
    image_id: ProgramId,
    segment_number: u32,
    update_auth: AccountId,
) -> AccountId {
    AccountId::for_public_pda(
        &loader_account_id,
        &header_pda_seed(image_id, segment_number, update_auth),
    )
}

#[must_use]
pub fn segment_account_id(
    loader_account_id: AccountId,
    image_id: ProgramId,
    segment_number: u32,
    update_auth: AccountId,
) -> AccountId {
    AccountId::for_public_pda(
        &loader_account_id,
        &segment_pda_seed(image_id, segment_number, update_auth),
    )
}

/// The dispatch address a program with `image_id` lives at once deployed via `Deploy` with no
/// upgrade authority.
///
/// `segment_number` 0, `update_auth` `AccountId::default()`. What every genesis-seeded builtin,
/// and any `Deploy` submitted with a default `update_auth`, dispatches at.
#[must_use]
pub fn immutable_deploy_account_id(image_id: ProgramId) -> AccountId {
    header_account_id(
        lee_core::program::PROGRAM_LOADER_ACCOUNT_ID,
        image_id,
        0,
        AccountId::default(),
    )
}

/// Executes the `Deploy` instruction.
///
/// Verifies `bytecode` decodes as a valid RISC0 program binary, derives its header and segment
/// PDAs, and claims both. Called natively from dispatch's `PROGRAM_LOADER_ACCOUNT_ID`
/// shortcut (see that constant's doc comment in `lee_core::program`).
#[must_use]
pub fn execute_deploy(
    self_account_id: AccountId,
    pre_states: Vec<AccountWithMetadata>,
    bytecode: Vec<u8>,
) -> Vec<AccountPostState> {
    let image_id: ProgramId = risc0_binfmt::compute_image_id(&bytecode)
        .expect("bytecode must decode as a valid RISC0 program binary")
        .into();
    let segment_number = 0_u32;
    let update_auth = AccountId::default();
    let header_seed = header_pda_seed(image_id, segment_number, update_auth);
    let segment_seed = segment_pda_seed(image_id, segment_number, update_auth);
    let header_pda = AccountId::for_public_pda(&self_account_id, &header_seed);
    let segment_pda = AccountId::for_public_pda(&self_account_id, &segment_seed);

    let [header_target, segment_target] = pre_states
        .try_into()
        .expect("Deploy requires exactly 2 accounts");

    assert_eq!(
        header_target.account_id, header_pda,
        "wrong deployment header target account"
    );
    assert_eq!(
        header_target.account,
        Account::default(),
        "program header already deployed"
    );
    assert_eq!(
        segment_target.account_id, segment_pda,
        "wrong deployment segment target account"
    );
    assert_eq!(
        segment_target.account,
        Account::default(),
        "program segment already deployed"
    );

    let program_data = ProgramData {
        image_id,
        segment_number,
        update_auth,
    };

    vec![
        AccountPostState::new_claimed(
            Account {
                data: Data::from(&program_data),
                ..Account::default()
            },
            Claim::Pda(header_seed),
        ),
        AccountPostState::new_claimed(
            Account {
                data: Data::try_from(bytecode).expect("elf must fit under DATA_MAX_LENGTH"),
                ..Account::default()
            },
            Claim::Pda(segment_seed),
        ),
    ]
}
