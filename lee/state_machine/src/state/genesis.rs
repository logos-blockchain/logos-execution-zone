//! Seeding a state with programs, which only genesis and tests do.

use lee_core::{
    RecoveryBinding,
    account::{Account, AccountId, ActorState},
    program::{PROGRAM_LOADER_ACCOUNT_ID, ProgramHeader, ProgramId, immutable_mirror_commitment},
};
use program_loader_core::LoaderActorState as _;

use super::V03State;
use crate::program::Program;

/// Builds a genesis state: the only way outside tests to seed programs, and always onto a fresh
/// state.
#[derive(Default)]
pub struct GenesisBuilder(V03State);

impl GenesisBuilder {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    #[must_use]
    pub fn with_public_accounts(
        self,
        public_accounts: impl IntoIterator<Item = (AccountId, Account)>,
    ) -> Self {
        Self(self.0.with_public_accounts(public_accounts))
    }

    #[must_use]
    pub fn with_recovery_bindings(
        self,
        bindings: impl IntoIterator<Item = RecoveryBinding>,
    ) -> Self {
        Self(self.0.with_recovery_bindings(bindings))
    }

    /// Seeds each program at its given address, `immutable` or not.
    #[must_use]
    pub fn with_programs_at(
        mut self,
        programs: impl IntoIterator<Item = (AccountId, Program, bool)>,
    ) -> Self {
        for (account_id, program, immutable) in programs {
            self.0.insert_program_at(account_id, &program, immutable);
        }
        self
    }

    #[must_use]
    pub fn build(self) -> V03State {
        self.0
    }
}

impl V03State {
    /// Seeds a program as a loader-owned header pointing at a segment chain holding its
    /// `user_elf`, chunked the same way a live `program_loader` deploy would. Private to this
    /// module: outside tests (`test-utils`), only [`GenesisBuilder`] reaches it, and it starts from
    /// an empty state, so a live state never gains a program this way.
    fn insert_program_at(
        &mut self,
        header_account_id: AccountId,
        program: &Program,
        immutable: bool,
    ) {
        let binary = risc0_binfmt::ProgramBinary::decode(program.elf())
            .expect("builtin program must be a valid ProgramBinary");
        let image_id: ProgramId =
            risc0_binfmt::compute_image_id(&crate::program::attach_kernel(binary.user_elf))
                .expect("builtin program must have a computable image id")
                .into();
        assert_eq!(
            image_id,
            program.id(),
            "builtin program's image id does not match its bytecode"
        );
        let user_elf = binary.user_elf.to_vec();

        let segment_account_ids: Vec<AccountId> =
            (0..program_loader_core::segment_count(&user_elf))
                .map(|i| genesis_segment_account_id(header_account_id, i))
                .collect();
        let segments = program_loader_core::build_segments(&user_elf, &segment_account_ids)
            .expect("builtin program must split into a valid segment chain");

        for (segment_account_id, segment) in segment_account_ids.iter().zip(segments) {
            let segment = Account::default().with_actor_state(
                PROGRAM_LOADER_ACCOUNT_ID,
                ActorState::from(segment.to_loader_actor_state()),
            );
            self.public_state.insert_mut(*segment_account_id, segment);
        }

        let program_header = ProgramHeader {
            image_id: program.id(),
            program_first_segment: segment_account_ids[0],
            immutable,
        };
        let header = Account::default().with_actor_state(
            PROGRAM_LOADER_ACCOUNT_ID,
            ActorState::from(program_header.to_loader_actor_state()),
        );
        self.public_state.insert_mut(header_account_id, header);

        if immutable {
            let commitment = immutable_mirror_commitment(header_account_id, &program_header);
            self.private_state.0.extend(&[commitment]);
        }
    }
}

#[cfg(any(test, feature = "test-utils"))]
impl V03State {
    /// Seeds each program at its given address, `immutable` or not.
    #[must_use]
    pub fn with_programs_at(
        mut self,
        programs: impl IntoIterator<Item = (AccountId, Program, bool)>,
    ) -> Self {
        for (account_id, program, immutable) in programs {
            self.insert_program_at(account_id, &program, immutable);
        }
        self
    }

    /// Seeds each program immutable, at the address derived from its image ID.
    #[must_use]
    pub fn with_programs(mut self, programs: impl IntoIterator<Item = Program>) -> Self {
        for program in programs {
            self.insert_program_at(
                AccountId::from_builtin_program(program.id()),
                &program,
                true,
            );
        }
        self
    }
}

/// The deterministic `AccountId` a genesis-seeded builtin's `index`-th segment lives at.
/// Only `insert_program_at` needs this — a live deploy has a real signer to pick addresses instead.
fn genesis_segment_account_id(header_account_id: AccountId, index: usize) -> AccountId {
    use sha2::{Digest as _, Sha256};
    const GENESIS_SEGMENT_ID_PREFIX: &[u8; 32] = b"/LEE/v0.3/AccountId/GenesisSeg/\x00";

    let mut hasher = Sha256::new();
    hasher.update(GENESIS_SEGMENT_ID_PREFIX);
    hasher.update(header_account_id.as_ref());
    hasher.update(
        u32::try_from(index)
            .expect("segment count fits in u32")
            .to_le_bytes(),
    );
    AccountId::new(hasher.finalize().into())
}
