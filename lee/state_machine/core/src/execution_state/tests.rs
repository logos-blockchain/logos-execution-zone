use super::*;
use crate::{account::Account, encryption::ViewingPublicKey};

const PROGRAM: AccountId = AccountId::new([0; 32]);
const OTHER_PROGRAM: AccountId = AccountId::new([1; 32]);
const SEED: PdaSeed = PdaSeed::new([2; 32]);
const OTHER_SEED: PdaSeed = PdaSeed::new([3; 32]);

fn witness_with(kind: WitnessKind) -> PrivateWitness {
    PrivateWitness {
        account: Account::default(),
        vpk: ViewingPublicKey::from_seed(&[4; 32], &[5; 32]),
        random_seed: [6; 32],
        identifier: 0,
        kind,
        nullifier: NullifierWitness::Init {
            npk: NullifierPublicKey([7; 32]),
            commitment_root: [8; 32],
        },
    }
}

fn pda_witness() -> PrivateWitness {
    witness_with(WitnessKind::Pda {
        binding: (PROGRAM, SEED),
    })
}

#[test]
fn a_delegated_seed_grants_the_binding_that_names_its_caller() {
    assert_eq!(
        private_seed_grant(Some(PROGRAM), &[OTHER_SEED, SEED], &pda_witness()),
        Some((PROGRAM, SEED))
    );
}

#[test]
fn a_caller_other_than_the_bound_program_grants_nothing() {
    assert_eq!(
        private_seed_grant(Some(OTHER_PROGRAM), &[SEED], &pda_witness()),
        None
    );
}

#[test]
fn an_undelegated_seed_grants_nothing() {
    assert_eq!(
        private_seed_grant(Some(PROGRAM), &[OTHER_SEED], &pda_witness()),
        None
    );
}

#[test]
fn a_regular_witness_has_no_binding_to_grant() {
    let witness = witness_with(WitnessKind::Regular { ask: None });
    assert_eq!(private_seed_grant(Some(PROGRAM), &[SEED], &witness), None);
}
