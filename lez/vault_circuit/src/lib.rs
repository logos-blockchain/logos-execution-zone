//! The rule of the LEZ vault, a Bedrock program holding the value behind bridged tokens.
//!
//! Bedrock's own program spend proof covers conservation and note membership. This proof adds
//! that the committee named by the vault notes signed the inscription, that the deposits it
//! consumes were made out to that committee, and that the notes it creates are well formed.

#![expect(
    clippy::arithmetic_side_effects,
    reason = "Field and curve arithmetic does not overflow"
)]

use std::sync::LazyLock;

use ark_bn254::{Bn254, Fr};
use ark_ec::{AffineRepr as _, CurveGroup as _};
use ark_ed_on_bn254::{EdwardsAffine, Fr as Scalar};
use ark_ff::{BigInteger as _, PrimeField as _};
use ark_groth16::{Groth16, ProvingKey, VerifyingKey};
use ark_relations::r1cs::SynthesisError;
use logos_blockchain_groth16::{
    CompressedGroth16Proof, CompressedGroth16VerificationKey, Groth16Proof, Groth16VerificationKey,
};
use logos_blockchain_poseidon2::{Digest as _, Poseidon2Bn254Hasher};
use rand::{CryptoRng, RngCore, SeedableRng as _};
use rand_chacha::ChaCha20Rng;
use sha2::{Digest as _, Sha512};

pub use crate::circuit::VaultCircuit;

mod circuit;
mod poseidon2;

/// The capacity of Bedrock's program spend.
pub const MAX_INPUTS: usize = 4;
pub const MAX_OUTPUTS: usize = 8;
/// The most members a committee holds.
pub const MAX_SIGNERS: usize = 4;
/// The most program deposits one step consumes.
pub const MAX_DEPOSITS: usize = 4;
/// The size of a program key in Bedrock's encoding.
pub const VERIFICATION_KEY_SIZE: usize = 352;
/// The verification key of [`demo_proving_key`], as `PROGRAM_REGISTER` takes it.
pub const DEMO_VERIFICATION_KEY: &[u8; VERIFICATION_KEY_SIZE] =
    include_bytes!("../demo_verification_key.bin");

const DEMO_SETUP_SEED: u64 = 0x4c45_5a5f_5641_554c;

const STEP_ID_DST: &[u8] = b"PROGRAM_STEP_ID_V1";
const DEPOSITS_DST: &[u8] = b"PROGRAM_DEPOSITS_V1";
const COMMITTEE_DST: &[u8] = b"LEZ_VAULT_COMMITTEE_V1";
const INTENT_DST: &[u8] = b"LEZ_VAULT_INTENT_V1";
const SIGNATURE_DST: &[u8] = b"LEZ_VAULT_SIG_V1";

/// The keys that move the vault notes carrying its id, and how many of them must sign.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Committee {
    pub threshold: u64,
    /// At most [`MAX_SIGNERS`].
    pub signers: Vec<EdwardsAffine>,
}

impl Committee {
    /// The value a vault note carries in its `data` to name this committee.
    #[must_use]
    pub fn id(&self) -> Fr {
        let mut preimage = vec![domain_tag(COMMITTEE_DST), Fr::from(self.threshold)];
        for key in self.padded_signers() {
            preimage.extend([key.x, key.y]);
        }
        Poseidon2Bn254Hasher::digest(&preimage)
    }

    /// The signers, with the identity in the unused slots.
    pub(crate) fn padded_signers(&self) -> [EdwardsAffine; MAX_SIGNERS] {
        assert!(
            self.signers.len() <= MAX_SIGNERS,
            "a committee holds at most {MAX_SIGNERS} signers"
        );
        std::array::from_fn(|slot| {
            self.signers
                .get(slot)
                .copied()
                .unwrap_or_else(EdwardsAffine::zero)
        })
    }
}

/// A program deposit a step consumes, with the opening of its intent.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Deposit {
    pub value: u64,
    /// Who the zone credits. Opaque to the circuit.
    pub recipient: Fr,
}

impl Deposit {
    /// The recipient of a deposit crediting the zone account `account_id`.
    #[must_use]
    pub fn recipient_element(account_id: &[u8; 32]) -> Fr {
        Fr::from_le_bytes_mod_order(account_id)
    }

    /// The intent the depositor signs: it pays `recipient` through the vault of `committee` only.
    #[must_use]
    pub fn intent(&self, committee: Fr) -> Fr {
        Poseidon2Bn254Hasher::digest(&[domain_tag(INTENT_DST), committee, self.recipient])
    }
}

/// A note the program spend consumes. Always a note of the program, held by `PK0`.
#[derive(Clone, Copy, Debug, Default)]
pub struct InputNote {
    pub value: u64,
    pub nonce: Fr,
    pub public_key: Fr,
    pub stake_public_key: Fr,
    pub data: Fr,
}

/// A note the program spend creates: a vault note when `program` is set, a payout otherwise.
#[derive(Clone, Copy, Debug, Default)]
pub struct OutputNote {
    pub value: u64,
    pub nonce: Fr,
    pub public_key: Fr,
    pub stake_public_key: Fr,
    pub program: Fr,
    pub data: Fr,
}

/// The notes of one program spend, the preimage of its `program_step_id`.
#[derive(Clone, Debug, Default)]
pub struct Step {
    pub inputs: [Option<InputNote>; MAX_INPUTS],
    pub outputs: [Option<OutputNote>; MAX_OUTPUTS],
}

impl Step {
    /// The elements Bedrock hashes after the domain tag: a flag then the fields of each note, an
    /// absent note reading as zeros.
    pub(crate) fn elements(&self) -> Vec<Fr> {
        let inputs = self.inputs.iter().flat_map(|input| {
            input.map_or([Fr::from(0_u64); 6], |note| {
                [
                    Fr::from(1_u64),
                    Fr::from(note.value),
                    note.nonce,
                    note.public_key,
                    note.stake_public_key,
                    note.data,
                ]
            })
        });
        let outputs = self.outputs.iter().flat_map(|output| {
            output.map_or([Fr::from(0_u64); 7], |note| {
                [
                    Fr::from(1_u64),
                    Fr::from(note.value),
                    note.nonce,
                    note.public_key,
                    note.stake_public_key,
                    note.program,
                    note.data,
                ]
            })
        });
        inputs.chain(outputs).collect()
    }

    /// Bedrock's `program_step_id`.
    #[must_use]
    pub fn id(&self) -> Fr {
        let mut preimage = vec![domain_tag(STEP_ID_DST)];
        preimage.extend(self.elements());
        Poseidon2Bn254Hasher::digest(&preimage)
    }
}

/// The public inputs of a program proof, in Bedrock's order.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct PublicInputs {
    pub program_step_id: Fr,
    pub program_deposits_hash: Fr,
    pub op_id: Fr,
}

impl PublicInputs {
    /// An operation id as the third input: Bedrock reduces its bytes into the field.
    #[must_use]
    pub fn op_id_element(op_id: &[u8; 32]) -> Fr {
        Fr::from_le_bytes_mod_order(op_id)
    }

    #[must_use]
    pub const fn to_array(&self) -> [Fr; 3] {
        [self.program_step_id, self.program_deposits_hash, self.op_id]
    }
}

/// A committee member's key on Baby Jubjub.
#[derive(Clone)]
pub struct SigningKey(Scalar);

impl SigningKey {
    /// Derives the key from the seed of the sequencer's Ed25519 channel key.
    #[must_use]
    pub fn from_channel_seed(seed: &[u8; 32]) -> Self {
        Self(hash_to_scalar(&[b"LEZ/vault-signing/v1", seed]))
    }

    pub fn public_key(&self) -> EdwardsAffine {
        (EdwardsAffine::generator() * self.0).into_affine()
    }

    /// Authorizes the program step of one inscription.
    #[must_use]
    pub fn sign(&self, public: &PublicInputs) -> Signature {
        let message: Vec<u8> = public
            .to_array()
            .iter()
            .flat_map(|element| element.into_bigint().to_bytes_le())
            .collect();
        let secret = self.0.into_bigint().to_bytes_le();
        let nonce = hash_to_scalar(&[b"LEZ/vault-nonce/v1", &secret, &message]);
        let r = (EdwardsAffine::generator() * nonce).into_affine();
        let e = challenge(&r, &self.public_key(), public);
        Signature {
            r,
            s: nonce + e * self.0,
        }
    }
}

/// A Schnorr signature over the public inputs of a program proof.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Signature {
    pub r: EdwardsAffine,
    pub s: Scalar,
}

impl Signature {
    #[must_use]
    pub fn verify(&self, signer: &EdwardsAffine, public: &PublicInputs) -> bool {
        let e = challenge(&self.r, signer, public);
        EdwardsAffine::generator() * self.s == self.r + *signer * e
    }
}

/// Bedrock's `program_deposits_hash` over the value and intent of each deposit.
#[must_use]
pub fn deposits_hash(deposits: &[(u64, Fr)]) -> Fr {
    let count = u64::try_from(deposits.len()).expect("a deposit count fits a u64");
    let mut preimage = vec![domain_tag(DEPOSITS_DST), Fr::from(count)];
    for (value, intent) in deposits {
        preimage.extend([Fr::from(*value), *intent]);
    }
    Poseidon2Bn254Hasher::digest(&preimage)
}

/// Generates the keys of the circuit. The registered program is their verification key, the
/// same for every committee.
///
/// Whoever knows the randomness can forge proofs, so a real deployment needs a ceremony.
pub fn setup(rng: &mut (impl RngCore + CryptoRng)) -> Result<ProvingKey<Bn254>, SynthesisError> {
    let blank = VaultCircuit {
        committee: Committee::default(),
        step: Step::default(),
        deposits: vec![],
        public: PublicInputs::default(),
        signatures: vec![],
        successor: Committee::default(),
        successor_signatures: vec![],
    };
    Groth16::<Bn254>::generate_random_parameters_with_reduction(blank, rng)
}

/// The keys of a setup whose randomness is public: anyone can forge proofs under them. For
/// demos and tests only.
#[must_use]
pub fn demo_proving_key() -> &'static ProvingKey<Bn254> {
    static KEY: LazyLock<ProvingKey<Bn254>> = LazyLock::new(|| {
        setup(&mut ChaCha20Rng::seed_from_u64(DEMO_SETUP_SEED)).expect("the circuit has a setup")
    });
    &KEY
}

/// A verification key in the encoding `PROGRAM_REGISTER` takes.
#[must_use]
pub fn verification_key_bytes(key: &VerifyingKey<Bn254>) -> [u8; VERIFICATION_KEY_SIZE] {
    let key = Groth16VerificationKey {
        alpha_1: key.alpha_g1,
        beta_2: key.beta_g2,
        gamma_2: key.gamma_g2,
        delta_2: key.delta_g2,
        ic: key.gamma_abc_g1.clone(),
    };
    CompressedGroth16VerificationKey::try_from(&key)
        .expect("the points of a setup compress")
        .to_bytes()
        .try_into()
        .expect("a key of three public inputs has the size of a program key")
}

/// Proves `circuit`, in the encoding a program step carries.
///
/// # Errors
///
/// [`SynthesisError::Unsatisfiable`] when the assignment breaks the vault's rule: a release
/// build would otherwise hand back a proof that does not verify.
pub fn prove(
    proving_key: &ProvingKey<Bn254>,
    circuit: VaultCircuit,
    rng: &mut (impl RngCore + CryptoRng),
) -> Result<CompressedGroth16Proof, SynthesisError> {
    let public = circuit.public.to_array();
    let proof = Groth16::<Bn254>::create_random_proof_with_reduction(circuit, proving_key, rng)?;
    let key = ark_groth16::prepare_verifying_key(&proving_key.vk);
    if !Groth16::<Bn254>::verify_proof(&key, &proof, &public)? {
        return Err(SynthesisError::Unsatisfiable);
    }
    Ok(CompressedGroth16Proof::try_from(&Groth16Proof {
        pi_a: proof.a,
        pi_b: proof.b,
        pi_c: proof.c,
    })
    .expect("the points of a proof compress"))
}

/// A domain tag as Bedrock encodes them: the bytes as a little-endian integer.
pub(crate) fn domain_tag(tag: &[u8]) -> Fr {
    Fr::from_le_bytes_mod_order(tag)
}

fn challenge(r: &EdwardsAffine, signer: &EdwardsAffine, public: &PublicInputs) -> Scalar {
    let hash = Poseidon2Bn254Hasher::digest(&[
        domain_tag(SIGNATURE_DST),
        r.x,
        r.y,
        signer.x,
        signer.y,
        public.program_step_id,
        public.program_deposits_hash,
        public.op_id,
    ]);
    Scalar::from_le_bytes_mod_order(&hash.into_bigint().to_bytes_le())
}

fn hash_to_scalar(parts: &[&[u8]]) -> Scalar {
    let mut hasher = Sha512::new();
    for part in parts {
        hasher.update(part);
    }
    Scalar::from_le_bytes_mod_order(&hasher.finalize())
}

#[cfg(test)]
mod tests {
    use ark_relations::r1cs::{ConstraintSynthesizer as _, ConstraintSystem};
    use logos_blockchain_core::mantle::{
        ops::channel::program_step::{ProgramDeposit, program_deposits_hash},
        programs::{
            ProgramVerificationKey, RegisteredProgram, SpendInputFields, SpendOutputFields,
            program_step_id,
        },
    };
    use logos_blockchain_key_management_system_keys::keys::ZkPublicKey;

    use super::*;

    const VAULT_PROGRAM: u64 = 0xBEEF;

    fn key(seed: u8) -> SigningKey {
        SigningKey::from_channel_seed(&[seed; 32])
    }

    fn committee() -> Committee {
        Committee {
            threshold: 2,
            signers: vec![
                key(1).public_key(),
                key(2).public_key(),
                key(3).public_key(),
            ],
        }
    }

    fn vault_note(value: u64, committee: &Committee) -> OutputNote {
        OutputNote {
            value,
            nonce: Fr::from(11_u64),
            public_key: Fr::from(42_u64),
            stake_public_key: Fr::from(0_u64),
            program: Fr::from(VAULT_PROGRAM),
            data: committee.id(),
        }
    }

    fn payout(value: u64, payee: u64) -> OutputNote {
        OutputNote {
            value,
            nonce: Fr::from(12_u64),
            public_key: Fr::from(payee),
            stake_public_key: Fr::from(payee),
            program: Fr::from(0_u64),
            data: Fr::from(0_u64),
        }
    }

    /// A step consuming a vault note of 100, paying 30 to a user and keeping 70.
    fn withdraw_step() -> Step {
        let mut step = Step::default();
        step.inputs[0] = Some(InputNote {
            value: 100,
            nonce: Fr::from(10_u64),
            public_key: Fr::from(42_u64),
            stake_public_key: Fr::from(0_u64),
            data: committee().id(),
        });
        step.outputs[0] = Some(vault_note(70, &committee()));
        step.outputs[1] = Some(payout(30, 1234));
        step
    }

    /// The step and deposits made out to `committee()`, signed by its first two members.
    fn circuit(step: Step, deposits: Vec<Deposit>) -> VaultCircuit {
        let committee = committee();
        let intents: Vec<_> = deposits
            .iter()
            .map(|deposit| (deposit.value, deposit.intent(committee.id())))
            .collect();
        let public = PublicInputs {
            program_step_id: step.id(),
            program_deposits_hash: deposits_hash(&intents),
            op_id: Fr::from(6_u64),
        };
        let signatures = vec![Some(key(1).sign(&public)), Some(key(2).sign(&public))];
        VaultCircuit {
            committee: committee.clone(),
            step,
            deposits,
            public,
            signatures: signatures.clone(),
            successor: committee,
            successor_signatures: signatures,
        }
    }

    fn is_satisfied(circuit: VaultCircuit) -> bool {
        let cs = ConstraintSystem::new_ref();
        // An assignment the gadgets cannot complete, such as the inverse of zero, is refused too.
        circuit.generate_constraints(cs.clone()).is_ok() && cs.is_satisfied().unwrap()
    }

    #[test]
    fn step_id_matches_bedrock() {
        let step = withdraw_step();
        let inputs = step.inputs.map(|input| {
            input.map_or_else(SpendInputFields::inactive, |note| SpendInputFields {
                active: true,
                value: note.value,
                nonce: note.nonce,
                public_key: ZkPublicKey::new(note.public_key),
                stake_public_key: ZkPublicKey::new(note.stake_public_key),
                data: note.data,
            })
        });
        let outputs = step.outputs.map(|output| {
            output.map_or_else(SpendOutputFields::inactive, |note| SpendOutputFields {
                active: true,
                value: note.value,
                nonce: note.nonce,
                public_key: ZkPublicKey::new(note.public_key),
                stake_public_key: ZkPublicKey::new(note.stake_public_key),
                program: note.program,
                data: note.data,
            })
        });

        assert_eq!(step.id(), program_step_id(&inputs, &outputs));
    }

    #[test]
    fn deposits_hash_matches_bedrock() {
        let deposit = |value, intent| ProgramDeposit {
            value,
            intent,
            ..ProgramDeposit::sample()
        };
        let (first, second) = (deposit(5, Fr::from(8_u64)), deposit(7, Fr::from(9_u64)));

        assert_eq!(deposits_hash(&[]), program_deposits_hash(&[]));
        assert_eq!(
            deposits_hash(&[(5, Fr::from(8_u64)), (7, Fr::from(9_u64))]),
            program_deposits_hash(&[&first, &second])
        );
    }

    #[test]
    fn signature_verifies_only_for_its_inputs_and_signer() {
        let public = PublicInputs {
            op_id: Fr::from(1_u64),
            ..PublicInputs::default()
        };
        let signature = key(1).sign(&public);
        let other_op = PublicInputs {
            op_id: Fr::from(2_u64),
            ..public
        };

        assert!(signature.verify(&key(1).public_key(), &public));
        assert!(!signature.verify(&key(1).public_key(), &other_op));
        assert!(!signature.verify(&key(2).public_key(), &public));
    }

    #[test]
    fn withdraw_step_satisfies_the_rule() {
        assert!(is_satisfied(circuit(withdraw_step(), vec![])));
    }

    #[test]
    fn signature_over_another_inscription_is_refused() {
        let mut circuit = circuit(withdraw_step(), vec![]);
        circuit.public.op_id = Fr::from(999_u64);
        assert!(!is_satisfied(circuit));
    }

    #[test]
    fn fewer_signatures_than_the_threshold_are_refused() {
        let mut circuit = circuit(withdraw_step(), vec![]);
        circuit.signatures[1] = None;
        assert!(!is_satisfied(circuit));
    }

    #[test]
    fn signature_of_a_stranger_is_refused() {
        let mut circuit = circuit(withdraw_step(), vec![]);
        circuit.signatures[1] = Some(key(9).sign(&circuit.public));
        assert!(!is_satisfied(circuit));
    }

    /// Anyone can sign under the identity key that fills an unused slot.
    #[test]
    fn signature_in_an_unused_slot_is_refused() {
        let mut circuit = circuit(withdraw_step(), vec![]);
        let s = Scalar::from(5_u64);
        circuit.signatures = vec![
            Some(key(1).sign(&circuit.public)),
            None,
            None,
            Some(Signature {
                r: (EdwardsAffine::generator() * s).into_affine(),
                s,
            }),
        ];
        circuit.successor_signatures = circuit.signatures.clone();
        assert!(!is_satisfied(circuit));
    }

    #[test]
    fn note_of_another_committee_is_refused() {
        let mut circuit = circuit(withdraw_step(), vec![]);
        circuit.committee.signers[2] = key(9).public_key();
        assert!(!is_satisfied(circuit));
    }

    fn successor() -> Committee {
        Committee {
            threshold: 1,
            signers: vec![key(9).public_key()],
        }
    }

    /// `committee()` handing the vault over to `successor()`, not yet signed by the latter.
    fn hand_over() -> VaultCircuit {
        let mut step = withdraw_step();
        step.outputs[0] = Some(vault_note(70, &successor()));
        let mut circuit = circuit(step, vec![]);
        circuit.successor = successor();
        circuit.successor_signatures = vec![];
        circuit
    }

    #[test]
    fn committee_hands_the_vault_to_a_successor_that_signs() {
        let mut circuit = hand_over();
        circuit.successor_signatures = vec![Some(key(9).sign(&circuit.public))];
        assert!(is_satisfied(circuit));
    }

    #[test]
    fn hand_over_to_a_successor_that_did_not_sign_is_refused() {
        assert!(!is_satisfied(hand_over()));
    }

    #[test]
    fn vault_note_naming_neither_committee_is_refused() {
        let mut step = withdraw_step();
        step.outputs[0] = Some(vault_note(70, &successor()));
        assert!(!is_satisfied(circuit(step, vec![])));
    }

    #[test]
    fn committee_needing_no_signature_is_refused() {
        let mut circuit = hand_over();
        circuit.successor = Committee {
            threshold: 0,
            signers: vec![],
        };
        circuit.step.outputs[0] = Some(vault_note(70, &circuit.successor));
        circuit.public.program_step_id = circuit.step.id();
        circuit.signatures = vec![
            Some(key(1).sign(&circuit.public)),
            Some(key(2).sign(&circuit.public)),
        ];
        assert!(!is_satisfied(circuit));
    }

    #[test]
    fn step_other_than_the_committed_one_is_refused() {
        let mut circuit = circuit(withdraw_step(), vec![]);
        circuit.step.outputs[1] = Some(payout(31, 1234));
        assert!(!is_satisfied(circuit));
    }

    #[test]
    fn payout_its_payee_cannot_spend_is_refused() {
        let mut step = withdraw_step();
        step.outputs[1] = Some(OutputNote {
            stake_public_key: Fr::from(1_u64),
            ..payout(30, 1234)
        });
        assert!(!is_satisfied(circuit(step, vec![])));
    }

    #[test]
    fn staked_vault_note_is_refused() {
        let mut step = withdraw_step();
        step.outputs[0] = Some(OutputNote {
            stake_public_key: Fr::from(1_u64),
            ..vault_note(70, &committee())
        });
        assert!(!is_satisfied(circuit(step, vec![])));
    }

    #[test]
    fn deposits_made_out_to_the_committee_are_consumed() {
        let deposits = vec![
            Deposit {
                value: 20,
                recipient: Fr::from(77_u64),
            },
            Deposit {
                value: 5,
                recipient: Fr::from(78_u64),
            },
        ];
        let mut step = withdraw_step();
        step.outputs[0] = Some(vault_note(95, &committee()));
        assert!(is_satisfied(circuit(step, deposits)));
    }

    #[test]
    fn deposit_made_out_to_another_committee_is_refused() {
        let deposit = Deposit {
            value: 20,
            recipient: Fr::from(77_u64),
        };
        let mut circuit = circuit(withdraw_step(), vec![deposit]);
        let other = Committee {
            threshold: 1,
            signers: vec![key(9).public_key()],
        };
        circuit.public.program_deposits_hash =
            deposits_hash(&[(deposit.value, deposit.intent(other.id()))]);
        circuit.signatures = vec![
            Some(key(1).sign(&circuit.public)),
            Some(key(2).sign(&circuit.public)),
        ];
        circuit.successor_signatures = circuit.signatures.clone();
        assert!(!is_satisfied(circuit));
    }

    #[test]
    fn step_consuming_nothing_takes_the_deposits_in() {
        let deposit = Deposit {
            value: 50,
            recipient: Fr::from(77_u64),
        };
        let mut step = Step::default();
        step.outputs[0] = Some(vault_note(50, &committee()));
        assert!(is_satisfied(circuit(step, vec![deposit])));
    }

    /// Run with `UPDATE_DEMO_KEY=1` after changing the circuit.
    #[test]
    fn demo_key_is_current_and_proves_for_bedrock() {
        let proving_key = demo_proving_key();
        let key_bytes = verification_key_bytes(&proving_key.vk);
        if std::env::var_os("UPDATE_DEMO_KEY").is_some() {
            let path = concat!(env!("CARGO_MANIFEST_DIR"), "/demo_verification_key.bin");
            std::fs::write(path, key_bytes).unwrap();
        }
        assert_eq!(&key_bytes, DEMO_VERIFICATION_KEY);

        let circuit = circuit(withdraw_step(), vec![]);
        let public = circuit.public.to_array();
        let proof = prove(proving_key, circuit, &mut ChaCha20Rng::seed_from_u64(1)).unwrap();

        let program = RegisteredProgram::new(
            ProgramVerificationKey::try_from_bytes(DEMO_VERIFICATION_KEY).unwrap(),
        )
        .unwrap();
        assert!(program.verify(&proof, &public).unwrap());

        let mut other_op = public;
        other_op[2] = Fr::from(999_u64);
        assert!(!program.verify(&proof, &other_op).unwrap());
    }
}
