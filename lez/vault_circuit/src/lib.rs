//! The rule of the LEZ vault, a Bedrock program holding the value behind bridged tokens.
//!
//! Bedrock's own program spend proof covers conservation and note membership. This proof adds
//! that the committee signed the inscription, and that the notes a step creates are well formed.

#![expect(
    clippy::arithmetic_side_effects,
    reason = "Field and curve arithmetic does not overflow"
)]

use ark_bn254::{Bn254, Fr};
use ark_ec::{AffineRepr as _, CurveGroup as _};
use ark_ed_on_bn254::{EdwardsAffine, Fr as Scalar};
use ark_ff::{BigInteger as _, PrimeField as _};
use ark_groth16::{Groth16, Proof, ProvingKey};
use ark_relations::r1cs::SynthesisError;
use logos_blockchain_poseidon2::{Digest as _, Poseidon2Bn254Hasher};
use rand::{CryptoRng, RngCore};
use sha2::{Digest as _, Sha512};

pub use crate::circuit::VaultCircuit;

mod circuit;
mod poseidon2;

/// The capacity of Bedrock's program spend.
pub const MAX_INPUTS: usize = 4;
pub const MAX_OUTPUTS: usize = 8;

const STEP_ID_DST: &[u8] = b"PROGRAM_STEP_ID_V1";
const NONCE_DST: &[u8] = b"LEZ_VAULT_NONCE_V1";
const SIGNATURE_DST: &[u8] = b"LEZ_VAULT_SIG_V1";

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

/// The nonce the circuit requires for output `index` of a step that consumes no note.
#[must_use]
pub fn bootstrap_nonce(program_deposits_hash: Fr, index: usize) -> Fr {
    Poseidon2Bn254Hasher::digest(&[
        domain_tag(NONCE_DST),
        program_deposits_hash,
        Fr::from(u64::try_from(index).expect("an output index fits a u64")),
    ])
}

/// Generates the keys of the circuit for a committee. The registered program is their
/// verification key.
///
/// Whoever knows the randomness can forge proofs, so a real deployment needs a ceremony.
pub fn setup(
    signers: Vec<EdwardsAffine>,
    threshold: usize,
    rng: &mut (impl RngCore + CryptoRng),
) -> Result<ProvingKey<Bn254>, SynthesisError> {
    let signatures = vec![None; signers.len()];
    let circuit = VaultCircuit {
        signers,
        threshold,
        step: Step::default(),
        public: PublicInputs::default(),
        signatures,
    };
    Groth16::<Bn254>::generate_random_parameters_with_reduction(circuit, rng)
}

pub fn prove(
    proving_key: &ProvingKey<Bn254>,
    circuit: VaultCircuit,
    rng: &mut (impl RngCore + CryptoRng),
) -> Result<Proof<Bn254>, SynthesisError> {
    Groth16::<Bn254>::create_random_proof_with_reduction(circuit, proving_key, rng)
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
    use logos_blockchain_core::mantle::programs::{
        ProgramVerificationKey, RegisteredProgram, SpendInputFields, SpendOutputFields,
        program_step_id,
    };
    use logos_blockchain_groth16::{CompressedGroth16Proof, Groth16Proof, Groth16VerificationKey};
    use logos_blockchain_key_management_system_keys::keys::ZkPublicKey;
    use rand::{SeedableRng as _, rngs::StdRng};

    use super::*;

    const VAULT_PROGRAM: u64 = 0xBEEF;

    fn key() -> SigningKey {
        SigningKey::from_channel_seed(&[7; 32])
    }

    fn vault_note(value: u64) -> OutputNote {
        OutputNote {
            value,
            nonce: Fr::from(11_u64),
            public_key: Fr::from(42_u64),
            stake_public_key: Fr::from(0_u64),
            program: Fr::from(VAULT_PROGRAM),
            data: Fr::from(0_u64),
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
            data: Fr::from(0_u64),
        });
        step.outputs[0] = Some(vault_note(70));
        step.outputs[1] = Some(payout(30, 1234));
        step
    }

    fn circuit(step: Step) -> VaultCircuit {
        let public = PublicInputs {
            program_step_id: step.id(),
            program_deposits_hash: Fr::from(5_u64),
            op_id: Fr::from(6_u64),
        };
        VaultCircuit {
            signers: vec![key().public_key()],
            threshold: 1,
            step,
            public,
            signatures: vec![Some(key().sign(&public))],
        }
    }

    fn is_satisfied(circuit: VaultCircuit) -> bool {
        let cs = ConstraintSystem::new_ref();
        circuit.generate_constraints(cs.clone()).unwrap();
        cs.is_satisfied().unwrap()
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
    fn signature_verifies_only_for_its_inputs_and_signer() {
        let public = PublicInputs {
            op_id: Fr::from(1_u64),
            ..PublicInputs::default()
        };
        let signature = key().sign(&public);
        let other_key = SigningKey::from_channel_seed(&[8; 32]);
        let other_op = PublicInputs {
            op_id: Fr::from(2_u64),
            ..public
        };

        assert!(signature.verify(&key().public_key(), &public));
        assert!(!signature.verify(&key().public_key(), &other_op));
        assert!(!signature.verify(&other_key.public_key(), &public));
    }

    #[test]
    fn withdraw_step_satisfies_the_rule() {
        assert!(is_satisfied(circuit(withdraw_step())));
    }

    #[test]
    fn signature_over_another_inscription_is_refused() {
        let mut circuit = circuit(withdraw_step());
        circuit.public.op_id = Fr::from(999_u64);
        assert!(!is_satisfied(circuit));
    }

    #[test]
    fn missing_signature_is_refused() {
        let mut circuit = circuit(withdraw_step());
        circuit.signatures = vec![None];
        assert!(!is_satisfied(circuit));
    }

    #[test]
    fn signature_of_a_stranger_is_refused() {
        let mut circuit = circuit(withdraw_step());
        let stranger = SigningKey::from_channel_seed(&[8; 32]);
        circuit.signatures = vec![Some(stranger.sign(&circuit.public))];
        assert!(!is_satisfied(circuit));
    }

    #[test]
    fn step_other_than_the_committed_one_is_refused() {
        let mut circuit = circuit(withdraw_step());
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
        assert!(!is_satisfied(circuit(step)));
    }

    #[test]
    fn vault_note_with_stake_or_data_is_refused() {
        let mut staked = withdraw_step();
        staked.outputs[0] = Some(OutputNote {
            stake_public_key: Fr::from(1_u64),
            ..vault_note(70)
        });
        assert!(!is_satisfied(circuit(staked)));

        let mut with_data = withdraw_step();
        with_data.outputs[0] = Some(OutputNote {
            data: Fr::from(1_u64),
            ..vault_note(70)
        });
        assert!(!is_satisfied(circuit(with_data)));
    }

    #[test]
    fn step_consuming_nothing_needs_the_derived_nonces() {
        let deposits_hash = Fr::from(5_u64);
        let mut step = Step::default();
        step.outputs[0] = Some(OutputNote {
            nonce: bootstrap_nonce(deposits_hash, 0),
            ..vault_note(50)
        });
        assert!(is_satisfied(circuit(step.clone())));

        step.outputs[0] = Some(vault_note(50));
        assert!(!is_satisfied(circuit(step)));
    }

    #[test]
    fn proof_verifies_with_bedrock_verifier() {
        let mut rng = StdRng::seed_from_u64(1);
        let proving_key = setup(vec![key().public_key()], 1, &mut rng).unwrap();
        let circuit = circuit(withdraw_step());
        let public = circuit.public.to_array();

        let proof = prove(&proving_key, circuit, &mut rng).unwrap();

        let program = RegisteredProgram::new(
            ProgramVerificationKey::try_from(&Groth16VerificationKey {
                alpha_1: proving_key.vk.alpha_g1,
                beta_2: proving_key.vk.beta_g2,
                gamma_2: proving_key.vk.gamma_g2,
                delta_2: proving_key.vk.delta_g2,
                ic: proving_key.vk.gamma_abc_g1.clone(),
            })
            .unwrap(),
        )
        .unwrap();
        let proof = CompressedGroth16Proof::try_from(&Groth16Proof {
            pi_a: proof.a,
            pi_b: proof.b,
            pi_c: proof.c,
        })
        .unwrap();
        assert!(program.verify(&proof, &public).unwrap());

        let mut other_op = public;
        other_op[2] = Fr::from(999_u64);
        assert!(!program.verify(&proof, &other_op).unwrap());
    }
}
