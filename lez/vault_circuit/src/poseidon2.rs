//! Bedrock's Poseidon2 sponge (BN254, state of 3, rate 1) as R1CS constraints.

use ark_bn254::Fr;
use ark_r1cs_std::fields::{FieldVar as _, fp::FpVar};
use ark_relations::r1cs::SynthesisError;
use jf_poseidon2::{Poseidon2Params as _, constants::bn254::Poseidon2ParamsBn3 as Params};

/// The state of a hash in progress, mirroring `lb_poseidon2::Poseidon2Hasher`.
#[derive(Clone)]
pub struct Sponge([FpVar<Fr>; 3]);

impl Sponge {
    pub fn new() -> Self {
        Self([FpVar::zero(), FpVar::zero(), FpVar::zero()])
    }

    pub fn absorb(&mut self, input: &FpVar<Fr>) -> Result<(), SynthesisError> {
        self.0[0] += input;
        permute(&mut self.0)
    }

    pub fn finalize(mut self) -> Result<FpVar<Fr>, SynthesisError> {
        self.absorb(&FpVar::one())?;
        let [digest, _, _] = self.0;
        Ok(digest)
    }
}

/// `lb_poseidon2::Digest::digest` over variables.
pub fn digest(inputs: &[FpVar<Fr>]) -> Result<FpVar<Fr>, SynthesisError> {
    let mut sponge = Sponge::new();
    for input in inputs {
        sponge.absorb(input)?;
    }
    sponge.finalize()
}

fn permute(state: &mut [FpVar<Fr>; 3]) -> Result<(), SynthesisError> {
    let external_rc = Params::external_rc();
    let (initial, terminal) = external_rc.split_at(external_rc.len().div_euclid(2));

    external_matrix(state);
    for rc in initial {
        external_round(state, rc)?;
    }
    for rc in Params::internal_rc() {
        state[0] += *rc;
        state[0] = sbox(&state[0])?;
        let sum = &state[0] + &state[1] + &state[2];
        state[0] += &sum;
        state[1] += &sum;
        state[2] = state[2].double()? + &sum;
    }
    for rc in terminal {
        external_round(state, rc)?;
    }
    Ok(())
}

fn external_round(state: &mut [FpVar<Fr>; 3], constants: &[Fr; 3]) -> Result<(), SynthesisError> {
    for (element, rc) in state.iter_mut().zip(constants) {
        *element += *rc;
        *element = sbox(element)?;
    }
    external_matrix(state);
    Ok(())
}

fn external_matrix(state: &mut [FpVar<Fr>; 3]) {
    let sum = &state[0] + &state[1] + &state[2];
    for element in state {
        *element += &sum;
    }
}

fn sbox(x: &FpVar<Fr>) -> Result<FpVar<Fr>, SynthesisError> {
    debug_assert_eq!(Params::D, 5, "the s-box below is x^5");
    Ok(x.square()?.square()? * x)
}

#[cfg(test)]
mod tests {
    use ark_ff::Field as _;
    use ark_r1cs_std::{R1CSVar as _, alloc::AllocVar as _};
    use ark_relations::r1cs::ConstraintSystem;
    use logos_blockchain_poseidon2::{Digest as _, Poseidon2Bn254Hasher};

    use super::*;

    #[test]
    fn gadget_matches_bedrock_hash() {
        for len in [0_u64, 1, 2, 3, 7] {
            let inputs: Vec<Fr> = (0..len).map(|i| Fr::from(i).pow([5]) + Fr::ONE).collect();
            let cs = ConstraintSystem::new_ref();
            let vars: Vec<_> = inputs
                .iter()
                .map(|input| FpVar::new_witness(cs.clone(), || Ok(*input)).unwrap())
                .collect();

            let hash = digest(&vars).unwrap();

            assert_eq!(hash.value().unwrap(), Poseidon2Bn254Hasher::digest(&inputs));
            assert!(cs.is_satisfied().unwrap());
        }
    }
}
