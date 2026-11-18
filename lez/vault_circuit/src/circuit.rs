use ark_bn254::Fr;
use ark_ec::AffineRepr as _;
use ark_ed_on_bn254::{EdwardsAffine, Fr as Scalar, constraints::EdwardsVar};
use ark_ff::{AdditiveGroup as _, BigInteger as _, PrimeField as _};
use ark_r1cs_std::{
    alloc::AllocVar as _,
    boolean::Boolean,
    convert::ToBitsGadget as _,
    eq::EqGadget as _,
    fields::{FieldVar as _, fp::FpVar},
    groups::CurveVar as _,
};
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError};

use crate::{
    MAX_INPUTS, NONCE_DST, PublicInputs, SIGNATURE_DST, STEP_ID_DST, Signature, Step, domain_tag,
    poseidon2::{Sponge, digest},
};

const INPUT_FIELDS: usize = 6;
const OUTPUT_FIELDS: usize = 7;

/// The vault's rule for one program step. `signers` and `threshold` shape the constraints, so
/// they are part of the verification key; the rest is the assignment.
#[derive(Clone)]
pub struct VaultCircuit {
    pub signers: Vec<EdwardsAffine>,
    pub threshold: usize,
    pub step: Step,
    pub public: PublicInputs,
    /// One slot per signer, in the order of `signers`.
    pub signatures: Vec<Option<Signature>>,
}

impl ConstraintSynthesizer<Fr> for VaultCircuit {
    fn generate_constraints(self, cs: ConstraintSystemRef<Fr>) -> Result<(), SynthesisError> {
        assert_eq!(
            self.signers.len(),
            self.signatures.len(),
            "one signature slot per signer"
        );
        let zero = FpVar::<Fr>::zero();

        // Bedrock's order.
        let step_id = FpVar::new_input(cs.clone(), || Ok(self.public.program_step_id))?;
        let deposits_hash = FpVar::new_input(cs.clone(), || Ok(self.public.program_deposits_hash))?;
        let op_id = FpVar::new_input(cs.clone(), || Ok(self.public.op_id))?;

        // Open the step. Flags and absent notes need no checks of their own: the hash ties every
        // element to the one Bedrock's program spend constrained.
        let elements = self
            .step
            .elements()
            .into_iter()
            .map(|element| FpVar::new_witness(cs.clone(), || Ok(element)))
            .collect::<Result<Vec<_>, _>>()?;
        let mut sponge = Sponge::new();
        sponge.absorb(&FpVar::constant(domain_tag(STEP_ID_DST)))?;
        for element in &elements {
            sponge.absorb(element)?;
        }
        sponge.finalize()?.enforce_equal(&step_id)?;

        let (inputs, outputs) = elements.split_at(MAX_INPUTS * INPUT_FIELDS);
        let consumes_nothing = FpVar::one() - &inputs[0];
        let mut nonce_sponge = Sponge::new();
        nonce_sponge.absorb(&FpVar::constant(domain_tag(NONCE_DST)))?;
        nonce_sponge.absorb(&deposits_hash)?;

        let (outputs, _) = outputs.as_chunks::<OUTPUT_FIELDS>();
        for (index, output) in outputs.iter().enumerate() {
            let [
                active,
                _value,
                nonce,
                public_key,
                stake_public_key,
                program,
                data,
            ] = output;

            // A vault note neither stakes nor carries data.
            program.mul_equals(stake_public_key, &zero)?;
            program.mul_equals(data, &zero)?;

            // A payout stakes under its payee's key, or the payee could not spend it.
            stake_public_key.conditional_enforce_equal(public_key, &program.is_eq(&zero)?)?;

            // Bedrock derives the nonces only when the step consumes a note.
            let mut derived = nonce_sponge.clone();
            let index = u64::try_from(index).expect("an output index fits a u64");
            derived.absorb(&FpVar::constant(Fr::from(index)))?;
            let derived = derived.finalize()?;
            (&consumes_nothing * active).mul_equals(&(nonce - derived), &zero)?;
        }

        let generator = EdwardsVar::constant(EdwardsAffine::generator().into_group());
        let mut signed = zero;
        for (signer, signature) in self.signers.iter().zip(&self.signatures) {
            let enabled = Boolean::new_witness(cs.clone(), || Ok(signature.is_some()))?;
            let signature = signature.unwrap_or(Signature {
                r: EdwardsAffine::zero(),
                s: Scalar::ZERO,
            });
            let r = EdwardsVar::new_witness(cs.clone(), || Ok(signature.r.into_group()))?;
            let s = signature
                .s
                .into_bigint()
                .to_bits_le()
                .into_iter()
                .take(usize::try_from(Scalar::MODULUS_BIT_SIZE).expect("a bit size fits a usize"))
                .map(|bit| Boolean::new_witness(cs.clone(), || Ok(bit)))
                .collect::<Result<Vec<_>, _>>()?;

            let challenge = digest(&[
                FpVar::constant(domain_tag(SIGNATURE_DST)),
                r.x.clone(),
                r.y.clone(),
                FpVar::constant(signer.x),
                FpVar::constant(signer.y),
                step_id.clone(),
                deposits_hash.clone(),
                op_id.clone(),
            ])?;

            // s·B == R + e·A
            let left = generator.scalar_mul_le(s.iter())?;
            let right = EdwardsVar::constant(signer.into_group())
                .scalar_mul_le(challenge.to_bits_le()?.iter())?
                + &r;
            left.conditional_enforce_equal(&right, &enabled)?;
            signed += FpVar::from(enabled);
        }
        let threshold = u64::try_from(self.threshold).expect("a threshold fits a u64");
        signed.enforce_equal(&FpVar::constant(Fr::from(threshold)))
    }
}
