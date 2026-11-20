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
    COMMITTEE_DST, Committee, DEPOSITS_DST, Deposit, INTENT_DST, MAX_DEPOSITS, MAX_INPUTS,
    PublicInputs, SIGNATURE_DST, STEP_ID_DST, Signature, Step, domain_tag,
    poseidon2::{Sponge, digest},
};

const INPUT_FIELDS: usize = 6;
const OUTPUT_FIELDS: usize = 7;

/// The vault's rule for one program step. Every field is part of the assignment: the constraints
/// are the same for every committee.
#[derive(Clone)]
pub struct VaultCircuit {
    /// The committee the consumed notes and deposits name.
    pub committee: Committee,
    pub step: Step,
    /// The deposits the step consumes, in their order in the mini-block. At most
    /// [`MAX_DEPOSITS`].
    pub deposits: Vec<Deposit>,
    pub public: PublicInputs,
    /// One slot per signer of `committee`, in order.
    pub signatures: Vec<Option<Signature>>,
    /// The committee the vault notes of the step go to: `committee` again unless it hands over.
    pub successor: Committee,
    pub successor_signatures: Vec<Option<Signature>>,
}

impl ConstraintSynthesizer<Fr> for VaultCircuit {
    fn generate_constraints(self, cs: ConstraintSystemRef<Fr>) -> Result<(), SynthesisError> {
        assert!(
            self.deposits.len() <= MAX_DEPOSITS,
            "a step consumes at most {MAX_DEPOSITS} deposits"
        );
        let zero = FpVar::<Fr>::zero();
        let one = FpVar::<Fr>::one();

        // Bedrock's order.
        let step_id = FpVar::new_input(cs.clone(), || Ok(self.public.program_step_id))?;
        let deposits_hash = FpVar::new_input(cs.clone(), || Ok(self.public.program_deposits_hash))?;
        let op_id = FpVar::new_input(cs.clone(), || Ok(self.public.op_id))?;

        let message = [step_id.clone(), deposits_hash.clone(), op_id];
        let committee = authorize(&cs, &self.committee, &self.signatures, &message)?;
        // A committee that takes the vault over proves it holds its keys, so the vault cannot
        // be handed to an id nobody can sign for.
        let successor = authorize(&cs, &self.successor, &self.successor_signatures, &message)?;

        // Open the step. Flags and absent notes need no checks of their own: the hash ties every
        // element to the one Bedrock's program spend constrained.
        let elements = self
            .step
            .elements()
            .into_iter()
            .map(|element| FpVar::new_witness(cs.clone(), || Ok(element)))
            .collect::<Result<Vec<_>, _>>()?;
        let mut opened_step = Sponge::new();
        opened_step.absorb(&FpVar::constant(domain_tag(STEP_ID_DST)))?;
        for element in &elements {
            opened_step.absorb(element)?;
        }
        opened_step.finalize()?.enforce_equal(&step_id)?;
        let (inputs, outputs) = elements.split_at(MAX_INPUTS * INPUT_FIELDS);
        let (inputs, _) = inputs.as_chunks::<INPUT_FIELDS>();
        let (outputs, _) = outputs.as_chunks::<OUTPUT_FIELDS>();

        // Every consumed note belongs to the committee.
        for [active, _value, _nonce, _public_key, _stake_public_key, data] in inputs {
            active.mul_equals(&(data - &committee), &zero)?;
        }

        for [
            _active,
            _value,
            _nonce,
            public_key,
            stake_public_key,
            program,
            data,
        ] in outputs
        {
            // A vault note does not stake, and goes to the successor.
            program.mul_equals(stake_public_key, &zero)?;
            program.mul_equals(&(data - &successor), &zero)?;

            // A payout stakes under its payee's key, so vault value is never staked under
            // another's.
            stake_public_key.conditional_enforce_equal(public_key, &program.is_eq(&zero)?)?;
        }

        // Open the deposits: each was made out to the committee. The hash covers a variable
        // count, so the digest of every prefix is computed and the one at the count is kept.
        let present = (0..MAX_DEPOSITS)
            .map(|slot| Boolean::new_witness(cs.clone(), || Ok(slot < self.deposits.len())))
            .collect::<Result<Vec<_>, _>>()?;
        let count = present.iter().fold(zero.clone(), |count, flag| {
            count + FpVar::from(flag.clone())
        });
        let mut prefix = Sponge::new();
        prefix.absorb(&FpVar::constant(domain_tag(DEPOSITS_DST)))?;
        prefix.absorb(&count)?;
        let mut opened_deposits = zero.clone();
        let mut previous = one;
        for (slot, flag) in present.iter().enumerate() {
            let deposit = self.deposits.get(slot).copied().unwrap_or_default();
            let value = FpVar::new_witness(cs.clone(), || Ok(Fr::from(deposit.value)))?;
            let recipient = FpVar::new_witness(cs.clone(), || Ok(deposit.recipient))?;
            let intent = digest(&[
                FpVar::constant(domain_tag(INTENT_DST)),
                committee.clone(),
                recipient,
            ])?;

            // The count is `slot` exactly when the previous slot is filled and this one is not.
            // The difference is a bit only if the filled slots come first.
            let flag = FpVar::from(flag.clone());
            let ends_here = &previous - &flag;
            ends_here.mul_equals(&(&ends_here - FpVar::one()), &zero)?;
            opened_deposits += ends_here * prefix.clone().finalize()?;

            prefix.absorb(&value)?;
            prefix.absorb(&intent)?;
            previous = flag;
        }
        opened_deposits += previous * prefix.finalize()?;
        opened_deposits.enforce_equal(&deposits_hash)
    }
}

/// Opens `committee` and checks that its threshold signed `message`. Returns its id.
fn authorize(
    cs: &ConstraintSystemRef<Fr>,
    committee: &Committee,
    signatures: &[Option<Signature>],
    message: &[FpVar<Fr>; 3],
) -> Result<FpVar<Fr>, SynthesisError> {
    let zero = FpVar::<Fr>::zero();

    // Allocation checks each key is in the prime-order subgroup.
    let threshold = FpVar::new_witness(cs.clone(), || Ok(Fr::from(committee.threshold)))?;
    let signers = committee
        .padded_signers()
        .into_iter()
        .map(|key| EdwardsVar::new_witness(cs.clone(), || Ok(key.into_group())))
        .collect::<Result<Vec<_>, _>>()?;
    let mut id = Sponge::new();
    id.absorb(&FpVar::constant(domain_tag(COMMITTEE_DST)))?;
    id.absorb(&threshold)?;
    for key in &signers {
        id.absorb(&key.x)?;
        id.absorb(&key.y)?;
    }

    // With no signature needed, anyone could move the notes.
    threshold.enforce_not_equal(&zero)?;

    // s·B == R + e·A for each signing member.
    let generator = EdwardsVar::constant(EdwardsAffine::generator().into_group());
    let mut signed = zero.clone();
    for (slot, signer) in signers.iter().enumerate() {
        let signature = signatures.get(slot).copied().flatten();
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

        let [step_id, deposits_hash, op_id] = message.clone();
        let challenge = digest(&[
            FpVar::constant(domain_tag(SIGNATURE_DST)),
            r.x.clone(),
            r.y.clone(),
            signer.x.clone(),
            signer.y.clone(),
            step_id,
            deposits_hash,
            op_id,
        ])?;
        let left = generator.scalar_mul_le(s.iter())?;
        let right = signer.scalar_mul_le(challenge.to_bits_le()?.iter())? + &r;
        left.conditional_enforce_equal(&right, &enabled)?;

        // An unused slot holds the identity, under which anyone can sign. In the subgroup it
        // is the only point with a zero x.
        let enabled = FpVar::from(enabled);
        enabled.mul_equals(&FpVar::from(signer.x.is_eq(&zero)?), &zero)?;
        signed += enabled;
    }
    signed.enforce_equal(&threshold)?;
    id.finalize()
}
