//! The vault's program step of an inscription: what it asks zone-sdk to build and the proof of
//! the vault's own rule.

use borsh::BorshDeserialize as _;
use bridge_core::{DepositMetadata, DepositRecipient};
pub use chain_state::vault::{VAULT_PROGRAM, vault_key};
use logos_blockchain_zone_sdk::{
    binary_codec::canonical::BinaryDecode as _,
    core::mantle::{
        batch::{DeferrableProof as _, DeferredProofs},
        notes::{NoteCommitment, derive_program_output_nonce},
        ops::{
            ProgramProof, StepProof, ZkProgramSpendProof, ZkTransferProof,
            channel::{
                ChannelId,
                inscribe::Step,
                program_step::{ProgramDeposit, program_deposit_id},
            },
            zk_transfer::defer_zk_transfer,
        },
    },
    groth16::{Fr, fr_to_bytes},
    key_management_system_service::keys::{PK0, ZkPublicKey},
    node_types::{Inscription, ProgramNoteOpening, Value},
    sequencer::{
        MiniBlockRequest, PreparedProgramStep, ProgramOutput, ProgramStepRequest, StepRequest,
        UserOutput, prove_program_step,
    },
};
use vault_circuit::{
    Committee, Deposit, InputNote, MAX_DEPOSITS, MAX_INPUTS, MAX_OUTPUTS, OutputNote, PublicInputs,
    Signature, VaultCircuit,
};

use crate::{Result, error::Error};

/// The most bytes the inscription of a deposit holds: a borsh [`DepositMetadata`] fits.
pub const MAX_DEPOSIT_INSCRIPTION: u32 = 128;

/// A program deposit the vault consumes, as its holder submitted it.
#[derive(Clone, Debug)]
pub struct VaultDeposit {
    pub deposit: ProgramDeposit,
    /// The holder's proof of the deposit.
    pub proof: ZkTransferProof,
    /// Whom the zone credits: the opening of the deposit's intent, read from its inscription.
    pub recipient: DepositRecipient,
}

impl VaultDeposit {
    /// Admits a deposit to the vault of `committee` on `channel`. `bytes` holds the step, then
    /// its proof, in Bedrock's encoding; the step's inscription is a borsh [`DepositMetadata`].
    ///
    /// Bedrock still decides whether the notes it spends exist and its root is recent.
    pub fn admit(bytes: &[u8], channel: &ChannelId, committee: &Committee) -> Result<Self> {
        let (rest, deposit) = ProgramDeposit::decode(bytes, &(MAX_DEPOSIT_INSCRIPTION, ()))
            .map_err(|_err| Error::InvalidVaultDeposit("its step does not decode"))?;
        let proof = ZkTransferProof::decode_all(rest, &())
            .map_err(|_err| Error::InvalidVaultDeposit("its proof does not decode"))?;
        let recipient = DepositMetadata::try_from_slice(deposit.inscription.as_ref())
            .map_err(|_err| Error::InvalidVaultDeposit("its inscription names no recipient"))?
            .recipient;

        if deposit.program_id != *VAULT_PROGRAM {
            return Err(Error::InvalidVaultDeposit("it pays another program"));
        }
        if deposit.value == 0 {
            return Err(Error::InvalidVaultDeposit("it pays nothing"));
        }
        // Bedrock refuses the whole inscription over a note spent twice.
        if deposit.inputs.iter().enumerate().any(|(at, input)| {
            deposit
                .inputs
                .iter()
                .take(at)
                .any(|earlier| earlier == input)
        }) {
            return Err(Error::InvalidVaultDeposit("it spends a note twice"));
        }
        if deposit.inputs.is_empty() {
            return Err(Error::InvalidVaultDeposit("it spends no note"));
        }
        let intent = Deposit {
            value: deposit.value,
            recipient: recipient_element(&recipient),
        }
        .intent(committee.id());
        if deposit.intent != intent {
            return Err(Error::InvalidVaultDeposit(
                "its intent names another committee or recipient",
            ));
        }
        // A deposit sits in the first mini-block, where its root is the one its holder proved
        // against.
        defer_zk_transfer(
            &proof,
            deposit.inputs.iter(),
            deposit.outputs.iter(),
            deposit.value,
            deposit.commitment_merkle_root,
            program_deposit_id(channel, &deposit),
        )
        .ok()
        .and_then(|transfer| {
            let mut batch = DeferredProofs::new();
            transfer.defer_into(&mut batch);
            batch.verify().ok()
        })
        .ok_or(Error::InvalidVaultDeposit("its proof does not verify"))?;

        Ok(Self {
            deposit,
            proof,
            recipient,
        })
    }

    /// The id the zone mints the deposit under. Bedrock spends a note once, so no other deposit
    /// shares its first nullifier.
    #[must_use]
    pub fn id(&self) -> Option<[u8; 32]> {
        let nullifier = self.deposit.inputs.iter().next()?;
        Some(fr_to_bytes(&nullifier.0))
    }
}

/// A vault note a step may consume, as zone-sdk tracks it.
#[derive(Clone, Debug)]
pub struct VaultNote {
    pub commitment: NoteCommitment,
    pub opening: ProgramNoteOpening,
}

/// What the vault does in one inscription: it takes the deposits in, pays the payouts and keeps
/// the rest in one note. zone-sdk builds the step and its spend; the vault's own proof is ours.
#[derive(Clone, Debug)]
pub struct VaultStep {
    pub committee: Committee,
    /// The vault notes consumed, among the ones zone-sdk lists as spendable.
    pub inputs: Vec<VaultNote>,
    /// In the order of their mini-block.
    pub deposits: Vec<VaultDeposit>,
    /// The value and payee of each payout.
    pub payouts: Vec<(Value, ZkPublicKey)>,
}

impl VaultStep {
    /// The mini-block of the step for zone-sdk to build: the deposits, then the vault's program
    /// step.
    pub fn mini_block(&self) -> Result<MiniBlockRequest> {
        let committee = self.committee.id();
        if self
            .inputs
            .iter()
            .any(|note| note.opening.data != committee)
        {
            return Err(Error::InvalidVaultStep(
                "it consumes a note that is not its vault's",
            ));
        }
        let kept = self.kept_value()?;
        // The spend's own limits are zone-sdk's to check.
        if self.deposits.len() > MAX_DEPOSITS {
            return Err(Error::InvalidVaultStep(
                "it takes in more deposits than a step holds",
            ));
        }

        // A step consuming a note has its output nonces derived from that note. One consuming
        // nothing names them: derived the same way from the first note its deposits spend, which
        // Bedrock lets no other deposit spend.
        let seed = if self.inputs.is_empty() {
            Some(
                self.deposits
                    .iter()
                    .find_map(|deposit| deposit.deposit.inputs.iter().next().copied())
                    .ok_or(Error::InvalidVaultStep("it consumes nothing"))?,
            )
        } else {
            None
        };
        let nonce = |index: usize, value: Value, public_key: &ZkPublicKey| {
            seed.as_ref()
                .map(|seed| derive_program_output_nonce(seed, index, value, public_key))
        };
        let kept_notes = usize::from(kept > 0);

        let deposits = self.deposits.iter().map(|deposit| StepRequest::User {
            step: Step::ProgramDeposit(deposit.deposit.clone()),
            proof: StepProof::ZkTransfer(deposit.proof),
        });
        let program = StepRequest::Program(ProgramStepRequest {
            program_id: *VAULT_PROGRAM,
            inputs: self.inputs.iter().map(|note| note.commitment).collect(),
            program_outputs: (kept > 0)
                .then(|| ProgramOutput {
                    value: kept,
                    stake_public_key: ZkPublicKey::zero(),
                    data: committee,
                    nonce: nonce(0, kept, &PK0),
                })
                .into_iter()
                .collect(),
            outputs: self
                .payouts
                .iter()
                .zip(kept_notes..)
                // The vault lets a payout stake under its payee's key alone.
                .map(|((value, public_key), index)| UserOutput {
                    public_key: *public_key,
                    stake_public_key: *public_key,
                    value: *value,
                    nonce: nonce(index, *value, public_key),
                })
                .collect(),
            inscription: Inscription::default(),
        });
        Ok(deposits.chain([program]).collect())
    }

    /// What a committee member signs to authorize the step zone-sdk built as `draft`.
    #[must_use]
    pub const fn public_inputs(draft: &PreparedProgramStep) -> PublicInputs {
        let [program_step_id, program_deposits_hash, op_id] = draft.program_inputs;
        PublicInputs {
            program_step_id,
            program_deposits_hash,
            op_id,
        }
    }

    /// The spend and program proofs of the step zone-sdk built as `draft`, for
    /// `PreparedProgramInscription::step_proofs`. `signatures` holds one slot per committee member.
    /// Takes seconds of CPU.
    pub fn prove(
        &self,
        draft: &PreparedProgramStep,
        signatures: Vec<Option<Signature>>,
    ) -> Result<(ZkProgramSpendProof, ProgramProof)> {
        let public = Self::public_inputs(draft);
        let signatures = self.threshold_of(&public, signatures)?;

        let inputs: Vec<_> = self
            .inputs
            .iter()
            .map(|note| InputNote {
                value: note.opening.value,
                nonce: note.opening.nonce,
                public_key: *PK0.as_fr(),
                stake_public_key: *note.opening.stake_public_key.as_fr(),
                data: note.opening.data,
            })
            .collect();
        let outputs: Vec<_> = draft
            .outputs
            .iter()
            .map(|note| OutputNote {
                value: note.value,
                nonce: note.nonce,
                public_key: *note.public_key.as_fr(),
                stake_public_key: *note.stake_public_key.as_fr(),
                program: note.program,
                data: note.data,
            })
            .collect();
        let step = vault_circuit::Step {
            inputs: std::array::from_fn(|slot| inputs.get(slot).copied()),
            outputs: std::array::from_fn(|slot| outputs.get(slot).copied()),
        };
        if inputs.len() > MAX_INPUTS
            || outputs.len() > MAX_OUTPUTS
            || step.id() != public.program_step_id
        {
            return Err(Error::InvalidVaultStep(
                "the step built is not the one it describes",
            ));
        }

        let circuit = VaultCircuit {
            committee: self.committee.clone(),
            step,
            deposits: self
                .deposits
                .iter()
                .map(|deposit| Deposit {
                    value: deposit.deposit.value,
                    recipient: recipient_element(&deposit.recipient),
                })
                .collect(),
            public,
            signatures: signatures.clone(),
            successor: self.committee.clone(),
            successor_signatures: signatures,
        };
        let program_proof = vault_circuit::prove(
            vault_circuit::demo_proving_key(),
            circuit,
            &mut rand::rngs::OsRng,
        )
        .map_err(|err| Error::VaultProofFailed(err.into()))?;
        let spend_proof =
            prove_program_step(draft).map_err(|err| Error::VaultProofFailed(err.into()))?;

        Ok((spend_proof, ProgramProof::new(program_proof)))
    }

    /// The valid ones among `signatures`, cut down to the committee's threshold: the circuit
    /// takes exactly that many.
    fn threshold_of(
        &self,
        public: &PublicInputs,
        signatures: Vec<Option<Signature>>,
    ) -> Result<Vec<Option<Signature>>> {
        let mut missing = self.committee.threshold;
        let kept = self
            .committee
            .signers
            .iter()
            .zip(signatures)
            .map(|(signer, signature)| {
                let signature =
                    signature.filter(|signed| missing > 0 && signed.verify(signer, public))?;
                missing = missing.saturating_sub(1);
                Some(signature)
            })
            .collect();
        if missing > 0 {
            return Err(Error::InvalidVaultStep("its committee has not signed it"));
        }
        Ok(kept)
    }

    /// What stays in the vault: the notes consumed and the deposits, less the payouts.
    fn kept_value(&self) -> Result<Value> {
        let held = self
            .deposits
            .iter()
            .map(|deposit| deposit.deposit.value)
            .chain(self.inputs.iter().map(|note| note.opening.value))
            .try_fold(0, |held: Value, value| held.checked_add(value))
            .ok_or(Error::InvalidVaultStep("the value it moves overflows"))?;
        self.payouts
            .iter()
            .try_fold(held, |kept, (value, _)| kept.checked_sub(*value))
            .ok_or(Error::InvalidVaultStep("it pays out more than it holds"))
    }
}

/// The recipient as a deposit's intent commits to it.
fn recipient_element(recipient: &DepositRecipient) -> Fr {
    Deposit::recipient_element(recipient.account_id().value())
}

#[cfg(test)]
mod tests {
    use logos_blockchain_core::mantle::ops::transfer::test_utils::prove_transfer;
    use logos_blockchain_program_spend::{
        ZkProgramSpendChainInputsData, ZkProgramSpendInputNoteData, ZkProgramSpendOutputNoteData,
        ZkProgramSpendWalletInputsData, ZkProgramSpendWitnessInputsData,
    };
    use logos_blockchain_zone_sdk::{
        Slot,
        binary_codec::canonical::BinaryEncode as _,
        core::mantle::{
            channel::Channels,
            ledger::{VerifiableOperation as _, verification_mode::StandardMode},
            note_set::{CommitmentMmr, NoteSets, TxNoteState},
            notes::{NoteNullifier, derive_note_nullifier},
            ops::{
                ChannelInscribeProof, ProgramStepProof, SignedOperation,
                channel::{
                    MsgId, UnverifiedChannelKeys,
                    inscribe::{
                        InscriptionOp, InscriptionPreverificationContext,
                        InscriptionValidationContext,
                    },
                    program_step::ProgramStep,
                },
            },
            programs::{Programs, RegisteredProgram, SpendInputFields, SpendOutputFields},
            transactions::{
                hash::{TxHash, TxHashView},
                states::Unverified,
            },
        },
        key_management_system_service::keys::{Ed25519Key, ZkKey},
        node_types::{
            InputNullifiers, MerklePath, Note, OpId as _, OutputCommitments,
            derive_program_output_nonce, program_deposits_hash, program_step_id,
        },
    };
    use vault_circuit::SigningKey;

    use super::*;

    const SEED: [u8; 32] = [15; 32];

    fn channel() -> ChannelId {
        ChannelId::from([14; 32])
    }

    fn committee() -> Committee {
        Committee {
            threshold: 1,
            signers: vec![SigningKey::from_channel_seed(&SEED).public_key()],
        }
    }

    /// The inscription of `vault` and the draft of its program step, built the way zone-sdk
    /// builds them: `held` are the notes `vault` consumes with their paths to `root`.
    #[expect(
        clippy::arithmetic_side_effects,
        reason = "an addition in the field does not overflow"
    )]
    fn built(
        vault: &VaultStep,
        held: &[(Note, MerklePath)],
        root: Fr,
    ) -> (InscriptionOp, PreparedProgramStep) {
        let mut mini_block = vault.mini_block().unwrap();
        let Some(StepRequest::Program(spec)) = mini_block.pop() else {
            panic!("the mini-block ends with the vault's step");
        };
        let deposits: Vec<_> = vault
            .deposits
            .iter()
            .map(|deposit| &deposit.deposit)
            .collect();
        let index = mini_block.len();
        let parent = MsgId::root();

        let nullifier_key = ZkKey::zero().nullifier_key();
        let nullifiers: Vec<_> = held
            .iter()
            .map(|(note, _)| derive_note_nullifier(&note.commitment(), &nullifier_key))
            .collect();
        let first_input = nullifiers.first().copied().unwrap_or_else(|| {
            NoteNullifier(
                PublicInputs::op_id_element(&parent.into())
                    + Fr::from(u64::try_from(index).unwrap()),
            )
        });
        let program_notes: Vec<_> = spec
            .program_outputs
            .iter()
            .enumerate()
            .map(|(at, output)| ProgramNoteOpening {
                value: output.value,
                nonce: output.nonce.unwrap_or_else(|| {
                    derive_program_output_nonce(&first_input, at, output.value, &PK0)
                }),
                stake_public_key: output.stake_public_key,
                data: output.data,
            })
            .collect();
        let outputs: Vec<Note> = program_notes
            .iter()
            .map(|opening| opening.note(spec.program_id))
            .chain(
                spec.outputs
                    .iter()
                    .zip(program_notes.len()..)
                    .map(|(output, at)| Note {
                        stake_public_key: output.stake_public_key,
                        ..Note::new(
                            output.value,
                            output.nonce.unwrap_or_else(|| {
                                derive_program_output_nonce(
                                    &first_input,
                                    at,
                                    output.value,
                                    &output.public_key,
                                )
                            }),
                            output.public_key,
                        )
                    }),
            )
            .collect();

        let input_fields = std::array::from_fn(|slot| {
            held.get(slot)
                .map_or_else(SpendInputFields::inactive, |(note, _)| SpendInputFields {
                    active: true,
                    value: note.value,
                    nonce: note.nonce,
                    public_key: note.public_key,
                    stake_public_key: note.stake_public_key,
                    data: note.data,
                })
        });
        let output_fields = std::array::from_fn(|slot| {
            outputs
                .get(slot)
                .map_or_else(SpendOutputFields::inactive, SpendOutputFields::of)
        });
        let step = ProgramStep {
            program_id: spec.program_id,
            inputs: InputNullifiers::try_from_iter(nullifiers).unwrap(),
            program_outputs: OutputCommitments::try_from_iter(
                outputs
                    .iter()
                    .take(program_notes.len())
                    .map(Note::commitment),
            )
            .unwrap(),
            outputs: OutputCommitments::try_from_iter(
                outputs
                    .iter()
                    .skip(program_notes.len())
                    .map(Note::commitment),
            )
            .unwrap(),
            commitment_merkle_root: root,
            program_step_id: program_step_id(&input_fields, &output_fields),
            inscription: spec.inscription,
        };
        let step_id = step.program_step_id;

        let steps = vault
            .deposits
            .iter()
            .map(|deposit| Step::ProgramDeposit(deposit.deposit.clone()))
            .chain([Step::Program(step)])
            .collect::<Vec<_>>();
        let op = InscriptionOp {
            channel_id: channel(),
            inscription: Inscription::default(),
            parent,
            signer: Ed25519Key::from_bytes(&SEED).public_key().into_unverified(),
            mini_blocks: [steps.try_into().unwrap()].into(),
        };
        let op_id = PublicInputs::op_id_element(&op.op_id());

        let witness = ZkProgramSpendWitnessInputsData {
            wallet: ZkProgramSpendWalletInputsData {
                inputs: std::array::from_fn(|slot| {
                    held.get(slot).map_or_else(
                        ZkProgramSpendInputNoteData::inactive,
                        |(note, path)| ZkProgramSpendInputNoteData {
                            stake_public_key: *note.stake_public_key.as_fr(),
                            nonce: note.nonce,
                            value: note.value,
                            data: note.data,
                            path_and_selectors: std::array::from_fn(|level| {
                                path.path_and_selectors(level).into()
                            }),
                        },
                    )
                }),
                outputs: std::array::from_fn(|slot| {
                    outputs
                        .get(slot)
                        .map_or_else(ZkProgramSpendOutputNoteData::inactive, |note| {
                            ZkProgramSpendOutputNoteData {
                                public_key: *note.public_key.as_fr(),
                                stake_public_key: *note.stake_public_key.as_fr(),
                                nonce: note.nonce,
                                value: note.value,
                                program: note.program,
                                data: note.data,
                            }
                        })
                }),
            },
            chain: ZkProgramSpendChainInputsData {
                inputs_active: std::array::from_fn(|slot| slot < held.len()),
                outputs_active: std::array::from_fn(|slot| slot < outputs.len()),
                outputs_of_program: std::array::from_fn(|slot| slot < program_notes.len()),
                // No step before this one leaves a note: the deposits have no change.
                tx_commitment_root: root,
                program_id: spec.program_id,
                paid_value: deposits.iter().map(|deposit| deposit.value).sum(),
                msg: op_id,
            },
        };
        let draft = PreparedProgramStep {
            index,
            witness: Box::new(witness),
            program_notes,
            outputs,
            program_inputs: [step_id, program_deposits_hash(&deposits), op_id],
        };
        (op, draft)
    }

    /// Runs Bedrock's checks of the inscription carrying `vault`, on a channel whose note set
    /// holds `notes`: `held` are the ones `vault` consumes.
    fn bedrock_accepts(
        vault: &VaultStep,
        held: &[(Note, MerklePath)],
        root: Fr,
        notes: &[NoteCommitment],
    ) {
        let sequencer = Ed25519Key::from_bytes(&SEED);
        let keys = UnverifiedChannelKeys::from(sequencer.public_key().into_unverified());
        let (channels, note_sets) =
            Channels::new().create_channel(channel(), Slot::from(0), keys, NoteSets::new());
        let set = note_sets
            .channel(&channel())
            .unwrap()
            .clone()
            .execute_adding(notes)
            .unwrap();
        let note_sets = note_sets.update_channel(set).end_block(1, 1024).unwrap();
        let programs = Programs::new()
            .register(RegisteredProgram::new(vault_key()).unwrap())
            .0;

        let (op, draft) = built(vault, held, root);
        let signature =
            SigningKey::from_channel_seed(&SEED).sign(&VaultStep::public_inputs(&draft));
        let (spend_proof, program_proof) = vault.prove(&draft, vec![Some(signature)]).unwrap();
        let proofs = vault
            .deposits
            .iter()
            .map(|deposit| StepProof::ZkTransfer(deposit.proof))
            .chain([StepProof::ProgramStep(ProgramStepProof {
                spend_proof,
                program_proof,
                program_notes: draft.program_notes,
            })])
            .collect();

        let tx_hash_view = TxHashView::new(TxHash::from([9; 32]));
        let inscribe_proof = ChannelInscribeProof::new(
            sequencer.sign_payload(tx_hash_view.as_bytes().as_ref()),
            proofs,
        );
        let deferred = SignedOperation::<_, Unverified, StandardMode>::new(op, inscribe_proof)
            .into_preverified(&InscriptionPreverificationContext {
                tx_hash_view: &tx_hash_view,
            })
            .expect("the inscription is well formed")
            .verify(&InscriptionValidationContext {
                channels: &channels,
                note_sets: &note_sets,
                tx_notes: &TxNoteState::new(),
                programs: &programs,
                block_slot: Slot::from(0),
                block_number: 2,
            })
            .expect("the steps fit the channel's notes");
        let mut batch = DeferredProofs::new();
        deferred.defer_into(&mut batch);
        batch.verify().expect("the proofs of the steps verify");
    }

    /// A vault note of `committee` worth 100, alone in its note set: with its path and root.
    fn held_note(data: Fr) -> (Note, MerklePath, Fr) {
        let held = Note {
            value: 100,
            nonce: Fr::from(21_u64),
            public_key: *PK0,
            stake_public_key: ZkPublicKey::zero(),
            program: *VAULT_PROGRAM,
            data,
        };
        let (mmr, path) = CommitmentMmr::new()
            .push_with_paths(held.commitment(), &mut [])
            .unwrap();
        (held, path, mmr.frontier_root())
    }

    fn vault_note(note: &Note) -> VaultNote {
        VaultNote {
            commitment: note.commitment(),
            opening: ProgramNoteOpening {
                value: note.value,
                nonce: note.nonce,
                stake_public_key: note.stake_public_key,
                data: note.data,
            },
        }
    }

    fn recipient() -> DepositRecipient {
        DepositRecipient::Identified(lee::PublicAccountEvidence::Pda {
            program: lee::AccountId::new([4; 32]),
            seed: bridge_core::PdaSeed::new([6; 32]),
        })
    }

    /// A deposit of a note worth 1000 to the vault of `committee`, with the note and the root
    /// of the set holding it alone.
    fn deposit(committee: &Committee) -> (VaultDeposit, Note, Fr) {
        deposit_of(committee, Fr::from(11_u64))
    }

    /// [`deposit`], of the holder's note with `nonce`.
    fn deposit_of(committee: &Committee, nonce: Fr) -> (VaultDeposit, Note, Fr) {
        let holder = Fr::from(1_u64);
        let note = Note::new(1_000, nonce, ZkKey::new(holder).to_public_key());
        let (mmr, path) = CommitmentMmr::new()
            .push_with_paths(note.commitment(), &mut [])
            .unwrap();
        let root = mmr.frontier_root();
        let metadata = DepositMetadata {
            recipient: recipient(),
        };
        let nullifier =
            derive_note_nullifier(&note.commitment(), &ZkKey::new(holder).nullifier_key());
        let deposit = ProgramDeposit {
            program_id: *VAULT_PROGRAM,
            inputs: [nullifier].into(),
            outputs: OutputCommitments::default(),
            commitment_merkle_root: root,
            value: 1_000,
            intent: Deposit {
                value: 1_000,
                recipient: recipient_element(&recipient()),
            }
            .intent(committee.id()),
            inscription: Inscription::try_new(
                borsh::to_vec(&metadata).unwrap(),
                MAX_DEPOSIT_INSCRIPTION,
            )
            .unwrap(),
        };
        let proof = prove_transfer(
            &[(note, holder, path)],
            &[],
            root,
            program_deposit_id(&channel(), &deposit),
        );
        let deposit = VaultDeposit {
            deposit,
            proof: ZkTransferProof::new(proof),
            recipient: recipient(),
        };
        (deposit, note, root)
    }

    fn submitted(deposit: &VaultDeposit) -> Vec<u8> {
        let mut bytes = Vec::new();
        deposit.deposit.encode_into(&mut bytes);
        deposit.proof.encode_into(&mut bytes);
        bytes
    }

    #[test]
    fn bedrock_accepts_a_deposit_into_an_empty_vault() {
        let (deposit, note, root) = deposit(&committee());
        let vault = VaultStep {
            committee: committee(),
            inputs: vec![],
            deposits: vec![deposit],
            payouts: vec![],
        };

        bedrock_accepts(&vault, &[], root, &[note.commitment()]);
    }

    #[test]
    fn a_submitted_deposit_is_admitted_with_its_recipient() {
        let (deposit, _, _) = deposit(&committee());

        let admitted = VaultDeposit::admit(&submitted(&deposit), &channel(), &committee()).unwrap();

        assert_eq!(admitted.recipient, recipient());
        assert_eq!(admitted.deposit, deposit.deposit);
        assert_eq!(
            admitted.id(),
            Some(fr_to_bytes(
                &deposit.deposit.inputs.iter().next().unwrap().0
            ))
        );
    }

    #[test]
    fn a_deposit_spending_a_note_twice_is_refused() {
        let (mut deposit, _, _) = deposit(&committee());
        let nullifier = *deposit.deposit.inputs.iter().next().unwrap();
        deposit.deposit.inputs = [nullifier, nullifier].into();

        assert!(matches!(
            VaultDeposit::admit(&submitted(&deposit), &channel(), &committee()),
            Err(Error::InvalidVaultDeposit("it spends a note twice"))
        ));
    }

    #[test]
    fn a_step_its_committee_has_not_signed_is_not_proven() {
        let (deposit, _, root) = deposit(&committee());
        let vault = VaultStep {
            committee: committee(),
            inputs: vec![],
            deposits: vec![deposit],
            payouts: vec![],
        };
        let (_, draft) = built(&vault, &[], root);
        let stranger = SigningKey::from_channel_seed(&[16; 32]);
        let signature = stranger.sign(&VaultStep::public_inputs(&draft));

        for signatures in [vec![], vec![None], vec![Some(signature)]] {
            assert!(matches!(
                vault.prove(&draft, signatures),
                Err(Error::InvalidVaultStep("its committee has not signed it"))
            ));
        }
    }

    #[test]
    fn a_step_consuming_a_note_of_another_committee_is_refused() {
        let (held, _, _) = held_note(Fr::from(3_u64));
        let vault = VaultStep {
            committee: committee(),
            inputs: vec![vault_note(&held)],
            deposits: vec![],
            payouts: vec![],
        };

        assert!(matches!(
            vault.mini_block(),
            Err(Error::InvalidVaultStep(
                "it consumes a note that is not its vault's"
            ))
        ));
    }

    #[test]
    fn a_deposit_to_another_committee_is_refused() {
        let other = Committee {
            threshold: 1,
            signers: vec![SigningKey::from_channel_seed(&[16; 32]).public_key()],
        };
        let (deposit, _, _) = deposit(&other);

        assert!(matches!(
            VaultDeposit::admit(&submitted(&deposit), &channel(), &committee()),
            Err(Error::InvalidVaultDeposit(
                "its intent names another committee or recipient"
            ))
        ));
    }

    #[test]
    fn a_deposit_whose_proof_covers_another_channel_is_refused() {
        let (deposit, _, _) = deposit(&committee());

        assert!(matches!(
            VaultDeposit::admit(
                &submitted(&deposit),
                &ChannelId::from([13; 32]),
                &committee()
            ),
            Err(Error::InvalidVaultDeposit("its proof does not verify"))
        ));
    }

    #[test]
    fn bedrock_accepts_a_payout_from_a_vault_note() {
        let (held, path, root) = held_note(committee().id());
        let vault = VaultStep {
            committee: committee(),
            inputs: vec![vault_note(&held)],
            deposits: vec![],
            payouts: vec![(30, ZkKey::new(Fr::from(5_u64)).to_public_key())],
        };

        bedrock_accepts(&vault, &[(held, path)], root, &[held.commitment()]);
    }

    #[test]
    fn a_step_paying_out_more_than_it_holds_is_refused() {
        let vault = VaultStep {
            committee: committee(),
            inputs: vec![],
            deposits: vec![],
            payouts: vec![(1, ZkKey::new(Fr::from(5_u64)).to_public_key())],
        };

        assert!(matches!(
            vault.mini_block(),
            Err(Error::InvalidVaultStep("it pays out more than it holds"))
        ));
    }
}
