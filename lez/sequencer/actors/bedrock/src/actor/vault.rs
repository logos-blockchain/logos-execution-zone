//! The vault's program step of an inscription: the notes it moves and the proofs Bedrock checks.

use std::sync::LazyLock;

use borsh::BorshDeserialize as _;
use bridge_core::{DepositMetadata, DepositRecipient};
use logos_blockchain_mmr::MerklePath;
use logos_blockchain_program_spend::{
    MAX_INPUTS, MAX_OUTPUTS, ZkProgramSpendChainInputsData, ZkProgramSpendInputNoteData,
    ZkProgramSpendOutputNoteData, ZkProgramSpendWalletInputsData, ZkProgramSpendWitnessInputs,
};
use logos_blockchain_zone_sdk::{
    binary_codec::canonical::BinaryDecodeExt,
    core::mantle::{
        batch::{DeferrableProof as _, DeferredProofs},
        notes::{Note, NoteNullifier, derive_note_nullifier},
        ops::{
            ProgramProof, ProgramStepProof, StepProof, ZkProgramSpendProof, ZkTransferProof,
            channel::{
                ChannelId,
                inscribe::{InscriptionOp, MiniBlock, Step},
                program_step::{ProgramDeposit, ProgramStep, program_deposit_id},
            },
            zk_transfer::defer_zk_transfer,
        },
        programs::{SpendInputFields, SpendOutputFields},
    },
    groth16::{Fr, fr_to_bytes},
    key_management_system_service::keys::{PK0, ZkKey, ZkPublicKey},
    node_types::{
        InputNullifiers, Inscription, OpId as _, OutputCommitments, ProgramId, ProgramNoteOpening,
        ProgramVerificationKey, Value, derive_program_id, derive_program_output_nonce,
        program_deposits_hash, program_step_id,
    },
};
use vault_circuit::{
    Committee, Deposit, InputNote, MAX_DEPOSITS, OutputNote, PublicInputs, Signature, VaultCircuit,
};

use crate::{Result, error::Error};

/// The id Bedrock gives the vault program.
pub static VAULT_PROGRAM: LazyLock<ProgramId> = LazyLock::new(|| derive_program_id(&vault_key()));

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
        let (rest, deposit) = <ProgramDeposit as BinaryDecodeExt>::decode(bytes)
            .map_err(|_err| Error::InvalidVaultDeposit("its step does not decode"))?;
        let proof = ZkTransferProof::decode_all(rest)
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
        let intent = Deposit {
            value: deposit.value,
            recipient: recipient_element(&deposit, &recipient)?,
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

/// What the vault does in one inscription: it takes the deposits in, pays the payouts and keeps
/// the rest in one note.
#[derive(Clone, Debug)]
pub struct VaultStep {
    pub committee: Committee,
    /// The vault notes consumed, each with its path to `tx_commitment_root`.
    pub inputs: Vec<(Note, MerklePath)>,
    /// In the order of their mini-block.
    pub deposits: Vec<VaultDeposit>,
    /// The value and payee of each payout.
    pub payouts: Vec<(Value, ZkPublicKey)>,
    /// A recent root of the channel's note set.
    pub commitment_merkle_root: Fr,
    /// That root extended with the notes the transaction creates before this step.
    pub tx_commitment_root: Fr,
}

impl VaultStep {
    /// The mini-block of the step: the deposits, then the vault's program step.
    pub fn mini_block(&self) -> Result<MiniBlock> {
        let steps = self
            .deposits
            .iter()
            .map(|deposit| Step::ProgramDeposit(deposit.deposit.clone()))
            .chain([Step::Program(self.program_step()?)])
            .collect::<Vec<_>>();
        Ok(MiniBlock::try_from(steps).expect("a mini-block with a program step is not empty"))
    }

    /// What a committee member signs to authorize the step in `op`.
    pub fn public_inputs(&self, op: &InscriptionOp) -> Result<PublicInputs> {
        let (inputs, outputs) = self.spend_fields()?;
        Ok(PublicInputs {
            program_step_id: program_step_id(&inputs, &outputs),
            program_deposits_hash: self.deposits_hash(),
            op_id: PublicInputs::op_id_element(&op.op_id()),
        })
    }

    /// One proof per step of [`Self::mini_block`], for the inscription `op` that carries it.
    /// `signatures` holds one slot per committee member.
    pub fn prove(
        &self,
        op: &InscriptionOp,
        signatures: Vec<Option<Signature>>,
    ) -> Result<Vec<StepProof>> {
        let public = self.public_inputs(op)?;
        let (inputs, outputs) = self.spend_fields()?;
        let signatures = self.threshold_of(&public, signatures)?;

        let circuit = VaultCircuit {
            committee: self.committee.clone(),
            step: vault_circuit::Step {
                inputs: inputs.map(|note| {
                    note.active.then(|| InputNote {
                        value: note.value,
                        nonce: note.nonce,
                        public_key: *note.public_key.as_fr(),
                        stake_public_key: *note.stake_public_key.as_fr(),
                        data: note.data,
                    })
                }),
                outputs: outputs.map(|note| {
                    note.active.then(|| OutputNote {
                        value: note.value,
                        nonce: note.nonce,
                        public_key: *note.public_key.as_fr(),
                        stake_public_key: *note.stake_public_key.as_fr(),
                        program: note.program,
                        data: note.data,
                    })
                }),
            },
            deposits: self
                .deposits
                .iter()
                .map(|deposit| {
                    Ok(Deposit {
                        value: deposit.deposit.value,
                        recipient: recipient_element(&deposit.deposit, &deposit.recipient)?,
                    })
                })
                .collect::<Result<_>>()?,
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

        let (spend_proof, _) = logos_blockchain_program_spend::prove(
            ZkProgramSpendWitnessInputs::from_chain_and_wallet_data(
                ZkProgramSpendChainInputsData {
                    inputs_active: inputs.map(|note| note.active),
                    outputs_active: outputs.map(|note| note.active),
                    outputs_of_program: outputs.map(|note| note.program != Fr::from(0_u64)),
                    tx_commitment_root: self.tx_commitment_root,
                    program_id: *VAULT_PROGRAM,
                    paid_value: self.paid_value()?,
                    msg: public.op_id,
                },
                ZkProgramSpendWalletInputsData {
                    inputs: std::array::from_fn(|slot| {
                        self.inputs.get(slot).map_or_else(
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
                    outputs: outputs.map(|note| {
                        if note.active {
                            ZkProgramSpendOutputNoteData {
                                public_key: *note.public_key.as_fr(),
                                stake_public_key: *note.stake_public_key.as_fr(),
                                nonce: note.nonce,
                                value: note.value,
                                program: note.program,
                                data: note.data,
                            }
                        } else {
                            ZkProgramSpendOutputNoteData::inactive()
                        }
                    }),
                },
            ),
        )
        .map_err(|err| Error::VaultProofFailed(err.into()))?;

        let (kept, _) = self.outputs()?;
        Ok(self
            .deposits
            .iter()
            .map(|deposit| StepProof::ZkTransfer(deposit.proof))
            .chain([StepProof::ProgramStep(ProgramStepProof {
                spend_proof: ZkProgramSpendProof::new(spend_proof),
                program_proof: ProgramProof::new(program_proof),
                program_notes: kept
                    .iter()
                    .map(|note| ProgramNoteOpening {
                        value: note.value,
                        nonce: note.nonce,
                        stake_public_key: note.stake_public_key,
                        data: note.data,
                    })
                    .collect(),
            })])
            .collect())
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

    fn program_step(&self) -> Result<ProgramStep> {
        let (inputs, outputs) = self.spend_fields()?;
        let (kept, payouts) = self.outputs()?;
        Ok(ProgramStep {
            program_id: *VAULT_PROGRAM,
            inputs: InputNullifiers::try_from_iter(self.nullifiers())
                .expect("the inputs of a spend fit a note list"),
            program_outputs: commitments(kept.iter()),
            outputs: commitments(payouts.iter()),
            commitment_merkle_root: self.commitment_merkle_root,
            program_step_id: program_step_id(&inputs, &outputs),
            inscription: Inscription::default(),
        })
    }

    /// The note that stays in the vault, if any value does, and the payouts. A program step
    /// lists them in this order.
    fn outputs(&self) -> Result<(Option<Note>, Vec<Note>)> {
        let held = self
            .inputs
            .iter()
            .try_fold(self.paid_value()?, |held, (note, _)| {
                held.checked_add(note.value)
            })
            .ok_or(Error::InvalidVaultStep("the value it moves overflows"))?;
        let kept = self
            .payouts
            .iter()
            .try_fold(held, |kept, (value, _)| kept.checked_sub(*value))
            .ok_or(Error::InvalidVaultStep("it pays out more than it holds"))?;

        // Bedrock fixes the nonces of a step that consumes a note. The vault's rule fixes the
        // others.
        let first_input = self.nullifiers().next();
        let deposits_hash = self.deposits_hash();
        let nonce = |index: usize, value: Value, public_key: &ZkPublicKey| {
            first_input.map_or_else(
                || vault_circuit::bootstrap_nonce(deposits_hash, index),
                |input| derive_program_output_nonce(&input, index, value, public_key),
            )
        };

        let kept = (kept > 0).then(|| Note {
            value: kept,
            nonce: nonce(0, kept, &PK0),
            public_key: *PK0,
            stake_public_key: ZkPublicKey::zero(),
            program: *VAULT_PROGRAM,
            data: self.committee.id(),
        });
        let payouts = self
            .payouts
            .iter()
            .zip(usize::from(kept.is_some())..)
            .map(|((value, payee), index)| Note::new(*value, nonce(index, *value, payee), *payee))
            .collect();
        Ok((kept, payouts))
    }

    /// The step's notes as Bedrock's program spend lays them out.
    fn spend_fields(
        &self,
    ) -> Result<(
        [SpendInputFields; MAX_INPUTS],
        [SpendOutputFields; MAX_OUTPUTS],
    )> {
        let (kept, payouts) = self.outputs()?;
        let outputs: Vec<_> = kept.iter().chain(&payouts).collect();
        if self.inputs.len() > MAX_INPUTS
            || outputs.len() > MAX_OUTPUTS
            || self.deposits.len() > MAX_DEPOSITS
        {
            return Err(Error::InvalidVaultStep(
                "it moves more notes than a step holds",
            ));
        }
        let committee = self.committee.id();
        if self.inputs.iter().any(|(note, _)| {
            note.program != *VAULT_PROGRAM || note.public_key != *PK0 || note.data != committee
        }) {
            return Err(Error::InvalidVaultStep(
                "it consumes a note that is not its vault's",
            ));
        }
        Ok((
            std::array::from_fn(|slot| {
                self.inputs
                    .get(slot)
                    .map_or_else(SpendInputFields::inactive, |(note, _)| SpendInputFields {
                        active: true,
                        value: note.value,
                        nonce: note.nonce,
                        public_key: note.public_key,
                        stake_public_key: note.stake_public_key,
                        data: note.data,
                    })
            }),
            std::array::from_fn(|slot| {
                outputs
                    .get(slot)
                    .map_or_else(SpendOutputFields::inactive, |note| {
                        SpendOutputFields::of(note)
                    })
            }),
        ))
    }

    /// The nullifiers of the consumed notes. A program note is held by the zero key.
    fn nullifiers(&self) -> impl Iterator<Item = NoteNullifier> {
        let nullifier_key = ZkKey::zero().nullifier_key();
        self.inputs
            .iter()
            .map(move |(note, _)| derive_note_nullifier(&note.commitment(), &nullifier_key))
    }

    fn deposits_hash(&self) -> Fr {
        let deposits: Vec<_> = self
            .deposits
            .iter()
            .map(|deposit| &deposit.deposit)
            .collect();
        program_deposits_hash(&deposits)
    }

    fn paid_value(&self) -> Result<Value> {
        self.deposits
            .iter()
            .try_fold(0, |paid: Value, deposit| {
                paid.checked_add(deposit.deposit.value)
            })
            .ok_or(Error::InvalidVaultStep("the value it moves overflows"))
    }
}

/// The key the vault program is registered under.
#[must_use]
pub fn vault_key() -> ProgramVerificationKey {
    ProgramVerificationKey::try_from_bytes(vault_circuit::DEMO_VERIFICATION_KEY)
        .expect("the vault key is a valid program key")
}

/// The recipient as the intent of `deposit` commits to it.
fn recipient_element(deposit: &ProgramDeposit, recipient: &DepositRecipient) -> Result<Fr> {
    let nullifier = deposit
        .inputs
        .iter()
        .next()
        .ok_or(Error::InvalidVaultDeposit("it spends no note"))?;
    Ok(Deposit::recipient_element(
        recipient.account_id().value(),
        nullifier.0,
    ))
}

fn commitments<'note>(notes: impl Iterator<Item = &'note Note>) -> OutputCommitments {
    OutputCommitments::try_from_iter(notes.map(Note::commitment))
        .expect("the outputs of a spend fit a note list")
}

#[cfg(test)]
mod tests {
    use logos_blockchain_core::mantle::ops::transfer::test_utils::prove_transfer;
    use logos_blockchain_zone_sdk::{
        Slot,
        binary_codec::canonical::BinaryEncode as _,
        core::mantle::{
            channel::Channels,
            ledger::{VerifiableOperation as _, verification_mode::StandardMode},
            note_set::{CommitmentMmr, NoteSets, TxNoteState},
            notes::NoteCommitment,
            ops::{
                ChannelInscribeProof, SignedOperation,
                channel::{
                    MsgId, UnverifiedChannelKeys,
                    inscribe::{InscriptionPreverificationContext, InscriptionValidationContext},
                },
            },
            programs::{Programs, RegisteredProgram},
            transactions::{
                hash::{TxHash, TxHashView},
                states::Unverified,
            },
        },
        key_management_system_service::keys::Ed25519Key,
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

    /// Runs Bedrock's checks of an inscription carrying `vault`, on a channel holding `notes`.
    fn bedrock_accepts(vault: &VaultStep, notes: &[NoteCommitment]) {
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
        let note_sets = note_sets.update_channel(set).end_block(1).unwrap();
        let programs = Programs::new()
            .register(RegisteredProgram::new(vault_key()).unwrap())
            .0;

        let op = InscriptionOp {
            channel_id: channel(),
            inscription: Inscription::default(),
            parent: MsgId::root(),
            signer: sequencer.public_key().into_unverified(),
            mini_blocks: [vault.mini_block().unwrap()].into(),
        };
        let signature =
            SigningKey::from_channel_seed(&SEED).sign(&vault.public_inputs(&op).unwrap());
        let proofs = vault.prove(&op, vec![Some(signature)]).unwrap();

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
                recipient: Deposit::recipient_element(
                    recipient().account_id().value(),
                    nullifier.0,
                ),
            }
            .intent(committee.id()),
            inscription: Inscription::try_from(borsh::to_vec(&metadata).unwrap()).unwrap(),
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
            commitment_merkle_root: root,
            tx_commitment_root: root,
        };

        bedrock_accepts(&vault, &[note.commitment()]);
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
    fn equal_deposits_into_an_empty_vault_make_different_notes() {
        let kept_note = |nonce: u64| {
            let (deposit, _, root) = deposit_of(&committee(), Fr::from(nonce));
            let vault = VaultStep {
                committee: committee(),
                inputs: vec![],
                deposits: vec![deposit],
                payouts: vec![],
                commitment_merkle_root: root,
                tx_commitment_root: root,
            };
            vault.program_step().unwrap().program_outputs
        };

        // The same value to the same recipient: only the notes paid in differ.
        assert_ne!(kept_note(11), kept_note(12));
    }

    #[test]
    fn a_step_its_committee_has_not_signed_is_not_proven() {
        let (deposit, _, root) = deposit(&committee());
        let vault = VaultStep {
            committee: committee(),
            inputs: vec![],
            deposits: vec![deposit],
            payouts: vec![],
            commitment_merkle_root: root,
            tx_commitment_root: root,
        };
        let op = InscriptionOp {
            channel_id: channel(),
            inscription: Inscription::default(),
            parent: MsgId::root(),
            signer: Ed25519Key::from_bytes(&SEED).public_key().into_unverified(),
            mini_blocks: [vault.mini_block().unwrap()].into(),
        };
        let stranger = SigningKey::from_channel_seed(&[16; 32]);
        let signature = stranger.sign(&vault.public_inputs(&op).unwrap());

        for signatures in [vec![], vec![None], vec![Some(signature)]] {
            assert!(matches!(
                vault.prove(&op, signatures),
                Err(Error::InvalidVaultStep("its committee has not signed it"))
            ));
        }
    }

    #[test]
    fn a_step_consuming_a_note_of_another_committee_is_refused() {
        let held = Note {
            value: 100,
            nonce: Fr::from(21_u64),
            public_key: *PK0,
            stake_public_key: ZkPublicKey::zero(),
            program: *VAULT_PROGRAM,
            data: Fr::from(3_u64),
        };
        let (_, path) = CommitmentMmr::new()
            .push_with_paths(held.commitment(), &mut [])
            .unwrap();
        let vault = VaultStep {
            committee: committee(),
            inputs: vec![(held, path)],
            deposits: vec![],
            payouts: vec![],
            commitment_merkle_root: Fr::from(0_u64),
            tx_commitment_root: Fr::from(0_u64),
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
        let held = Note {
            value: 100,
            nonce: Fr::from(21_u64),
            public_key: *PK0,
            stake_public_key: ZkPublicKey::zero(),
            program: *VAULT_PROGRAM,
            data: committee().id(),
        };
        let (mmr, path) = CommitmentMmr::new()
            .push_with_paths(held.commitment(), &mut [])
            .unwrap();
        let root = mmr.frontier_root();

        let vault = VaultStep {
            committee: committee(),
            inputs: vec![(held, path)],
            deposits: vec![],
            payouts: vec![(30, ZkKey::new(Fr::from(5_u64)).to_public_key())],
            commitment_merkle_root: root,
            tx_commitment_root: root,
        };

        bedrock_accepts(&vault, &[held.commitment()]);
    }

    #[test]
    fn a_step_paying_out_more_than_it_holds_is_refused() {
        let vault = VaultStep {
            committee: committee(),
            inputs: vec![],
            deposits: vec![],
            payouts: vec![(1, ZkKey::new(Fr::from(5_u64)).to_public_key())],
            commitment_merkle_root: Fr::from(0_u64),
            tx_commitment_root: Fr::from(0_u64),
        };

        assert!(matches!(
            vault.mini_block(),
            Err(Error::InvalidVaultStep("it pays out more than it holds"))
        ));
    }
}
