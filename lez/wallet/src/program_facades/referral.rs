use std::collections::{BTreeSet, HashMap};

use common::{HashType, transaction::LeeTransaction};
use lee::{
    Account, AccountId, privacy_preserving_transaction::circuit::ProgramWithDependencies,
    program::Program,
};
use lee_core::{
    Commitment, Identifier, PrivateAccountKind,
    account::ProgramShardSelector,
    program::{InstructionData, PdaSeed},
};
use referral_core::{
    Instruction, Invitation, NodeId, ORACLE_ACCOUNT_ID, Participant, ParticipantAuthorizationV1,
    Registry, State, ed25519_dalek::Signature,
};

use crate::{
    AccountIdentity, ChainView, ExecutionFailureKind, WalletCore,
    account_manager::AccountMention,
    storage::{
        key_chain::FoundPrivateAccount,
        referral::{
            OperationKind, PendingOperation, PendingRegistration, ReferralIntent, ReferralStore,
            SubmissionStatus, random_identifier, random_seed,
        },
    },
};

pub struct Referral<'wallet> {
    wallet: &'wallet mut WalletCore,
    program: ProgramWithDependencies,
}

impl<'wallet> Referral<'wallet> {
    #[must_use]
    pub fn new(
        wallet: &'wallet mut WalletCore,
        program: Program,
        program_account: AccountId,
    ) -> Self {
        let dependencies = HashMap::from([(program_account, program.clone())]);
        Self {
            wallet,
            program: ProgramWithDependencies::new(program, program_account, dependencies),
        }
    }

    #[must_use]
    pub const fn program_account(&self) -> AccountId {
        self.program.self_account_id
    }

    pub fn create_participant(&mut self) -> Result<AccountId, ExecutionFailureKind> {
        let identifier = random_identifier();
        let key_chain = self.wallet.storage_mut().key_chain_mut();
        let cci = key_chain.create_private_accounts_key(None);
        let participant = key_chain
            .register_identifier_on_private_key_chain(&cci, identifier)
            .ok_or(ExecutionFailureKind::KeyNotFoundError)?;
        key_chain
            .insert_private_account(
                participant,
                PrivateAccountKind::Regular(identifier),
                Account::default(),
            )
            .map_err(ExecutionFailureKind::SequencerError)?;
        self.persist()?;
        Ok(participant)
    }

    pub fn state(&self, account: AccountId) -> Result<State, ExecutionFailureKind> {
        let found = self.found(account)?;
        State::decode(found.account.data.shard(self.program_account()))
            .ok_or(ExecutionFailureKind::AccountDataError(account))
    }

    #[must_use]
    pub fn intent(&self, participant: AccountId) -> Option<&ReferralIntent> {
        self.wallet.storage().referral().intents.get(&participant)
    }

    #[must_use]
    pub fn pending_registration(&self, participant: AccountId) -> Option<&PendingRegistration> {
        self.intent(participant)?.registration.as_ref()
    }

    #[must_use]
    pub fn operation_status(&self, reference: [u8; 32]) -> Option<SubmissionStatus> {
        self.wallet
            .storage()
            .referral()
            .operation(reference)
            .map(|operation| operation.status)
    }

    pub fn invitation(
        &self,
        participant: AccountId,
        node: NodeId,
    ) -> Result<Invitation, ExecutionFailureKind> {
        let found = self.found(participant)?;
        Ok(Invitation::new(
            node,
            found.key_chain.nullifier_public_key,
            found.key_chain.viewing_public_key.clone(),
        ))
    }

    pub fn import_invitation(
        &mut self,
        participant: AccountId,
        invitation: Invitation,
    ) -> Result<(), ExecutionFailureKind> {
        let parent = invitation.parent_node;
        let mut intent = self
            .intent(participant)
            .cloned()
            .unwrap_or_else(|| ReferralIntent::new(self.program_account()));
        let recorded = intent.registration.as_ref().map_or_else(
            || self.participant(participant).ok().map(|me| me.referrer),
            |pending| Some(pending.referrer),
        );
        if recorded.is_some_and(|referrer| referrer != Some(parent)) {
            return Err(conflict(
                "this invitation names another referrer than the participant's",
            ));
        }

        intent.invitation = Some(invitation);
        self.store_intent(participant, intent)
    }

    pub fn prepare_registration(
        &mut self,
        participant: AccountId,
        node: NodeId,
        referrer: Option<NodeId>,
    ) -> Result<ParticipantAuthorizationV1, ExecutionFailureKind> {
        let program_account = self.program_account();
        let mut intent = self
            .intent(participant)
            .cloned()
            .unwrap_or_else(|| ReferralIntent::new(program_account));

        if let Some(parent) = referrer
            && intent
                .invitation
                .as_ref()
                .map(|invitation| invitation.parent_node)
                != Some(parent)
        {
            return Err(conflict(
                "the referrer's invitation is needed before its registration",
            ));
        }
        if self.participant(participant).is_ok() {
            return Err(conflict("this participant is already registered"));
        }

        match &intent.registration {
            Some(pending)
                if intent.program_account == program_account
                    && pending.node == node
                    && pending.referrer == referrer => {}
            Some(_pending) => {
                return Err(conflict(
                    "a pending registration for another deployment, node or referrer is unresolved",
                ));
            }
            None => {
                intent.program_account = program_account;
                intent.registration = Some(PendingRegistration {
                    node,
                    referrer,
                    signature: None,
                });
            }
        }
        self.store_intent(participant, intent)?;

        Ok(ParticipantAuthorizationV1::new(
            program_account,
            node,
            participant,
            referrer,
        ))
    }

    pub fn attach_node_signature(
        &mut self,
        participant: AccountId,
        signature: [u8; 64],
    ) -> Result<(), ExecutionFailureKind> {
        let mut intent = self
            .intent(participant)
            .cloned()
            .ok_or(ExecutionFailureKind::KeyNotFoundError)?;
        let pending = intent
            .registration
            .as_mut()
            .ok_or(ExecutionFailureKind::AccountDataError(participant))?;
        pending.signature = Some(Signature::from_bytes(&signature));

        let authorization = ParticipantAuthorizationV1::new(
            intent.program_account,
            pending.node,
            participant,
            pending.referrer,
        );
        if !authorization.verify(&signature) {
            return Err(ExecutionFailureKind::AccountDataError(participant));
        }

        self.store_intent(participant, intent)
    }

    pub async fn registry(&self) -> Result<Registry, ExecutionFailureKind> {
        let program_account = self.program_account();
        let account = self
            .wallet
            .get_account_view(ProgramShardSelector::new(
                ORACLE_ACCOUNT_ID,
                program_account,
            ))
            .await
            .map_err(ExecutionFailureKind::SequencerError)?;
        match State::decode(account.data.shard(program_account)) {
            None => Ok(Registry::default()),
            Some(State::Registry(registry)) => Ok(registry),
            Some(State::Participant(_) | State::Child { .. } | State::Credit { .. }) => {
                Err(ExecutionFailureKind::AccountDataError(ORACLE_ACCOUNT_ID))
            }
        }
    }

    pub fn notes(
        &self,
        participant: AccountId,
    ) -> Result<Vec<(AccountId, State)>, ExecutionFailureKind> {
        let me = self.participant(participant)?;
        let npk = self.found(participant)?.key_chain.nullifier_public_key;
        Ok(self
            .wallet
            .storage()
            .key_chain()
            .private_account_key_chains()
            .filter(|(id, key_chain, _index)| {
                *id != participant && key_chain.nullifier_public_key == npk
            })
            .filter_map(|(id, _key_chain, _index)| {
                let found = self.found(id).ok()?;
                let state = State::decode(found.account.data.shard(self.program_account()))?;
                let addressed = match state {
                    State::Child { referrer, .. } => referrer == me.node,
                    State::Credit { recipient_node, .. } => recipient_node == me.node,
                    State::Registry(_) | State::Participant(_) => false,
                };
                addressed.then_some((id, state))
            })
            .collect())
    }

    pub async fn claimable(&self, participant: AccountId) -> Result<u128, ExecutionFailureKind> {
        let states: Vec<State> = self
            .notes(participant)?
            .into_iter()
            .map(|(_id, state)| state)
            .collect();
        self.preview(participant, &states).await
    }

    async fn preview(
        &self,
        participant: AccountId,
        states: &[State],
    ) -> Result<u128, ExecutionFailureKind> {
        Ok(self
            .participant(participant)?
            .claim(&self.registry().await?, states))
    }

    pub async fn publish(
        &self,
        epoch: u32,
        active: BTreeSet<NodeId>,
    ) -> Result<HashType, ExecutionFailureKind> {
        let program_account = self.program_account();
        let transaction = self
            .wallet
            .build_public_transaction(
                vec![
                    AccountIdentity::Public(ORACLE_ACCOUNT_ID)
                        .select_program_shard(program_account),
                ],
                instruction_data(Instruction::Publish { epoch, active }),
                program_account,
            )
            .await?;
        self.wallet.submit_public_transaction(transaction).await
    }

    pub async fn submit(
        &mut self,
        reference: [u8; 32],
        operation: OperationKind,
    ) -> Result<(HashType, SubmissionStatus), ExecutionFailureKind> {
        let program_account = self.program_account();
        let recorded = self
            .wallet
            .storage()
            .referral()
            .operation(reference)
            .cloned();
        if let Some(recorded) = recorded.as_ref() {
            if recorded.program_account != program_account || recorded.operation != operation {
                return Err(conflict(
                    "this reference was already used for a different deployment or operation",
                ));
            }
            let status = self.reconcile(reference).await?;
            match status {
                SubmissionStatus::Settled => {
                    return Ok((recorded.transaction.hash(), status));
                }
                SubmissionStatus::Pending => {
                    self.rebroadcast(recorded.transaction.clone()).await?;
                    return Ok((recorded.transaction.hash(), SubmissionStatus::Pending));
                }
                SubmissionStatus::Rejected => {}
            }
        }

        let participant = operation.participant();
        let unresolved: Vec<[u8; 32]> = self
            .wallet
            .storage()
            .referral()
            .operations
            .values()
            .filter(|other| {
                other.reference != reference
                    && !other.status.is_conclusive()
                    && other.operation.participant() == participant
            })
            .map(|other| other.reference)
            .collect();
        for other in unresolved {
            if !self.reconcile(other).await?.is_conclusive() {
                return Err(conflict(
                    "another unresolved operation for this participant is in flight",
                ));
            }
        }

        let built = self.build(reference, operation).await?;
        let transaction = built.transaction.clone();
        self.persisted(|store| store.record_operation(built))?;
        let hash = self.rebroadcast(transaction).await?;
        Ok((hash, SubmissionStatus::Pending))
    }

    pub async fn reconcile(
        &mut self,
        reference: [u8; 32],
    ) -> Result<SubmissionStatus, ExecutionFailureKind> {
        let Some(recorded) = self
            .wallet
            .storage()
            .referral()
            .operation(reference)
            .cloned()
        else {
            return Ok(SubmissionStatus::Rejected);
        };
        if recorded.status.is_conclusive() {
            return Ok(recorded.status);
        }

        let selectors: Vec<ProgramShardSelector> = recorded
            .pinned_public_views
            .iter()
            .map(|(selector, _account)| *selector)
            .collect();
        let view = self
            .wallet
            .observe_transaction(&selectors, &effect_commitments(&recorded.transaction))
            .await
            .map_err(ExecutionFailureKind::SequencerError)?;

        if view.effect_settled {
            return self.set_status(reference, SubmissionStatus::Settled);
        }
        if is_superseded(&recorded, &view) || self.is_outspent(&recorded) {
            return self.set_status(reference, SubmissionStatus::Rejected);
        }

        Ok(SubmissionStatus::Pending)
    }

    async fn build(
        &self,
        reference: [u8; 32],
        operation: OperationKind,
    ) -> Result<PendingOperation, ExecutionFailureKind> {
        let (accounts, instruction) = match &operation {
            OperationKind::Register { participant } => self.register_request(*participant).await?,
            OperationKind::Claim { participant, notes } => {
                self.claim_request(*participant, notes).await?
            }
        };

        self.private_operation(reference, operation, accounts, instruction)
            .await
    }

    async fn private_operation(
        &self,
        reference: [u8; 32],
        operation: OperationKind,
        accounts: Vec<AccountMention>,
        instruction: InstructionData,
    ) -> Result<PendingOperation, ExecutionFailureKind> {
        let built = self
            .wallet
            .build_privacy_preserving_tx_with_pre_check(
                accounts,
                instruction,
                &self.program,
                |_| Ok(()),
            )
            .await?;
        Ok(PendingOperation {
            reference,
            program_account: self.program_account(),
            operation,
            transaction: LeeTransaction::PrivacyPreserving(built.transaction),
            pinned_public_views: built.pinned_public_views,
            pinned_private_inputs: built.pinned_private_inputs,
            status: SubmissionStatus::Pending,
        })
    }

    async fn register_request(
        &self,
        participant: AccountId,
    ) -> Result<(Vec<AccountMention>, InstructionData), ExecutionFailureKind> {
        let program_account = self.program_account();
        let (node, referrer, node_signature) = self
            .pending_registration(participant)
            .and_then(|pending| Some((pending.node, pending.referrer, pending.signed()?)))
            .ok_or_else(|| conflict("this participant has no signed registration"))?;
        if self.is_registered(node).await? {
            return Err(conflict("this node is already registered"));
        }

        let mut accounts = vec![
            self.own_private(participant)?
                .select_program_shard(program_account),
            AccountIdentity::PublicNoSign(ORACLE_ACCOUNT_ID).select_program_shard(program_account),
        ];
        self.deliver(participant, referrer, &mut accounts)?;

        Ok((
            accounts,
            instruction_data(Instruction::Register {
                node,
                referrer,
                node_signature,
            }),
        ))
    }

    async fn claim_request(
        &self,
        participant: AccountId,
        notes: &[AccountId],
    ) -> Result<(Vec<AccountMention>, InstructionData), ExecutionFailureKind> {
        let program_account = self.program_account();
        let referrer = self.participant(participant)?.referrer;
        let listed = self.notes(participant)?;
        let states: Vec<State> = notes
            .iter()
            .map(|note| {
                listed
                    .iter()
                    .find_map(|(id, state)| (id == note).then(|| state.clone()))
                    .ok_or_else(|| conflict("this note is not addressed to the participant"))
            })
            .collect::<Result<_, _>>()?;
        if self.preview(participant, &states).await? == 0 {
            return Err(conflict("nothing to claim"));
        }

        let mut accounts = vec![
            self.own_private(participant)?
                .select_program_shard(program_account),
            AccountIdentity::PublicNoSign(ORACLE_ACCOUNT_ID).select_program_shard(program_account),
        ];
        for note in notes {
            accounts.push(
                self.own_private(*note)?
                    .select_program_shard(program_account),
            );
        }
        self.deliver(participant, referrer, &mut accounts)?;

        Ok((accounts, instruction_data(Instruction::Claim)))
    }

    fn deliver(
        &self,
        participant: AccountId,
        referrer: Option<NodeId>,
        accounts: &mut Vec<AccountMention>,
    ) -> Result<(), ExecutionFailureKind> {
        let program_account = self.program_account();
        let Some(parent) = referrer else {
            return Ok(());
        };

        let invitation = self
            .intent(participant)
            .and_then(|intent| intent.invitation.clone())
            .filter(|invitation| invitation.parent_node == parent)
            .ok_or_else(|| conflict("the referrer's invitation is needed to address its note"))?;
        accounts.push(
            foreign_note(
                program_account,
                random_seed(),
                random_identifier(),
                &invitation,
            )
            .select_program_shard(program_account),
        );

        Ok(())
    }

    fn is_outspent(&self, recorded: &PendingOperation) -> bool {
        recorded
            .pinned_private_inputs
            .iter()
            .any(|(account_id, spent)| {
                self.wallet
                    .get_private_account_commitment(*account_id)
                    .is_some_and(|current| current != *spent)
            })
    }

    async fn rebroadcast(
        &self,
        transaction: LeeTransaction,
    ) -> Result<HashType, ExecutionFailureKind> {
        match transaction {
            LeeTransaction::Public(public) => self.wallet.submit_public_transaction(public).await,
            LeeTransaction::PrivacyPreserving(private) => {
                self.wallet
                    .submit_privacy_preserving_transaction(private)
                    .await
            }
        }
    }

    fn set_status(
        &mut self,
        reference: [u8; 32],
        status: SubmissionStatus,
    ) -> Result<SubmissionStatus, ExecutionFailureKind> {
        self.persisted(|store| {
            let Some(recorded) = store.operation_mut(reference) else {
                return;
            };
            recorded.status = status;
            if status != SubmissionStatus::Settled {
                return;
            }
            let registered = matches!(recorded.operation, OperationKind::Register { .. });
            let participant = recorded.operation.participant();
            if let Some(intent) = store.intents.get_mut(&participant)
                && registered
            {
                intent.registration = None;
            }
        })?;
        Ok(status)
    }

    fn store_intent(
        &mut self,
        participant: AccountId,
        intent: ReferralIntent,
    ) -> Result<(), ExecutionFailureKind> {
        self.persisted(|store| {
            store.intents.insert(participant, intent);
        })
    }

    fn persisted<T>(
        &mut self,
        mutate: impl FnOnce(&mut ReferralStore) -> T,
    ) -> Result<T, ExecutionFailureKind> {
        let snapshot = self.wallet.storage().referral().clone();
        let value = mutate(self.wallet.storage_mut().referral_mut());
        if let Err(error) = self.persist() {
            *self.wallet.storage_mut().referral_mut() = snapshot;
            return Err(error);
        }
        Ok(value)
    }

    fn persist(&self) -> Result<(), ExecutionFailureKind> {
        self.wallet
            .store_persistent_data()
            .map_err(ExecutionFailureKind::SequencerError)
    }

    fn participant(&self, account: AccountId) -> Result<Participant, ExecutionFailureKind> {
        let Ok(State::Participant(participant)) = self.state(account) else {
            return Err(conflict("this participant is not registered yet"));
        };
        Ok(participant)
    }

    async fn is_registered(&self, node: NodeId) -> Result<bool, ExecutionFailureKind> {
        Ok(self.registry().await?.nodes.contains(&node))
    }

    fn own_private(&self, account: AccountId) -> Result<AccountIdentity, ExecutionFailureKind> {
        self.wallet
            .resolve_private_account(account)
            .ok_or(ExecutionFailureKind::KeyNotFoundError)
    }

    fn found(&self, account: AccountId) -> Result<FoundPrivateAccount<'_>, ExecutionFailureKind> {
        self.wallet
            .storage()
            .key_chain()
            .private_account(account)
            .ok_or(ExecutionFailureKind::KeyNotFoundError)
    }
}

fn is_superseded(recorded: &PendingOperation, view: &ChainView) -> bool {
    recorded
        .pinned_public_views
        .iter()
        .zip(&view.views)
        .any(|((_selector, pinned), current)| current != pinned)
}

fn effect_commitments(transaction: &LeeTransaction) -> Vec<Commitment> {
    match transaction {
        LeeTransaction::Public(_public) => Vec::new(),
        LeeTransaction::PrivacyPreserving(private) => private.message().commitments(),
    }
}

fn conflict(message: &str) -> ExecutionFailureKind {
    ExecutionFailureKind::TransactionBuildError(lee::error::LeeError::InvalidInput(
        message.to_owned(),
    ))
}

fn foreign_note(
    program_account: AccountId,
    seed: PdaSeed,
    identifier: Identifier,
    invitation: &Invitation,
) -> AccountIdentity {
    AccountIdentity::PrivateForeign {
        npk: invitation.npk,
        vpk: invitation.vpk.clone(),
        kind: PrivateAccountKind::Pda {
            account_id: program_account,
            seed,
            identifier,
        },
    }
}

fn instruction_data(instruction: Instruction) -> InstructionData {
    Program::serialize_instruction(instruction).expect("Instruction should serialize")
}
