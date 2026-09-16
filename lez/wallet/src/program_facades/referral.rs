use std::collections::HashMap;

use common::{HashType, transaction::LeeTransaction};
use lee::{
    Account, AccountId, privacy_preserving_transaction::circuit::ProgramWithDependencies,
    program::Program,
};
use lee_core::{
    Commitment, PrivateAccountKind,
    account::{Nonce, ProgramShardSelector},
    program::{InstructionData, PdaSeed},
};
use referral_core::{
    CREDIT_IDENTIFIER, FirstUse, Instruction, Invitation, NodeBatch, NodeId, ORACLE_ACCOUNT_ID,
    ParticipantAuthorizationV1, ParticipantDescriptor, State, StoredState, credit_account_id,
    ed25519_dalek::Signature, registry_account_id, ticket_account_id,
};

use crate::{
    AccountIdentity, ChainView, ExecutionFailureKind, WalletCore,
    account_manager::AccountMention,
    storage::{
        key_chain::FoundPrivateAccount,
        referral::{
            OperationKind, PendingFirstUse, PendingOperation, ReferralIntent, ReferralStore,
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

    pub fn descriptor(
        &self,
        participant: AccountId,
    ) -> Result<ParticipantDescriptor, ExecutionFailureKind> {
        let found = self.found(participant)?;
        Ok(ParticipantDescriptor {
            npk: found.key_chain.nullifier_public_key,
            vpk: found.key_chain.viewing_public_key.clone(),
            identifier: found.kind.identifier(),
        })
    }

    pub fn state(&self, account: AccountId) -> Result<State, ExecutionFailureKind> {
        self.cached_state(account)
    }

    #[must_use]
    pub fn intent(&self, participant: AccountId) -> Option<&ReferralIntent> {
        self.wallet.storage().referral().intents.get(&participant)
    }

    #[must_use]
    pub fn pending_first_use(&self, participant: AccountId) -> Option<FirstUse> {
        self.intent(participant)?.first_use()
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
        let descriptor = self.descriptor(participant)?;
        Ok(Invitation::new(
            self.program_account(),
            node,
            descriptor.npk,
            descriptor.vpk,
        ))
    }

    pub fn import_invitation(
        &mut self,
        participant: AccountId,
        invitation: Invitation,
    ) -> Result<(), ExecutionFailureKind> {
        let parent = invitation
            .parent_node(self.program_account())
            .ok_or_else(|| conflict("this invitation was issued for another deployment"))?;
        let mut intent = self
            .intent(participant)
            .cloned()
            .unwrap_or_else(|| ReferralIntent::new(self.program_account()));
        let recorded = intent.first_use.as_ref().map_or_else(
            || self.referrer(participant, None).ok(),
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

    pub fn prepare_first_use(
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
                .and_then(|invitation| invitation.parent_node(program_account))
                != Some(parent)
        {
            return Err(conflict(
                "the referrer's invitation is needed before its first use",
            ));
        }

        match &intent.first_use {
            Some(pending)
                if intent.program_account == program_account
                    && pending.node == node
                    && pending.referrer == referrer => {}
            Some(_pending) => {
                return Err(conflict(
                    "a pending first use for another deployment, node or referrer is unresolved",
                ));
            }
            None => {
                intent.program_account = program_account;
                intent.first_use = Some(PendingFirstUse {
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
    ) -> Result<FirstUse, ExecutionFailureKind> {
        let mut intent = self
            .intent(participant)
            .cloned()
            .ok_or(ExecutionFailureKind::KeyNotFoundError)?;
        let pending = intent
            .first_use
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

        let first_use = intent
            .first_use()
            .ok_or(ExecutionFailureKind::AccountDataError(participant))?;
        self.store_intent(participant, intent)?;
        Ok(first_use)
    }

    pub fn reserve_credit(
        &mut self,
        participant: AccountId,
    ) -> Result<PdaSeed, ExecutionFailureKind> {
        let mut intent = self.intent_or_recovered(participant)?;
        let seed = random_seed();
        intent.record_credit(seed);
        self.store_intent(participant, intent)?;
        Ok(seed)
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
                SubmissionStatus::Settled | SubmissionStatus::Included => {
                    return Ok((recorded.transaction.hash(), status));
                }
                SubmissionStatus::Pending => {
                    self.rebroadcast(recorded.transaction.clone()).await?;
                    return Ok((recorded.transaction.hash(), SubmissionStatus::Pending));
                }
                SubmissionStatus::Rejected => {}
            }
        }

        if let Some(participant) = operation.participant() {
            let unresolved: Vec<[u8; 32]> = self
                .wallet
                .storage()
                .referral()
                .operations
                .values()
                .filter(|other| {
                    other.reference != reference
                        && !other.status.is_conclusive()
                        && other.operation.participant() == Some(participant)
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
        }

        let built = self.build(reference, operation).await?;
        if recorded.is_some_and(|previous| previous.destination != built.destination) {
            return Err(conflict(
                "a replacement for this reference must deliver its credit to the recorded account",
            ));
        }

        let transaction = built.transaction.clone();
        self.store_operation(built)?;
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

        let nonces = replay_nonces(&recorded.transaction);
        let signers: Vec<AccountId> = nonces.iter().map(|(signer, _nonce)| *signer).collect();
        let selectors: Vec<ProgramShardSelector> = recorded
            .pinned_public_views
            .iter()
            .map(|(selector, _account)| *selector)
            .collect();
        let view = self
            .wallet
            .observe_transaction(
                recorded.transaction.hash(),
                &signers,
                &selectors,
                &effect_commitments(&recorded.transaction),
            )
            .await
            .map_err(ExecutionFailureKind::SequencerError)?;

        if view.effect_settled {
            return self.set_status(reference, SubmissionStatus::Settled);
        }
        if view.included {
            return self.set_status(reference, SubmissionStatus::Included);
        }
        if !is_superseded(&recorded, &nonces, &view) && !self.is_outspent(&recorded, &view) {
            return Ok(SubmissionStatus::Pending);
        }

        self.set_status(reference, SubmissionStatus::Rejected)
    }

    pub fn record_failed_outcome(
        &mut self,
        reference: [u8; 32],
    ) -> Result<SubmissionStatus, ExecutionFailureKind> {
        let Some(recorded) = self.wallet.storage().referral().operation(reference) else {
            return Err(ExecutionFailureKind::KeyNotFoundError);
        };
        if recorded.status != SubmissionStatus::Included {
            return Err(conflict(
                "only an included operation with an unknown outcome can be marked failed",
            ));
        }
        self.set_status(reference, SubmissionStatus::Rejected)
    }

    async fn build(
        &self,
        reference: [u8; 32],
        operation: OperationKind,
    ) -> Result<PendingOperation, ExecutionFailureKind> {
        let program_account = self.program_account();
        let (accounts, instruction, destination) = match &operation {
            OperationKind::AddEpochData { epoch, nodes } => {
                let new_node_ids = NodeBatch::new(nodes.clone())
                    .ok_or_else(|| conflict("the registry batch exceeds its maximum length"))?;
                (
                    vec![
                        AccountIdentity::Public(ORACLE_ACCOUNT_ID).balance(),
                        AccountIdentity::PublicNoSign(registry_account_id(program_account))
                            .select_program_shard(program_account),
                    ],
                    instruction_data(Instruction::AddEpochData {
                        epoch: *epoch,
                        new_node_ids,
                    }),
                    None,
                )
            }
            OperationKind::Grant { node, amount } => (
                vec![
                    AccountIdentity::Public(ORACLE_ACCOUNT_ID).balance(),
                    AccountIdentity::PublicNoSign(ticket_account_id(program_account, *node))
                        .select_program_shard(program_account),
                ],
                instruction_data(Instruction::Grant {
                    node: *node,
                    amount: *amount,
                }),
                None,
            ),
            OperationKind::Collect {
                participant,
                source,
                output_seed,
            } => self.collect_request(*participant, *source, *output_seed)?,
        };

        match operation.participant() {
            None => {
                self.public_operation(reference, operation, accounts, instruction)
                    .await
            }
            Some(_participant) => {
                self.private_operation(reference, operation, destination, accounts, instruction)
                    .await
            }
        }
    }

    async fn public_operation(
        &self,
        reference: [u8; 32],
        operation: OperationKind,
        accounts: Vec<AccountMention>,
        instruction: InstructionData,
    ) -> Result<PendingOperation, ExecutionFailureKind> {
        let program_account = self.program_account();
        let transaction = self
            .wallet
            .build_public_transaction(accounts, instruction, program_account)
            .await?;

        Ok(PendingOperation {
            reference,
            program_account,
            operation,
            transaction: LeeTransaction::Public(transaction),
            pinned_public_views: Vec::new(),
            pinned_private_inputs: Vec::new(),
            destination: None,
            status: SubmissionStatus::Pending,
        })
    }

    async fn private_operation(
        &self,
        reference: [u8; 32],
        operation: OperationKind,
        destination: Option<AccountId>,
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
            destination,
            status: SubmissionStatus::Pending,
        })
    }

    fn collect_request(
        &self,
        participant: AccountId,
        source: AccountId,
        output_seed: Option<PdaSeed>,
    ) -> Result<(Vec<AccountMention>, InstructionData, Option<AccountId>), ExecutionFailureKind>
    {
        let program_account = self.program_account();
        let descriptor = self.descriptor(participant)?;
        let first_use = self.pending_first_use(participant);
        let referrer = self.referrer(participant, first_use.as_ref())?;

        let mut accounts = vec![
            self.own_private(participant)?
                .select_program_shard(program_account),
            self.source_mention(source)
                .select_program_shard(program_account),
        ];

        if referrer.is_none() && output_seed.is_some() {
            return Err(conflict("a root participant's collection takes no output"));
        }
        let destination = referrer
            .map(|parent| -> Result<AccountId, ExecutionFailureKind> {
                let invitation = self
                    .intent(participant)
                    .and_then(|intent| intent.invitation.clone())
                    .filter(|invitation| invitation.parent_node(program_account) == Some(parent))
                    .ok_or_else(|| {
                        conflict("the referrer's invitation is needed before this collection")
                    })?;
                let seed = output_seed.ok_or_else(|| {
                    conflict("a referred participant's collection requires a reserved output seed")
                })?;
                accounts.push(
                    foreign_credit(program_account, seed, &invitation)
                        .select_program_shard(program_account),
                );
                Ok(credit_account_id(
                    program_account,
                    &seed,
                    &invitation.npk,
                    &invitation.vpk,
                ))
            })
            .transpose()?;
        self.push_registry(&mut accounts, first_use.is_some());

        Ok((
            accounts,
            instruction_data(Instruction::Collect {
                participant: descriptor,
                first_use,
            }),
            destination,
        ))
    }

    fn is_outspent(&self, recorded: &PendingOperation, view: &ChainView) -> bool {
        view.height >= self.wallet.storage().last_synced_block()
            && recorded
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
            let OperationKind::Collect {
                participant,
                output_seed,
                ..
            } = recorded.operation
            else {
                return;
            };
            if status != SubmissionStatus::Settled {
                return;
            }
            let Some(intent) = store.intents.get_mut(&participant) else {
                return;
            };
            intent.first_use = None;
            if let Some(seed) = output_seed {
                intent.settle_credit(seed);
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

    fn store_operation(&mut self, operation: PendingOperation) -> Result<(), ExecutionFailureKind> {
        self.persisted(|store| store.record_operation(operation))
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

    fn push_registry(&self, accounts: &mut Vec<AccountMention>, first_use: bool) {
        if first_use {
            let program_account = self.program_account();
            accounts.push(
                AccountIdentity::PublicNoSign(registry_account_id(program_account))
                    .select_program_shard(program_account),
            );
        }
    }

    fn referrer(
        &self,
        participant: AccountId,
        first_use: Option<&FirstUse>,
    ) -> Result<Option<NodeId>, ExecutionFailureKind> {
        if let Some(first_use) = first_use {
            return Ok(first_use.referrer);
        }
        let State::Participant { referrer, .. } = self.cached_state(participant)? else {
            return Err(ExecutionFailureKind::AccountDataError(participant));
        };
        Ok(referrer)
    }

    fn intent_or_recovered(
        &self,
        participant: AccountId,
    ) -> Result<ReferralIntent, ExecutionFailureKind> {
        if let Some(intent) = self.intent(participant) {
            return Ok(intent.clone());
        }
        let State::Participant { .. } = self.cached_state(participant)? else {
            return Err(ExecutionFailureKind::AccountDataError(participant));
        };
        Ok(ReferralIntent::new(self.program_account()))
    }

    fn own_private(&self, account: AccountId) -> Result<AccountIdentity, ExecutionFailureKind> {
        self.wallet
            .resolve_private_account(account)
            .ok_or(ExecutionFailureKind::KeyNotFoundError)
    }

    fn source_mention(&self, source: AccountId) -> AccountIdentity {
        self.wallet
            .resolve_private_account(source)
            .unwrap_or(AccountIdentity::PublicNoSign(source))
    }

    fn found(&self, account: AccountId) -> Result<FoundPrivateAccount<'_>, ExecutionFailureKind> {
        self.wallet
            .storage()
            .key_chain()
            .private_account(account)
            .ok_or(ExecutionFailureKind::KeyNotFoundError)
    }

    fn cached_state(&self, account: AccountId) -> Result<State, ExecutionFailureKind> {
        let found = self.found(account)?;
        Ok(
            StoredState::decode(found.account.data.shard(self.program_account()))
                .ok_or(ExecutionFailureKind::AccountDataError(account))?
                .state,
        )
    }
}

fn is_superseded(
    recorded: &PendingOperation,
    nonces: &[(AccountId, Nonce)],
    view: &ChainView,
) -> bool {
    nonces
        .iter()
        .zip(&view.signer_nonces)
        .any(|((_signer, declared), chain)| chain != declared)
        || recorded
            .pinned_public_views
            .iter()
            .zip(&view.views)
            .any(|((_selector, pinned), current)| current != pinned)
}

fn replay_nonces(transaction: &LeeTransaction) -> Vec<(AccountId, Nonce)> {
    match transaction {
        LeeTransaction::Public(public) => public
            .witness_set()
            .signatures_and_public_keys()
            .iter()
            .map(|(_signature, key)| AccountId::from(key))
            .zip(public.message().nonces.iter().copied())
            .collect(),
        LeeTransaction::PrivacyPreserving(_private) => Vec::new(),
    }
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

fn foreign_credit(
    program_account: AccountId,
    seed: PdaSeed,
    invitation: &Invitation,
) -> AccountIdentity {
    AccountIdentity::PrivateForeign {
        npk: invitation.npk,
        vpk: invitation.vpk.clone(),
        kind: PrivateAccountKind::Pda {
            account_id: program_account,
            seed,
            identifier: CREDIT_IDENTIFIER,
        },
    }
}

fn instruction_data(instruction: Instruction) -> InstructionData {
    Program::serialize_instruction(instruction).expect("Instruction should serialize")
}
