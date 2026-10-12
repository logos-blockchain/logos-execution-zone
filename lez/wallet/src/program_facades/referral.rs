use std::collections::{BTreeMap, BTreeSet, HashMap};

use common::HashType;
use hkdf::Hkdf;
use indexer_service_protocol::Transaction as IndexedTransaction;
use lee::{
    Account, AccountId, PrivacyPreservingTransaction,
    privacy_preserving_transaction::circuit::ProgramWithDependencies, program::Program,
};
use lee_core::{
    NullifierSecretKey, PrivateAccountKind,
    account::{ProgramShardSelector, ShardData},
    program::InstructionData,
};
use referral_core::{
    Claim, Effect, Instruction, Invitation, NodeId, ORACLE_ACCOUNT_ID, Participant,
    ParticipantAuthorizationV1, Registry, State, active_digest, cash_out_receipt,
    ed25519_dalek::Signature,
};
use sha2::Sha256;

use crate::{
    AccountIdentity, ExecutionFailureKind, WalletCore,
    account_manager::AccountMention,
    storage::{
        key_chain::FoundPrivateAccount,
        referral::{
            OperationKind, PendingOperation, PendingRegistration, Publication, ReferralIntent,
            ReferralStore, SubmissionStatus, random_identifier,
        },
    },
};

const BLINDING_FACTOR_SALT: &[u8; 31] = b"LEZ/Referral/CashOutFactors/v1\0";

const HISTORY_PAGE_LIMIT: u64 = 10;

pub struct Referral<'wallet> {
    wallet: &'wallet mut WalletCore,
    program: ProgramWithDependencies,
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Opening {
    pub program_account: AccountId,
    pub node: NodeId,
    pub blinding_factor: [u8; 32],
    pub account_id: AccountId,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Receipt {
    pub index: u64,
    pub account_id: AccountId,
    pub points: u128,
}

struct ReceiptKeys {
    program_account: AccountId,
    participant: AccountId,
    node: NodeId,
    nsk: NullifierSecretKey,
}

impl ReceiptKeys {
    fn opening(&self, index: u64) -> Opening {
        let mut blinding_factor = [0; 32];
        Hkdf::<Sha256>::new(Some(BLINDING_FACTOR_SALT), &self.nsk)
            .expand_multi_info(
                &[
                    self.program_account.as_ref(),
                    self.participant.as_ref(),
                    &index.to_le_bytes(),
                ],
                &mut blinding_factor,
            )
            .expect("32 bytes is a valid HKDF-SHA256 output length");
        Opening {
            program_account: self.program_account,
            node: self.node,
            blinding_factor,
            account_id: cash_out_receipt(self.program_account, self.node, blinding_factor),
        }
    }
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
        decode_registry(&account, program_account)
    }

    pub fn notes(
        &self,
        participant: AccountId,
    ) -> Result<Vec<(AccountId, State)>, ExecutionFailureKind> {
        let program_account = self.program_account();
        let found = self.found(participant)?;
        let me = decode_participant(found.account, program_account)?;
        let npk = found.key_chain.nullifier_public_key;
        Ok(self
            .wallet
            .storage()
            .key_chain()
            .private_accounts()
            .filter(|note| note.key_chain.nullifier_public_key == npk)
            .filter_map(|note| {
                let state = State::decode(note.account.data.shard(program_account))?;
                let addressed = match state {
                    State::Child { referrer, .. } => referrer == me.node,
                    State::Credit { recipient_node, .. } => recipient_node == me.node,
                    State::Registry(_) | State::Participant(_) | State::CashOut { .. } => false,
                };
                addressed.then(|| {
                    let id = AccountId::for_private_account(
                        &note.key_chain.nullifier_public_key,
                        &note.key_chain.viewing_public_key,
                        note.kind,
                    );
                    (id, state)
                })
            })
            .collect())
    }

    pub async fn claimable(
        &mut self,
        participant: AccountId,
    ) -> Result<u128, ExecutionFailureKind> {
        self.batches(participant)
            .await?
            .iter()
            .try_fold(0, |sum: u128, (_operation, total)| sum.checked_add(*total))
            .ok_or_else(|| conflict("the claimable total overflows"))
    }

    pub async fn claim_operations(
        &mut self,
        participant: AccountId,
    ) -> Result<Vec<OperationKind>, ExecutionFailureKind> {
        Ok(self
            .batches(participant)
            .await?
            .into_iter()
            .map(|(operation, _total)| operation)
            .collect())
    }

    async fn batches(
        &mut self,
        participant: AccountId,
    ) -> Result<Vec<(OperationKind, u128)>, ExecutionFailureKind> {
        let claimant = self.participant(participant)?;
        let registry = self.registry().await?;
        let current = (registry.epoch, active_digest(&registry.active));
        let mut groups = BTreeMap::from([(current, (Vec::new(), Vec::new()))]);
        for (id, state) in self.notes(participant)? {
            let group = if let State::Credit {
                epoch,
                active_digest: digest,
                ..
            } = state
            {
                (epoch, digest)
            } else {
                current
            };
            let (ids, states) = groups.entry(group).or_default();
            ids.push(id);
            states.push(state);
        }

        let mut batches = Vec::new();
        for ((epoch, digest), (notes, states)) in groups {
            let collects = (epoch, digest) != current;
            let active = self.publication(&registry, epoch, digest).await?;
            if !active.contains(&claimant.node) {
                continue;
            }
            let total = claim_for(claimant.clone(), states, epoch, digest, collects, active)?.total;
            if total == 0 {
                continue;
            }
            let operation = if collects {
                OperationKind::CollectCredits {
                    participant,
                    notes,
                    epoch,
                    active_digest: digest,
                }
            } else {
                OperationKind::Claim {
                    participant,
                    notes,
                    epoch,
                    active_digest: digest,
                }
            };
            batches.push((operation, total));
        }
        Ok(batches)
    }

    async fn publication(
        &mut self,
        registry: &Registry,
        epoch: u32,
        digest: [u8; 32],
    ) -> Result<BTreeSet<NodeId>, ExecutionFailureKind> {
        if (registry.epoch, active_digest(&registry.active)) == (epoch, digest) {
            return Ok(registry.active.clone());
        }
        let program_account = self.program_account();
        if let Some(active) =
            self.wallet
                .storage()
                .referral()
                .publication(program_account, epoch, digest)
        {
            return Ok(active.clone());
        }
        self.refresh_publications().await?;
        self.wallet
            .storage()
            .referral()
            .publication(program_account, epoch, digest)
            .cloned()
            .ok_or_else(|| conflict("the active set of that publication is not available"))
    }

    async fn refresh_publications(&mut self) -> Result<(), ExecutionFailureKind> {
        let program_account = self.program_account();
        let mut offset = self
            .wallet
            .storage()
            .referral()
            .history_offsets
            .get(&program_account)
            .copied()
            .unwrap_or(0);
        let mut found = Vec::new();
        loop {
            let page = self
                .wallet
                .get_transactions_by_account(ORACLE_ACCOUNT_ID, offset, HISTORY_PAGE_LIMIT)
                .await
                .map_err(ExecutionFailureKind::SequencerError)?;
            let fetched = u64::try_from(page.len()).expect("a page length fits in u64");
            offset = offset
                .checked_add(fetched)
                .expect("the history offset fits in u64");
            found.extend(
                page.iter()
                    .filter_map(|transaction| published(transaction, program_account)),
            );
            if fetched < HISTORY_PAGE_LIMIT {
                break;
            }
        }
        self.persisted(|store| {
            for publication in found {
                if !store.publications.contains(&publication) {
                    store.publications.push(publication);
                }
            }
            store.history_offsets.insert(program_account, offset);
        })
    }

    pub async fn publish(
        &self,
        epoch: u32,
        active: BTreeSet<NodeId>,
    ) -> Result<HashType, ExecutionFailureKind> {
        let program_account = self.program_account();
        self.wallet
            .send_pub_tx(
                vec![
                    AccountIdentity::Public(ORACLE_ACCOUNT_ID)
                        .select_program_shard(program_account),
                ],
                instruction_data(Instruction::Publish { epoch, active }),
                program_account,
            )
            .await
    }

    pub fn opening(
        &self,
        participant: AccountId,
        index: u64,
    ) -> Result<Opening, ExecutionFailureKind> {
        Ok(self
            .receipt_keys(self.program_account(), participant)?
            .opening(index))
    }

    pub async fn receipts(
        &self,
        participant: AccountId,
    ) -> Result<Vec<Receipt>, ExecutionFailureKind> {
        let keys = self.receipt_keys(self.program_account(), participant)?;
        Ok(self.scan(&keys).await?.0)
    }

    pub async fn cash_out(
        &mut self,
        reference: [u8; 32],
        participant: AccountId,
    ) -> Result<(HashType, SubmissionStatus), ExecutionFailureKind> {
        let recorded = self
            .wallet
            .storage()
            .referral()
            .operation(reference)
            .map(|recorded| recorded.operation.clone());
        let index = match recorded {
            Some(OperationKind::CashOut {
                participant: holder,
                index,
            }) if holder == participant => index,
            _ => {
                let keys = self.receipt_keys(self.program_account(), participant)?;
                self.scan(&keys).await?.1
            }
        };
        self.submit(reference, OperationKind::CashOut { participant, index })
            .await
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
        if let Some(recorded) = recorded {
            if recorded.program_account != program_account || recorded.operation != operation {
                return Err(conflict(
                    "this reference was already used for a different deployment or operation",
                ));
            }
            let hash = HashType(recorded.transaction.hash());
            let status = self.reconcile(reference).await?;
            match status {
                SubmissionStatus::Settled => {
                    return Ok((hash, status));
                }
                SubmissionStatus::Pending => {
                    self.rebroadcast(recorded.transaction).await?;
                    return Ok((hash, SubmissionStatus::Pending));
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
        if recorded.status != SubmissionStatus::Settled
            && let OperationKind::CashOut { participant, index } = recorded.operation
        {
            let receipt = self
                .receipt_keys(recorded.program_account, participant)?
                .opening(index)
                .account_id;
            let shard = self
                .receipt_shard(recorded.program_account, receipt)
                .await?;
            return match cash_out_transition(recorded.status, &shard, self.is_outspent(&recorded)) {
                Some(status) => self.set_status(reference, status),
                None => Ok(recorded.status),
            };
        }
        if recorded.status.is_conclusive() {
            return Ok(recorded.status);
        }

        let registry = self
            .wallet
            .get_account_view(ProgramShardSelector::new(
                ORACLE_ACCOUNT_ID,
                recorded.program_account,
            ))
            .await
            .map_err(ExecutionFailureKind::SequencerError)?;
        let settled = self
            .wallet
            .commitments_settled(&recorded.transaction.message().commitments())
            .await
            .map_err(ExecutionFailureKind::SequencerError)?;

        if settled {
            return self.set_status(reference, SubmissionStatus::Settled);
        }

        if self.is_outspent(&recorded) || is_superseded(&recorded, &registry)? {
            return self.set_status(reference, SubmissionStatus::Rejected);
        }

        Ok(SubmissionStatus::Pending)
    }

    async fn build(
        &mut self,
        reference: [u8; 32],
        operation: OperationKind,
    ) -> Result<PendingOperation, ExecutionFailureKind> {
        let (accounts, instruction) = match &operation {
            OperationKind::Register { participant } => self.register_request(*participant).await?,
            OperationKind::Claim { .. } | OperationKind::CollectCredits { .. } => {
                self.claim_request(&operation).await?
            }
            OperationKind::CashOut { participant, index } => {
                self.cash_out_request(*participant, *index).await?
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
            transaction: built.transaction,
            input_commitments: built.input_commitments,
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
        let registry = self.registry().await?;
        if registry.nodes.contains(&node) {
            return Err(conflict("this node is already registered"));
        }
        if referrer.is_some_and(|parent| !registry.nodes.contains(&parent)) {
            return Err(conflict("the referrer is not registered"));
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
                pool: registry.nodes,
            }),
        ))
    }

    async fn claim_request(
        &mut self,
        operation: &OperationKind,
    ) -> Result<(Vec<AccountMention>, InstructionData), ExecutionFailureKind> {
        let (OperationKind::Claim {
            participant,
            notes,
            epoch,
            active_digest: digest,
        }
        | OperationKind::CollectCredits {
            participant,
            notes,
            epoch,
            active_digest: digest,
        }) = operation
        else {
            unreachable!("only claims and credit collections build a claim")
        };
        let collects = matches!(operation, OperationKind::CollectCredits { .. });
        let registry = self.registry().await?;
        if !collects && (registry.epoch, active_digest(&registry.active)) != (*epoch, *digest) {
            return Err(conflict(
                "the publication this claim was built for has changed",
            ));
        }
        let active = self.publication(&registry, *epoch, *digest).await?;
        let listed = self.notes(*participant)?;
        let states = notes
            .iter()
            .map(|note| {
                listed
                    .iter()
                    .find_map(|(id, state)| (id == note).then(|| state.clone()))
                    .ok_or_else(|| conflict("this note is not addressed to the participant"))
            })
            .collect::<Result<_, _>>()?;
        let claim = claim_for(
            self.participant(*participant)?,
            states,
            *epoch,
            *digest,
            collects,
            active,
        )?;
        if claim.total == 0 {
            return Err(conflict("nothing to claim"));
        }

        let program_account = self.program_account();
        let mut accounts = vec![
            self.own_private(*participant)?
                .select_program_shard(program_account),
        ];
        if !collects {
            accounts.push(
                AccountIdentity::PublicNoSign(ORACLE_ACCOUNT_ID)
                    .select_program_shard(program_account),
            );
        }
        for note in notes {
            accounts.push(
                self.own_private(*note)?
                    .select_program_shard(program_account),
            );
        }
        self.deliver(*participant, claim.forward_to(), &mut accounts)?;

        let instruction = if collects {
            Instruction::CollectCredits(claim)
        } else {
            Instruction::Claim(claim)
        };
        Ok((accounts, instruction_data(instruction)))
    }

    async fn cash_out_request(
        &self,
        participant: AccountId,
        index: u64,
    ) -> Result<(Vec<AccountMention>, InstructionData), ExecutionFailureKind> {
        let program_account = self.program_account();
        let points = self.participant(participant)?.reward_balance;
        if points == 0 {
            return Err(conflict("nothing to cash out"));
        }
        let keys = self.receipt_keys(program_account, participant)?;
        if self.scan(&keys).await?.1 != index {
            return Err(conflict(
                "a cash out takes the participant's first free receipt index",
            ));
        }
        let opening = keys.opening(index);

        Ok((
            vec![
                self.own_private(participant)?
                    .select_program_shard(program_account),
                AccountIdentity::PublicNoSign(opening.account_id)
                    .select_program_shard(program_account),
            ],
            instruction_data(Instruction::CashOut {
                node: opening.node,
                points,
                blinding_factor: opening.blinding_factor,
            }),
        ))
    }

    async fn scan(&self, keys: &ReceiptKeys) -> Result<(Vec<Receipt>, u64), ExecutionFailureKind> {
        let mut receipts = Vec::new();
        let mut index = 0;
        loop {
            let account_id = keys.opening(index).account_id;
            let shard = self.receipt_shard(keys.program_account, account_id).await?;
            if shard.is_empty() {
                return Ok((receipts, index));
            }
            if let Some(State::CashOut { points }) = State::decode(&shard) {
                receipts.push(Receipt {
                    index,
                    account_id,
                    points,
                });
            }
            index = index.checked_add(1).expect("cash-out index fits in u64");
        }
    }

    fn receipt_keys(
        &self,
        program_account: AccountId,
        participant: AccountId,
    ) -> Result<ReceiptKeys, ExecutionFailureKind> {
        let found = self.found(participant)?;
        Ok(ReceiptKeys {
            program_account,
            participant,
            node: decode_participant(found.account, program_account)?.node,
            nsk: found.key_chain.private_key_holder.nullifier_secret_key(),
        })
    }

    async fn receipt_shard(
        &self,
        program_account: AccountId,
        receipt: AccountId,
    ) -> Result<ShardData, ExecutionFailureKind> {
        let account = self
            .wallet
            .get_account_view(ProgramShardSelector::new(receipt, program_account))
            .await
            .map_err(ExecutionFailureKind::SequencerError)?;
        Ok(account.data.shard(program_account).clone())
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
        accounts.push(foreign_note(&invitation).select_program_shard(program_account));

        Ok(())
    }

    fn is_outspent(&self, recorded: &PendingOperation) -> bool {
        recorded
            .input_commitments
            .iter()
            .any(|(account_id, spent)| {
                self.wallet
                    .get_private_account_commitment(*account_id)
                    .is_some_and(|current| current != *spent)
            })
    }

    async fn rebroadcast(
        &self,
        transaction: PrivacyPreservingTransaction,
    ) -> Result<HashType, ExecutionFailureKind> {
        self.wallet
            .submit_privacy_preserving_transaction(transaction)
            .await
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
        decode_participant(self.found(account)?.account, self.program_account())
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

fn decode_participant(
    account: &Account,
    program_account: AccountId,
) -> Result<Participant, ExecutionFailureKind> {
    let Some(State::Participant(participant)) = State::decode(account.data.shard(program_account))
    else {
        return Err(conflict("this participant is not registered yet"));
    };
    Ok(participant)
}

fn decode_registry(
    account: &Account,
    program_account: AccountId,
) -> Result<Registry, ExecutionFailureKind> {
    match State::decode(account.data.shard(program_account)) {
        None => Ok(Registry::default()),
        Some(State::Registry(registry)) => Ok(registry),
        Some(
            State::Participant(_)
            | State::Child { .. }
            | State::Credit { .. }
            | State::CashOut { .. },
        ) => Err(ExecutionFailureKind::AccountDataError(ORACLE_ACCOUNT_ID)),
    }
}

fn claim_for(
    mut claimant: Participant,
    states: Vec<State>,
    epoch: u32,
    digest: [u8; 32],
    collects: bool,
    active: BTreeSet<NodeId>,
) -> Result<Claim, ExecutionFailureKind> {
    if !active.contains(&claimant.node) {
        return Err(conflict(
            "the participant was not active in that publication",
        ));
    }
    for state in &states {
        let belongs = match *state {
            State::Credit {
                epoch: earned,
                active_digest: earned_under,
                ..
            } => (earned, earned_under) == (epoch, digest),
            State::Child { .. } => !collects,
            State::Registry(_) | State::Participant(_) | State::CashOut { .. } => false,
        };
        if !belongs {
            return Err(conflict(
                "this note does not belong to the claimed publication",
            ));
        }
    }
    let referrer = claimant.referrer;
    let total = if collects {
        claimant.collect_credits(&active, &states)
    } else {
        claimant.claim(epoch, &active, &states)
    };
    Ok(Claim {
        epoch,
        active,
        notes: states,
        total,
        referrer,
    })
}

fn is_superseded(
    recorded: &PendingOperation,
    registry: &Account,
) -> Result<bool, ExecutionFailureKind> {
    let registry = decode_registry(registry, recorded.program_account)?;
    Ok(recorded
        .transaction
        .message()
        .public_actions
        .iter()
        .filter(|action| action.account_id == ORACLE_ACCOUNT_ID)
        .flat_map(|action| &action.effects)
        .filter(|effect| effect.program_account_id == recorded.program_account)
        .any(|effect| {
            match borsh::from_slice::<Effect>(&effect.data)
                .expect("referral effect data decodes as referral_core::Effect")
            {
                Effect::Register { node, .. } => registry.nodes.contains(&node),
                Effect::CheckEpoch {
                    epoch,
                    active_digest: digest,
                } => registry.epoch != epoch || active_digest(&registry.active) != digest,
                Effect::Publish { .. }
                | Effect::Create(_)
                | Effect::Claim(_)
                | Effect::CollectCredits(_)
                | Effect::Consume(_)
                | Effect::CashOutBurn { .. } => false,
            }
        }))
}

fn published(transaction: &IndexedTransaction, program_account: AccountId) -> Option<Publication> {
    let program = *program_account.value();
    let (epoch, active) = match transaction {
        IndexedTransaction::Public(public) => {
            if public.message.program_account_id.value != program {
                return None;
            }
            let Instruction::Publish { epoch, active } =
                borsh::from_slice(&public.message.instruction_data).ok()?
            else {
                return None;
            };
            (epoch, active)
        }
        IndexedTransaction::PrivacyPreserving(private) => private
            .message
            .public_actions
            .iter()
            .filter(|action| action.account_id.value == *ORACLE_ACCOUNT_ID.value())
            .flat_map(|action| &action.effects)
            .filter(|effect| effect.program_account_id.value == program)
            .find_map(|effect| {
                let Effect::Publish { epoch, active } = borsh::from_slice(&effect.data).ok()?
                else {
                    return None;
                };
                Some((epoch, active))
            })?,
    };
    Some(Publication {
        program_account,
        epoch,
        active,
    })
}

fn cash_out_transition(
    recorded: SubmissionStatus,
    receipt: &ShardData,
    outspent: bool,
) -> Option<SubmissionStatus> {
    let status = if matches!(State::decode(receipt), Some(State::CashOut { .. })) {
        SubmissionStatus::Settled
    } else if outspent || !receipt.is_empty() {
        SubmissionStatus::Rejected
    } else {
        SubmissionStatus::Pending
    };
    (status != recorded).then_some(status)
}

fn conflict(message: &str) -> ExecutionFailureKind {
    ExecutionFailureKind::TransactionBuildError(lee::error::LeeError::InvalidInput(
        message.to_owned(),
    ))
}

fn foreign_note(invitation: &Invitation) -> AccountIdentity {
    AccountIdentity::PrivateForeign {
        npk: invitation.npk,
        vpk: invitation.vpk.clone(),
        kind: PrivateAccountKind::Regular(random_identifier()),
    }
}

fn instruction_data(instruction: Instruction) -> InstructionData {
    Program::serialize_instruction(instruction).expect("Instruction should serialize")
}

#[cfg(test)]
mod tests {
    use lee::privacy_preserving_transaction::{
        circuit::Proof,
        message::{Message, PublicActionWithID},
        witness_set::WitnessSet,
    };
    use lee_core::execution_state::DeferredPublicEffect;

    use super::*;

    fn private_effect(program_account: AccountId, effect: &Effect) -> PrivacyPreservingTransaction {
        let message = Message {
            public_actions: vec![PublicActionWithID {
                account_id: ORACLE_ACCOUNT_ID,
                effects: vec![DeferredPublicEffect {
                    program_account_id: program_account,
                    shard_program_account_id: program_account,
                    data: borsh::to_vec(effect).unwrap(),
                }],
            }],
            ..Message::default()
        };
        let witness_set = WitnessSet::for_message(&message, Proof::from_inner(Vec::new()), &[]);
        PrivacyPreservingTransaction::new(message, witness_set)
    }

    fn indexed_id(account_id: AccountId) -> indexer_service_protocol::AccountId {
        indexer_service_protocol::AccountId {
            value: *account_id.value(),
        }
    }

    fn indexed_call(program_account: AccountId, instruction: &Instruction) -> IndexedTransaction {
        IndexedTransaction::Public(indexer_service_protocol::PublicTransaction {
            hash: indexer_service_protocol::HashType([0; 32]),
            message: indexer_service_protocol::PublicMessage {
                program_account_id: indexed_id(program_account),
                shard_selectors: Vec::new(),
                nonces: Vec::new(),
                instruction_data: borsh::to_vec(instruction).unwrap(),
                fee: None,
            },
            witness_set: indexer_service_protocol::WitnessSet {
                signatures_and_public_keys: Vec::new(),
                proof: None,
            },
        })
    }

    fn indexed_effect(program_account: AccountId, effect: &Effect) -> IndexedTransaction {
        IndexedTransaction::PrivacyPreserving(
            indexer_service_protocol::PrivacyPreservingTransaction {
                hash: indexer_service_protocol::HashType([0; 32]),
                message: indexer_service_protocol::PrivacyPreservingMessage {
                    public_actions: vec![indexer_service_protocol::PublicActionWithID {
                        account_id: indexed_id(ORACLE_ACCOUNT_ID),
                        effects: vec![indexer_service_protocol::DeferredPublicEffect {
                            program_account_id: indexed_id(program_account),
                            shard_program_account_id: indexed_id(program_account),
                            data: borsh::to_vec(effect).unwrap(),
                        }],
                    }],
                    nonces: Vec::new(),
                    private_actions: Vec::new(),
                    block_validity_window: indexer_service_protocol::ValidityWindow((None, None)),
                    timestamp_validity_window: indexer_service_protocol::ValidityWindow((
                        None, None,
                    )),
                },
                witness_set: indexer_service_protocol::WitnessSet {
                    signatures_and_public_keys: Vec::new(),
                    proof: None,
                },
            },
        )
    }

    #[test]
    fn publications_are_read_from_this_programs_history_by_epoch_and_digest() {
        let ours = AccountId::new([1; 32]);
        let other = AccountId::new([2; 32]);
        let first = BTreeSet::from([NodeId::new([7; 32])]);
        let corrected = BTreeSet::from([NodeId::new([8; 32])]);
        let history = [
            indexed_call(
                ours,
                &Instruction::Publish {
                    epoch: 1,
                    active: first.clone(),
                },
            ),
            indexed_call(
                other,
                &Instruction::Publish {
                    epoch: 1,
                    active: BTreeSet::new(),
                },
            ),
            indexed_call(
                ours,
                &Instruction::CashOut {
                    node: NodeId::new([7; 32]),
                    points: 1,
                    blinding_factor: [0; 32],
                },
            ),
            indexed_effect(
                ours,
                &Effect::CheckEpoch {
                    epoch: 1,
                    active_digest: active_digest(&first),
                },
            ),
            indexed_effect(
                ours,
                &Effect::Publish {
                    epoch: 1,
                    active: corrected.clone(),
                },
            ),
        ];
        let store = ReferralStore {
            publications: history
                .iter()
                .filter_map(|transaction| published(transaction, ours))
                .collect(),
            ..ReferralStore::default()
        };

        assert_eq!(store.publications.len(), 2);
        assert_eq!(
            store.publication(ours, 1, active_digest(&first)),
            Some(&first)
        );
        assert_eq!(
            store.publication(ours, 1, active_digest(&corrected)),
            Some(&corrected)
        );
        assert_eq!(store.publication(ours, 2, active_digest(&first)), None);
        assert_eq!(
            store.publication(other, 1, active_digest(&BTreeSet::new())),
            None
        );
    }

    #[test]
    fn reconciliation_reads_the_recorded_deployment() {
        let ours = AccountId::new([1; 32]);
        let other = AccountId::new([2; 32]);
        let active = BTreeSet::from([NodeId::new([9; 32])]);
        let transaction = private_effect(
            ours,
            &Effect::CheckEpoch {
                epoch: 1,
                active_digest: active_digest(&active),
            },
        );

        let recorded = PendingOperation {
            reference: [0; 32],
            program_account: ours,
            operation: OperationKind::Claim {
                participant: AccountId::new([3; 32]),
                notes: vec![],
                epoch: 1,
                active_digest: active_digest(&active),
            },
            transaction,
            input_commitments: Vec::new(),
            status: SubmissionStatus::Pending,
        };

        let registry = Account::default()
            .with_shard(
                ours,
                State::Registry(Registry {
                    epoch: 2,
                    active: active.clone(),
                    ..Registry::default()
                })
                .to_data(),
            )
            .with_shard(
                other,
                State::Registry(Registry {
                    epoch: 1,
                    active,
                    ..Registry::default()
                })
                .to_data(),
            );

        assert!(is_superseded(&recorded, &registry).expect("registry decodes"));
    }

    #[test]
    fn a_cash_out_settles_on_its_receipt_and_otherwise_follows_its_input() {
        let receipt = State::CashOut { points: 7 }.to_data();
        let note = State::Credit {
            recipient_node: NodeId::new([1; 32]),
            amount: 1,
            epoch: 1,
            active_digest: [0; 32],
        }
        .to_data();
        let empty = ShardData::empty();

        assert_eq!(
            cash_out_transition(SubmissionStatus::Pending, &receipt, false),
            Some(SubmissionStatus::Settled)
        );
        assert_eq!(
            cash_out_transition(SubmissionStatus::Rejected, &receipt, true),
            Some(SubmissionStatus::Settled),
            "another attempt at the same index created the receipt"
        );
        assert_eq!(
            cash_out_transition(SubmissionStatus::Pending, &note, false),
            Some(SubmissionStatus::Rejected)
        );
        assert_eq!(
            cash_out_transition(SubmissionStatus::Pending, &empty, true),
            Some(SubmissionStatus::Rejected)
        );
        assert_eq!(
            cash_out_transition(SubmissionStatus::Pending, &empty, false),
            None
        );
        assert_eq!(
            cash_out_transition(SubmissionStatus::Rejected, &empty, true),
            None
        );
    }

    #[test]
    fn a_participant_is_read_from_its_own_deployment() {
        let (ours, other) = (AccountId::new([1; 32]), AccountId::new([2; 32]));
        let (our_node, other_node) = (NodeId::new([5; 32]), NodeId::new([6; 32]));
        let account = Account::default()
            .with_shard(
                ours,
                State::Participant(Participant::new(our_node, None)).to_data(),
            )
            .with_shard(
                other,
                State::Participant(Participant::new(other_node, None)).to_data(),
            );

        assert_eq!(
            decode_participant(&account, other)
                .expect("the other deployment registered the participant")
                .node,
            other_node
        );
        assert!(
            decode_participant(&Account::default(), other).is_err(),
            "a deployment that never registered the participant holds no participant"
        );
    }

    fn keys(nsk: u8, program_account: u8, participant: u8) -> ReceiptKeys {
        ReceiptKeys {
            program_account: AccountId::new([program_account; 32]),
            participant: AccountId::new([participant; 32]),
            node: NodeId::new([7; 32]),
            nsk: [nsk; 32],
        }
    }

    #[test]
    fn blinding_factors_expand_the_nullifier_key_per_deployment_participant_and_index() {
        assert_eq!(
            keys(1, 2, 3).opening(0).blinding_factor,
            [
                0x54, 0x10, 0xab, 0x83, 0x00, 0xd8, 0x55, 0x91, 0x80, 0x35, 0x91, 0xd3, 0x63, 0x92,
                0x8f, 0x68, 0xbf, 0xe5, 0x33, 0x91, 0x4a, 0x2a, 0x92, 0x85, 0x45, 0xe3, 0xa5, 0xc4,
                0x84, 0xae, 0x3d, 0x91,
            ]
        );
        assert_eq!(
            keys(1, 2, 3).opening(1).blinding_factor,
            [
                0x43, 0xf5, 0xae, 0x83, 0xb9, 0x5a, 0x50, 0x56, 0x90, 0x52, 0x64, 0x0d, 0xaf, 0x83,
                0x2f, 0xd8, 0xf0, 0xff, 0x23, 0xea, 0x55, 0x5c, 0x94, 0xdf, 0xc4, 0xd6, 0xfa, 0xda,
                0x06, 0x16, 0xb6, 0xe5,
            ]
        );
        assert_eq!(
            keys(1, 2, 6).opening(0).blinding_factor,
            [
                0x2b, 0x25, 0x4b, 0xc3, 0x61, 0x68, 0x41, 0x91, 0x7f, 0xcf, 0xf0, 0x0b, 0x9b, 0x6b,
                0x40, 0xce, 0x8c, 0x17, 0x68, 0xe5, 0x8b, 0xba, 0xce, 0x7c, 0xcf, 0xa6, 0xd3, 0x9c,
                0x7f, 0x9c, 0x17, 0xc9,
            ]
        );
        assert_eq!(
            keys(1, 5, 3).opening(0).blinding_factor,
            [
                0x28, 0x10, 0x70, 0x87, 0x4b, 0x39, 0x57, 0x21, 0x9d, 0x83, 0x8d, 0xc3, 0x06, 0xba,
                0xd8, 0x7f, 0x07, 0x43, 0xab, 0x2f, 0xf0, 0x5d, 0xc8, 0xd3, 0x69, 0x35, 0x34, 0xad,
                0x67, 0xe3, 0xcf, 0xec,
            ]
        );
        assert_ne!(
            keys(4, 2, 3).opening(0).blinding_factor,
            keys(1, 2, 3).opening(0).blinding_factor
        );
    }
}
