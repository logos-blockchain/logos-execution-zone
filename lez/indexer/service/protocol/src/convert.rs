//! Conversions between `indexer_service_protocol` types and `lee/lee_core` types.

use std::collections::BTreeMap;

use lee_core::account::Nonce;

use crate::{
    Account, AccountData, AccountId, Actor, ActorState, BedrockStatus, Block, BlockBody,
    BlockHeader, BlockId, BlockIngestError, BoundaryStep, Ciphertext, Commitment,
    CommitmentSetDigest, CrossZoneHalt, Delivery, EncryptedNote, EphemeralPublicKey, EventRecord,
    FeeDeclaration, HashType, IndexerStatus, IndexerSyncState, MessageEnvelope, Nullifier, PdaSeed,
    PeerHealth, PeerStatus, PrivacyPreservingMessage, PrivacyPreservingTransaction, PrivateAction,
    Proof, PublicAccountEvidence, PublicExecutionContext, PublicKey, PublicMessage,
    PublicTransaction, RecoveryBinding, RootCall, SealedCast, Selector, Signature, StallReason,
    Transaction, ValidityWindow, WitnessSet,
};

// ============================================================================
// Account-related conversions
// ============================================================================

impl From<lee_core::account::AccountId> for AccountId {
    fn from(value: lee_core::account::AccountId) -> Self {
        Self {
            value: value.into_value(),
        }
    }
}

impl From<AccountId> for lee_core::account::AccountId {
    fn from(value: AccountId) -> Self {
        let AccountId { value } = value;
        Self::new(value)
    }
}

impl From<lee_core::account::Account> for Account {
    fn from(value: lee_core::account::Account) -> Self {
        let lee_core::account::Account { nonce, data } = value;

        Self {
            nonce: nonce.0,
            data: data.into(),
        }
    }
}

impl From<Account> for lee_core::account::Account {
    fn from(value: Account) -> Self {
        let Account { nonce, data } = value;

        Self {
            nonce: Nonce(nonce),
            data: data.into(),
        }
    }
}

impl From<lee_core::account::AccountData> for AccountData {
    fn from(value: lee_core::account::AccountData) -> Self {
        let lee_core::account::AccountData { actor_states } = value;

        Self {
            actor_states: actor_states
                .into_iter()
                .map(|(program, data)| (program.into(), data.into()))
                .collect(),
        }
    }
}

impl From<AccountData> for lee_core::account::AccountData {
    fn from(value: AccountData) -> Self {
        let AccountData { actor_states } = value;

        Self {
            actor_states: actor_states
                .into_iter()
                .map(|(program, data)| (program.into(), data.into()))
                .collect(),
        }
    }
}

impl From<lee_core::account::Actor> for Actor {
    fn from(value: lee_core::account::Actor) -> Self {
        let lee_core::account::Actor {
            account_id,
            program_account_id,
        } = value;

        Self {
            account_id: account_id.into(),
            program_account_id: program_account_id.into(),
        }
    }
}

impl From<Actor> for lee_core::account::Actor {
    fn from(value: Actor) -> Self {
        let Actor {
            account_id,
            program_account_id,
        } = value;

        Self {
            account_id: account_id.into(),
            program_account_id: program_account_id.into(),
        }
    }
}

impl From<lee_core::account::ActorState> for ActorState {
    fn from(value: lee_core::account::ActorState) -> Self {
        Self(value.into_inner())
    }
}

impl From<ActorState> for lee_core::account::ActorState {
    fn from(value: ActorState) -> Self {
        Self::from(value.0)
    }
}

// ============================================================================
// Commitment and Nullifier conversions
// ============================================================================

impl From<lee_core::Commitment> for Commitment {
    fn from(value: lee_core::Commitment) -> Self {
        Self(value.to_byte_array())
    }
}

impl From<Commitment> for lee_core::Commitment {
    fn from(value: Commitment) -> Self {
        Self::from_byte_array(value.0)
    }
}

impl From<lee_core::Nullifier> for Nullifier {
    fn from(value: lee_core::Nullifier) -> Self {
        Self(value.to_byte_array())
    }
}

impl From<Nullifier> for lee_core::Nullifier {
    fn from(value: Nullifier) -> Self {
        Self::from_byte_array(value.0)
    }
}

impl From<lee_core::CommitmentSetDigest> for CommitmentSetDigest {
    fn from(value: lee_core::CommitmentSetDigest) -> Self {
        Self(value)
    }
}

impl From<CommitmentSetDigest> for lee_core::CommitmentSetDigest {
    fn from(value: CommitmentSetDigest) -> Self {
        value.0
    }
}

// ============================================================================
// Encryption-related conversions
// ============================================================================

impl From<lee_core::encryption::Ciphertext> for Ciphertext {
    fn from(value: lee_core::encryption::Ciphertext) -> Self {
        Self(value.into_inner())
    }
}

impl From<Ciphertext> for lee_core::encryption::Ciphertext {
    fn from(value: Ciphertext) -> Self {
        Self::from_inner(value.0)
    }
}

impl From<lee_core::encryption::EphemeralPublicKey> for EphemeralPublicKey {
    fn from(value: lee_core::encryption::EphemeralPublicKey) -> Self {
        Self(value.0)
    }
}

impl From<EphemeralPublicKey> for lee_core::encryption::EphemeralPublicKey {
    fn from(value: EphemeralPublicKey) -> Self {
        Self(value.0)
    }
}

// ============================================================================
// Signature and PublicKey conversions
// ============================================================================

impl From<lee::Signature> for Signature {
    fn from(value: lee::Signature) -> Self {
        let lee::Signature { value } = value;
        Self(value)
    }
}

impl From<Signature> for lee::Signature {
    fn from(value: Signature) -> Self {
        let Signature(sig_value) = value;
        Self { value: sig_value }
    }
}

impl From<lee::PublicKey> for PublicKey {
    fn from(value: lee::PublicKey) -> Self {
        Self(*value.value())
    }
}

impl TryFrom<PublicKey> for lee::PublicKey {
    type Error = lee::error::LeeError;

    fn try_from(value: PublicKey) -> Result<Self, Self::Error> {
        Self::try_new(value.0)
    }
}

// ============================================================================
// Proof conversions
// ============================================================================

impl From<lee::privacy_preserving_transaction::circuit::Proof> for Proof {
    fn from(value: lee::privacy_preserving_transaction::circuit::Proof) -> Self {
        Self(value.into_inner())
    }
}

impl From<Proof> for lee::privacy_preserving_transaction::circuit::Proof {
    fn from(value: Proof) -> Self {
        Self::from_inner(value.0)
    }
}

// ============================================================================
// EncryptedNote conversions
// ============================================================================

impl From<lee_core::EncryptedNote> for EncryptedNote {
    fn from(value: lee_core::EncryptedNote) -> Self {
        Self {
            ciphertext: value.ciphertext.into(),
            epk: value.epk.into(),
        }
    }
}

impl From<EncryptedNote> for lee_core::EncryptedNote {
    fn from(value: EncryptedNote) -> Self {
        Self {
            ciphertext: value.ciphertext.into(),
            epk: value.epk.into(),
        }
    }
}

// ============================================================================
// Transaction Message conversions
// ============================================================================

impl From<lee::FeeDeclaration> for FeeDeclaration {
    fn from(value: lee::FeeDeclaration) -> Self {
        let lee::FeeDeclaration {
            payer,
            gas_limit,
            tip,
            max_fee,
        } = value;
        Self {
            payer: payer.into(),
            gas_limit,
            tip,
            max_fee,
        }
    }
}

impl From<FeeDeclaration> for lee::FeeDeclaration {
    fn from(value: FeeDeclaration) -> Self {
        let FeeDeclaration {
            payer,
            gas_limit,
            tip,
            max_fee,
        } = value;
        Self::new(payer.into(), gas_limit, tip, max_fee)
    }
}

impl From<lee::public_transaction::Message> for PublicMessage {
    fn from(value: lee::public_transaction::Message) -> Self {
        let lee::TransactionMessage {
            context,
            execution: lee::public_transaction::PublicExecution { root, fee },
            nonces,
            admission_evidence,
        } = value;
        Self {
            context: context.into(),
            root: root.into(),
            fee: fee.map(Into::into),
            nonces: nonce_entries(nonces),
            admission_evidence: admission_evidence.into_iter().map(Into::into).collect(),
        }
    }
}

impl TryFrom<PublicMessage> for lee::public_transaction::Message {
    type Error = lee::error::LeeError;

    fn try_from(value: PublicMessage) -> Result<Self, Self::Error> {
        let PublicMessage {
            context,
            root,
            fee,
            nonces,
            admission_evidence,
        } = value;
        Ok(Self {
            context: context.into(),
            execution: lee::public_transaction::PublicExecution {
                root: root.into(),
                fee: fee.map(Into::into),
            },
            nonces: nonce_map(nonces)?,
            admission_evidence: admission_evidence
                .into_iter()
                .map(TryInto::try_into)
                .collect::<Result<Vec<_>, Self::Error>>()?,
        })
    }
}

impl From<lee_core::RootCall> for RootCall {
    fn from(value: lee_core::RootCall) -> Self {
        let lee_core::RootCall { to, message } = value;
        Self {
            to: to.into(),
            message,
        }
    }
}

impl From<RootCall> for lee_core::RootCall {
    fn from(value: RootCall) -> Self {
        let RootCall { to, message } = value;
        Self {
            to: to.into(),
            message,
        }
    }
}

impl From<lee::PublicAccountEvidence> for PublicAccountEvidence {
    fn from(value: lee::PublicAccountEvidence) -> Self {
        match value {
            lee::PublicAccountEvidence::Key(key) => Self::Key(key.into()),
            lee::PublicAccountEvidence::Pda { program, seed } => Self::Pda {
                program: program.into(),
                seed: seed.into(),
            },
        }
    }
}

impl TryFrom<PublicAccountEvidence> for lee::PublicAccountEvidence {
    type Error = lee::error::LeeError;

    fn try_from(value: PublicAccountEvidence) -> Result<Self, Self::Error> {
        match value {
            PublicAccountEvidence::Key(key) => Ok(Self::Key(key.try_into()?)),
            PublicAccountEvidence::Pda { program, seed } => Ok(Self::Pda {
                program: program.into(),
                seed: seed.into(),
            }),
        }
    }
}

impl From<lee_core::program::PdaSeed> for PdaSeed {
    fn from(value: lee_core::program::PdaSeed) -> Self {
        Self(*value.as_bytes())
    }
}

impl From<PdaSeed> for lee_core::program::PdaSeed {
    fn from(value: PdaSeed) -> Self {
        Self::new(value.0)
    }
}

impl<S: Into<T>, T> From<lee_core::program::MessageEnvelope<S>> for MessageEnvelope<T> {
    fn from(value: lee_core::program::MessageEnvelope<S>) -> Self {
        let lee_core::program::MessageEnvelope { from, to, message } = value;
        Self {
            from: from.into(),
            to: to.into(),
            message,
        }
    }
}

impl<S: Into<T>, T> From<MessageEnvelope<S>> for lee_core::program::MessageEnvelope<T> {
    fn from(value: MessageEnvelope<S>) -> Self {
        let MessageEnvelope { from, to, message } = value;
        Self {
            from: from.into(),
            to: to.into(),
            message,
        }
    }
}

impl<S: Into<T>, T> From<lee_core::execution_state::Delivery<S>> for Delivery<T> {
    fn from(value: lee_core::execution_state::Delivery<S>) -> Self {
        let lee_core::execution_state::Delivery {
            envelope,
            inherited_authorizations,
            inherits_entry_authorizations,
            pda_seeds,
        } = value;
        Self {
            envelope: envelope.into(),
            inherited_authorizations: inherited_authorizations
                .into_iter()
                .map(Into::into)
                .collect(),
            inherits_entry_authorizations,
            pda_seeds: pda_seeds.into_iter().map(Into::into).collect(),
        }
    }
}

impl<S: Into<T>, T> From<Delivery<S>> for lee_core::execution_state::Delivery<T> {
    fn from(value: Delivery<S>) -> Self {
        let Delivery {
            envelope,
            inherited_authorizations,
            inherits_entry_authorizations,
            pda_seeds,
        } = value;
        Self {
            envelope: envelope.into(),
            inherited_authorizations: inherited_authorizations
                .into_iter()
                .map(Into::into)
                .collect(),
            inherits_entry_authorizations,
            pda_seeds: pda_seeds.into_iter().map(Into::into).collect(),
        }
    }
}

impl From<lee_core::execution_state::BoundaryStep> for BoundaryStep {
    fn from(value: lee_core::execution_state::BoundaryStep) -> Self {
        match value {
            lee_core::execution_state::BoundaryStep::PrivateToPublic(delivery) => {
                Self::PrivateToPublic(delivery.into())
            }
            lee_core::execution_state::BoundaryStep::PublicToPrivate(cross_message) => {
                Self::PublicToPrivate(cross_message.into())
            }
            lee_core::execution_state::BoundaryStep::EndPrivateSubtree => Self::EndPrivateSubtree,
            lee_core::execution_state::BoundaryStep::EndPublicSubtree => Self::EndPublicSubtree,
        }
    }
}

impl From<BoundaryStep> for lee_core::execution_state::BoundaryStep {
    fn from(value: BoundaryStep) -> Self {
        match value {
            BoundaryStep::PrivateToPublic(delivery) => Self::PrivateToPublic(delivery.into()),
            BoundaryStep::PublicToPrivate(cross_message) => {
                Self::PublicToPrivate(cross_message.into())
            }
            BoundaryStep::EndPrivateSubtree => Self::EndPrivateSubtree,
            BoundaryStep::EndPublicSubtree => Self::EndPublicSubtree,
        }
    }
}

impl From<lee_core::execution_state::PublicExecutionContext> for PublicExecutionContext {
    fn from(value: lee_core::execution_state::PublicExecutionContext) -> Self {
        let lee_core::execution_state::PublicExecutionContext {
            actors,
            authorized_accounts,
            cast_promotions,
        } = value;
        Self {
            actors: actors.into_iter().map(Into::into).collect(),
            authorized_accounts: authorized_accounts.into_iter().map(Into::into).collect(),
            cast_promotions: cast_promotions.into_iter().collect(),
        }
    }
}

impl From<PublicExecutionContext> for lee_core::execution_state::PublicExecutionContext {
    fn from(value: PublicExecutionContext) -> Self {
        let PublicExecutionContext {
            actors,
            authorized_accounts,
            cast_promotions,
        } = value;
        Self {
            actors: actors.into_iter().map(Into::into).collect(),
            authorized_accounts: authorized_accounts.into_iter().map(Into::into).collect(),
            cast_promotions: cast_promotions.into_iter().collect(),
        }
    }
}

impl From<lee_core::PrivateAction> for PrivateAction {
    fn from(value: lee_core::PrivateAction) -> Self {
        Self {
            nullifier: value.nullifier.into(),
            root: value.root.into(),
            commitment: value.commitment.into(),
            encrypted_post_state: value.encrypted_post_state.into(),
        }
    }
}

impl From<lee_core::RecoveryBinding> for RecoveryBinding {
    fn from(value: lee_core::RecoveryBinding) -> Self {
        let lee_core::RecoveryBinding { address, note } = value;
        Self {
            address: address.into(),
            note: note.into(),
        }
    }
}

impl From<RecoveryBinding> for lee_core::RecoveryBinding {
    fn from(value: RecoveryBinding) -> Self {
        let RecoveryBinding { address, note } = value;
        Self {
            address: address.into(),
            note: note.into(),
        }
    }
}

impl From<lee_core::SealedCast> for SealedCast {
    fn from(value: lee_core::SealedCast) -> Self {
        let lee_core::SealedCast { commitment, note } = value;
        Self {
            commitment: commitment.into(),
            note: note.into(),
        }
    }
}

impl From<SealedCast> for lee_core::SealedCast {
    fn from(value: SealedCast) -> Self {
        let SealedCast { commitment, note } = value;
        Self {
            commitment: commitment.into(),
            note: note.into(),
        }
    }
}

impl From<lee::privacy_preserving_transaction::message::Message> for PrivacyPreservingMessage {
    fn from(value: lee::privacy_preserving_transaction::message::Message) -> Self {
        let lee::TransactionMessage {
            context,
            execution:
                lee_core::ProvenExecution {
                    boundary,
                    casts,
                    recovery_bindings,
                    public_root,
                    private_actions,
                    validity,
                    // Not yet part of this wire protocol; see the `program_image_claims` field doc
                    // on `lee_core::ProvenExecution`. FFI/wallet plumbing for address-flexible
                    // program dispatch is tracked separately.
                    program_image_claims: _,
                },
            nonces,
            admission_evidence,
        } = value;
        Self {
            context: context.into(),
            boundary: boundary.into_iter().map(Into::into).collect(),
            casts: casts.into_iter().map(Into::into).collect(),
            recovery_bindings: recovery_bindings.into_iter().map(Into::into).collect(),
            public_root: public_root.map(Into::into),
            nonces: nonce_entries(nonces),
            private_actions: private_actions.into_iter().map(Into::into).collect(),
            block_validity_window: validity.blocks.into(),
            timestamp_validity_window: validity.timestamps.into(),
            admission_evidence: admission_evidence.into_iter().map(Into::into).collect(),
        }
    }
}

impl From<PrivateAction> for lee_core::PrivateAction {
    fn from(value: PrivateAction) -> Self {
        Self {
            nullifier: value.nullifier.into(),
            root: value.root.into(),
            commitment: value.commitment.into(),
            encrypted_post_state: value.encrypted_post_state.into(),
        }
    }
}

impl TryFrom<PrivacyPreservingMessage> for lee::privacy_preserving_transaction::message::Message {
    type Error = lee::error::LeeError;

    fn try_from(value: PrivacyPreservingMessage) -> Result<Self, Self::Error> {
        let PrivacyPreservingMessage {
            context,
            boundary,
            casts,
            recovery_bindings,
            public_root,
            nonces,
            private_actions,
            block_validity_window,
            timestamp_validity_window,
            admission_evidence,
        } = value;

        let private_actions = private_actions.into_iter().map(Into::into).collect();

        Ok(Self {
            context: context.into(),
            execution: lee_core::ProvenExecution {
                boundary: boundary.into_iter().map(Into::into).collect(),
                casts: casts.into_iter().map(Into::into).collect(),
                recovery_bindings: recovery_bindings.into_iter().map(Into::into).collect(),
                public_root: public_root.map(Into::into),
                private_actions,
                validity: lee_core::program::ValidityWindows {
                    blocks: block_validity_window
                        .try_into()
                        .map_err(|e| lee::error::LeeError::InvalidInput(format!("{e}")))?,
                    timestamps: timestamp_validity_window
                        .try_into()
                        .map_err(|e| lee::error::LeeError::InvalidInput(format!("{e}")))?,
                },
                // Not yet part of this wire protocol; see the corresponding destructure above.
                // A privacy-preserving tx submitted through this protocol will fail proof
                // verification for any program not at its bijection address until this is wired.
                program_image_claims: Vec::new(),
            },
            nonces: nonce_map(nonces)?,
            admission_evidence: admission_evidence
                .into_iter()
                .map(TryInto::try_into)
                .collect::<Result<Vec<_>, Self::Error>>()?,
        })
    }
}

// ============================================================================
// WitnessSet conversions
// ============================================================================

impl From<lee::public_transaction::WitnessSet> for WitnessSet {
    fn from(value: lee::public_transaction::WitnessSet) -> Self {
        Self {
            signatures_and_public_keys: value
                .signatures_and_public_keys()
                .iter()
                .map(|(sig, pk)| (sig.clone().into(), pk.clone().into()))
                .collect(),
            proof: None,
        }
    }
}

impl From<lee::privacy_preserving_transaction::witness_set::WitnessSet> for WitnessSet {
    fn from(value: lee::privacy_preserving_transaction::witness_set::WitnessSet) -> Self {
        let (sigs_and_pks, proof) = value.into_raw_parts();
        Self {
            signatures_and_public_keys: sigs_and_pks
                .into_iter()
                .map(|(sig, pk)| (sig.into(), pk.into()))
                .collect(),
            proof: Some(proof.into()),
        }
    }
}

impl TryFrom<WitnessSet> for lee::privacy_preserving_transaction::witness_set::WitnessSet {
    type Error = lee::error::LeeError;

    fn try_from(value: WitnessSet) -> Result<Self, Self::Error> {
        let WitnessSet {
            signatures_and_public_keys,
            proof,
        } = value;
        let signatures_and_public_keys = signatures_and_public_keys
            .into_iter()
            .map(|(sig, pk)| Ok((sig.into(), pk.try_into()?)))
            .collect::<Result<Vec<_>, Self::Error>>()?;

        Ok(Self::from_raw_parts(
            signatures_and_public_keys,
            proof
                .map(Into::into)
                .ok_or_else(|| lee::error::LeeError::InvalidInput("Missing proof".to_owned()))?,
        ))
    }
}

// ============================================================================
// Transaction conversions
// ============================================================================

impl From<lee::PublicTransaction> for PublicTransaction {
    fn from(value: lee::PublicTransaction) -> Self {
        let hash = HashType(value.hash());
        let lee::PublicTransaction {
            message,
            witness_set,
        } = value;

        Self {
            hash,
            message: message.into(),
            witness_set: witness_set.into(),
        }
    }
}

impl TryFrom<PublicTransaction> for lee::PublicTransaction {
    type Error = lee::error::LeeError;

    fn try_from(value: PublicTransaction) -> Result<Self, Self::Error> {
        let PublicTransaction {
            hash: _,
            message,
            witness_set,
        } = value;
        let WitnessSet {
            signatures_and_public_keys,
            proof: _,
        } = witness_set;

        Ok(Self::new(
            message.try_into()?,
            lee::public_transaction::WitnessSet::from_raw_parts(
                signatures_and_public_keys
                    .into_iter()
                    .map(|(sig, pk)| Ok((sig.into(), pk.try_into()?)))
                    .collect::<Result<Vec<_>, Self::Error>>()?,
            ),
        ))
    }
}

impl From<lee::PrivacyPreservingTransaction> for PrivacyPreservingTransaction {
    fn from(value: lee::PrivacyPreservingTransaction) -> Self {
        let hash = HashType(value.hash());
        let lee::PrivacyPreservingTransaction {
            message,
            witness_set,
        } = value;

        Self {
            hash,
            message: message.into(),
            witness_set: witness_set.into(),
        }
    }
}

impl TryFrom<PrivacyPreservingTransaction> for lee::PrivacyPreservingTransaction {
    type Error = lee::error::LeeError;

    fn try_from(value: PrivacyPreservingTransaction) -> Result<Self, Self::Error> {
        let PrivacyPreservingTransaction {
            hash: _,
            message,
            witness_set,
        } = value;

        Ok(Self::new(message.try_into()?, witness_set.try_into()?))
    }
}

impl From<common::transaction::LeeTransaction> for Transaction {
    fn from(value: common::transaction::LeeTransaction) -> Self {
        match value {
            common::transaction::LeeTransaction::Public(tx) => Self::Public(tx.into()),
            common::transaction::LeeTransaction::PrivacyPreserving(tx) => {
                Self::PrivacyPreserving(tx.into())
            }
        }
    }
}

impl TryFrom<Transaction> for common::transaction::LeeTransaction {
    type Error = lee::error::LeeError;

    fn try_from(value: Transaction) -> Result<Self, Self::Error> {
        match value {
            Transaction::Public(tx) => Ok(Self::Public(tx.try_into()?)),
            Transaction::PrivacyPreserving(tx) => Ok(Self::PrivacyPreserving(tx.try_into()?)),
        }
    }
}

// ============================================================================
// Block conversions
// ============================================================================

impl From<common::block::BlockHeader> for BlockHeader {
    fn from(value: common::block::BlockHeader) -> Self {
        let common::block::BlockHeader {
            block_id,
            prev_block_hash,
            hash,
            timestamp,
            producer,
            signature,
        } = value;
        Self {
            block_id,
            prev_block_hash: prev_block_hash.into(),
            hash: hash.into(),
            timestamp,
            producer: producer.into(),
            signature: signature.into(),
        }
    }
}

impl TryFrom<BlockHeader> for common::block::BlockHeader {
    type Error = lee::error::LeeError;

    fn try_from(value: BlockHeader) -> Result<Self, Self::Error> {
        let BlockHeader {
            block_id,
            prev_block_hash,
            hash,
            timestamp,
            producer,
            signature,
        } = value;
        Ok(Self {
            block_id,
            prev_block_hash: prev_block_hash.into(),
            hash: hash.into(),
            timestamp,
            producer: producer.try_into()?,
            signature: signature.into(),
        })
    }
}

impl From<common::block::BlockBody> for BlockBody {
    fn from(value: common::block::BlockBody) -> Self {
        let common::block::BlockBody { transactions } = value;

        let transactions = transactions
            .into_iter()
            .map(|tx| match tx {
                common::transaction::LeeTransaction::Public(tx) => Transaction::Public(tx.into()),
                common::transaction::LeeTransaction::PrivacyPreserving(tx) => {
                    Transaction::PrivacyPreserving(tx.into())
                }
            })
            .collect();

        Self { transactions }
    }
}

impl TryFrom<BlockBody> for common::block::BlockBody {
    type Error = lee::error::LeeError;

    fn try_from(value: BlockBody) -> Result<Self, Self::Error> {
        let BlockBody { transactions } = value;

        let transactions = transactions
            .into_iter()
            .map(|tx| {
                let lee_tx: common::transaction::LeeTransaction = tx.try_into()?;
                Ok::<_, lee::error::LeeError>(lee_tx)
            })
            .collect::<Result<Vec<_>, _>>()?;

        Ok(Self { transactions })
    }
}

impl From<common::block::Block> for Block {
    fn from(value: common::block::Block) -> Self {
        let common::block::Block {
            header,
            body,
            bedrock_status,
        } = value;

        Self {
            header: header.into(),
            body: body.into(),
            bedrock_status: bedrock_status.into(),
        }
    }
}

impl TryFrom<Block> for common::block::Block {
    type Error = lee::error::LeeError;

    fn try_from(value: Block) -> Result<Self, Self::Error> {
        let Block {
            header,
            body,
            bedrock_status,
        } = value;

        Ok(Self {
            header: header.try_into()?,
            body: body.try_into()?,
            bedrock_status: bedrock_status.into(),
        })
    }
}

impl From<common::block::BedrockStatus> for BedrockStatus {
    fn from(value: common::block::BedrockStatus) -> Self {
        match value {
            common::block::BedrockStatus::Pending => Self::Pending,
            common::block::BedrockStatus::Safe => Self::Safe,
            common::block::BedrockStatus::Finalized => Self::Finalized,
        }
    }
}

impl From<BedrockStatus> for common::block::BedrockStatus {
    fn from(value: BedrockStatus) -> Self {
        match value {
            BedrockStatus::Pending => Self::Pending,
            BedrockStatus::Safe => Self::Safe,
            BedrockStatus::Finalized => Self::Finalized,
        }
    }
}

impl From<common::HashType> for HashType {
    fn from(value: common::HashType) -> Self {
        Self(value.0)
    }
}

impl From<HashType> for common::HashType {
    fn from(value: HashType) -> Self {
        Self(value.0)
    }
}

// ============================================================================
// ValidityWindow conversions
// ============================================================================

impl From<lee_core::program::ValidityWindow<u64>> for ValidityWindow {
    fn from(value: lee_core::program::ValidityWindow<u64>) -> Self {
        Self((value.start(), value.end()))
    }
}

impl TryFrom<ValidityWindow> for lee_core::program::ValidityWindow<u64> {
    type Error = lee_core::program::InvalidWindow;

    fn try_from(value: ValidityWindow) -> Result<Self, Self::Error> {
        value.0.try_into()
    }
}

// ============================================================================
// Indexer status conversions
// ============================================================================

impl From<indexer_core::status::IndexerSyncState> for IndexerSyncState {
    fn from(value: indexer_core::status::IndexerSyncState) -> Self {
        // `Unknown` is a decode-side fallback for clients only; converting
        // from the core enum is exhaustive and never produces it.
        match value {
            indexer_core::status::IndexerSyncState::Starting => Self::Starting,
            indexer_core::status::IndexerSyncState::Syncing => Self::Syncing,
            indexer_core::status::IndexerSyncState::CaughtUp => Self::CaughtUp,
            indexer_core::status::IndexerSyncState::Error => Self::Error,
            indexer_core::status::IndexerSyncState::Stalled => Self::Stalled,
            indexer_core::status::IndexerSyncState::Halted => Self::Halted,
        }
    }
}

impl From<indexer_core::status::CrossZoneHalt> for CrossZoneHalt {
    fn from(value: indexer_core::status::CrossZoneHalt) -> Self {
        let indexer_core::status::CrossZoneHalt {
            block_id,
            block_hash,
            src_zone,
            src_block_id,
            src_tx_index,
            verdict,
        } = value;

        Self {
            block_id,
            block_hash: block_hash.into(),
            src_zone,
            src_block_id,
            src_tx_index,
            verdict,
        }
    }
}

impl From<indexer_core::status::PeerHealth> for PeerHealth {
    fn from(value: indexer_core::status::PeerHealth) -> Self {
        match value {
            indexer_core::status::PeerHealth::Live => Self::Live,
            indexer_core::status::PeerHealth::Lagging => Self::Lagging,
            indexer_core::status::PeerHealth::Holed => Self::Holed,
            indexer_core::status::PeerHealth::Suspended => Self::Suspended,
            indexer_core::status::PeerHealth::Halted => Self::Halted,
        }
    }
}

impl From<indexer_core::status::PeerStatus> for PeerStatus {
    fn from(value: indexer_core::status::PeerStatus) -> Self {
        let indexer_core::status::PeerStatus {
            zone,
            verified_tip_block_id,
            cursor_slot,
            stuck_slot_attempts,
            health,
        } = value;

        Self {
            zone,
            verified_tip_block_id,
            cursor_slot,
            stuck_slot_attempts,
            health: health.into(),
        }
    }
}

impl From<indexer_core::BlockIngestError> for BlockIngestError {
    fn from(value: indexer_core::BlockIngestError) -> Self {
        match value {
            indexer_core::BlockIngestError::Deserialize(msg) => Self::Deserialize(msg),
            indexer_core::BlockIngestError::UnexpectedBlockId { expected, got } => {
                Self::UnexpectedBlockId { expected, got }
            }
            indexer_core::BlockIngestError::BrokenChainLink {
                expected_prev,
                got_prev,
            } => Self::BrokenChainLink {
                expected_prev: expected_prev.into(),
                got_prev: got_prev.into(),
            },
            indexer_core::BlockIngestError::HashMismatch { computed, header } => {
                Self::HashMismatch {
                    computed: computed.into(),
                    header: header.into(),
                }
            }
            indexer_core::BlockIngestError::EmptyBlock => Self::EmptyBlock,
            indexer_core::BlockIngestError::InvalidClockTransaction => {
                Self::InvalidClockTransaction
            }
            indexer_core::BlockIngestError::InvalidFeeTransaction => Self::InvalidFeeTransaction,
            indexer_core::BlockIngestError::InvalidRewardTarget { reason } => {
                Self::InvalidRewardTarget { reason }
            }
            indexer_core::BlockIngestError::InvalidProducerSignature => {
                Self::InvalidProducerSignature
            }
            indexer_core::BlockIngestError::InvalidFeeClass { tx_index, reason } => {
                Self::InvalidFeeClass { tx_index, reason }
            }
            indexer_core::BlockIngestError::MissingFeeDeclaration { tx_index } => {
                Self::MissingFeeDeclaration { tx_index }
            }
            indexer_core::BlockIngestError::GasCapExceeded { tx_index, reason } => {
                Self::GasCapExceeded { tx_index, reason }
            }
            indexer_core::BlockIngestError::RestrictedAccountModification { tx_index, reason } => {
                Self::RestrictedAccountModification { tx_index, reason }
            }
            indexer_core::BlockIngestError::NonPublicGenesisTransaction => {
                Self::NonPublicGenesisTransaction
            }
            indexer_core::BlockIngestError::StateTransition { tx_index, reason } => {
                Self::StateTransition { tx_index, reason }
            }
        }
    }
}

impl From<indexer_core::StallReason> for StallReason {
    fn from(value: indexer_core::StallReason) -> Self {
        let indexer_core::StallReason {
            block_id,
            block_hash,
            prev_block_hash,
            l1_slot,
            error,
            first_seen,
            orphans_since,
        } = value;

        Self {
            block_id,
            block_hash: block_hash.map(Into::into),
            prev_block_hash: prev_block_hash.map(Into::into),
            l1_slot: l1_slot.into_inner(),
            error: error.into(),
            first_seen,
            orphans_since,
        }
    }
}

impl From<indexer_core::status::IndexerStatus> for IndexerStatus {
    fn from(value: indexer_core::status::IndexerStatus) -> Self {
        let indexer_core::status::IndexerStatus {
            sync,
            indexed_block_id,
            stall_reason,
            cross_zone_halt,
            cross_zone_peers,
        } = value;

        Self {
            state: sync.state.into(),
            last_error: sync.last_error,
            indexed_block_id,
            stall_reason: stall_reason.map(Into::into),
            cross_zone_halt: cross_zone_halt.map(Into::into),
            cross_zone_peers: cross_zone_peers.into_iter().map(Into::into).collect(),
        }
    }
}

// ============================================================================
// Event-related conversions
// ============================================================================

impl From<[u8; 8]> for Selector {
    fn from(value: [u8; 8]) -> Self {
        Self(value)
    }
}

#[expect(
    clippy::multiple_inherent_impl,
    reason = "We prefer to group methods by functionality rather than by type for conversions"
)]
impl EventRecord {
    // Not `From`: the orphan rule forbids implementing a foreign trait for `Vec<EventRecord>`.
    #[must_use]
    pub fn from_tx_events(block_id: BlockId, group: common::transaction::TxEvents) -> Vec<Self> {
        let common::transaction::TxEvents {
            tx_index,
            tx_hash,
            events,
        } = group;
        events
            .into_iter()
            .map(|event| Self {
                block_id,
                tx_index,
                tx_hash: tx_hash.into(),
                program_account_id: event.account_id.into(),
                selector: event.event.selector.into(),
                data: event.event.data,
            })
            .collect()
    }
}

fn nonce_entries(nonces: BTreeMap<lee::AccountId, Nonce>) -> Vec<(AccountId, u128)> {
    nonces
        .into_iter()
        .map(|(account_id, nonce)| (account_id.into(), nonce.0))
        .collect()
}

fn nonce_map(
    entries: Vec<(AccountId, u128)>,
) -> Result<BTreeMap<lee::AccountId, Nonce>, lee::error::LeeError> {
    Ok(lee::nonce_map(entries.into_iter().map(
        |(account_id, nonce)| (account_id.into(), Nonce(nonce)),
    ))?)
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use super::*;

    #[test]
    fn a_nested_account_round_trips_through_the_indexer_mirror() {
        let program = lee_core::account::AccountId::new([3; 32]);
        let account = lee_core::account::Account {
            nonce: lee_core::account::Nonce(u128::MAX),
            data: lee_core::account::Account::funded(u128::MAX)
                .data
                .with_actor_state(program, b"record".to_vec().into()),
        };

        let mirrored = Account::from(account.clone());
        let json = serde_json::to_string(&mirrored).unwrap();
        let restored: Account = serde_json::from_str(&json).unwrap();

        assert_eq!(restored.nonce, u128::MAX);
        assert_eq!(restored.data.balance(), Some(u128::MAX));
        assert_eq!(lee_core::account::Account::from(restored), account);
    }

    #[test]
    fn from_tx_events_copies_block_and_tx_context_onto_every_record() {
        let event = |selector: u8| lee_core::program::TransactionEvent {
            account_id: lee_core::account::AccountId::from_builtin_program([7_u32; 8]),
            event: lee_core::program::ProgramEvent {
                selector: [selector; 8],
                data: vec![selector; 2],
            },
        };
        let group = common::transaction::TxEvents {
            tx_index: 4,
            tx_hash: common::HashType([9_u8; 32]),
            events: vec![event(1), event(2), event(3)],
        };

        let records = EventRecord::from_tx_events(77, group);

        assert_eq!(records.len(), 3);
        assert!(records.iter().all(|r| r.block_id == 77 && r.tx_index == 4));
        let expected_program_account_id: AccountId =
            lee_core::account::AccountId::from_builtin_program([7; 8]).into();
        assert!(records.iter().all(|r| r.tx_hash == HashType([9_u8; 32])
            && r.program_account_id == expected_program_account_id));
        assert_eq!(records[1].selector, Selector([2; 8]));
        assert_eq!(records[2].data, vec![3, 3]);
    }

    /// A charged public transaction's fee declaration must survive the
    /// lee -> protocol -> lee round trip, or the transaction read back over the
    /// protocol recomputes to a different hash than the one on chain.
    #[test]
    fn public_fee_declaration_survives_roundtrip() {
        let signer = lee::PrivateKey::try_new([1_u8; 32]).expect("valid key");
        let signer_id = lee::AccountId::from(&lee::PublicKey::new_from_private_key(&signer));

        let fee = lee::FeeDeclaration::new(signer_id, 2_000_000, 0, u128::MAX >> 1);
        let to = lee::Actor::new(signer_id, lee::AccountId::new([7; 32]));
        let message = lee::public_transaction::Message::try_new_with_fees(
            to,
            vec![to],
            BTreeMap::from([(signer_id, 0_u128.into())]),
            0_u32,
            fee,
        )
        .expect("message builds");
        let witness_set = lee::public_transaction::WitnessSet::for_message(&message, &[&signer]);
        let tx = lee::PublicTransaction::new(message, witness_set);
        let original_hash = tx.hash();
        assert_eq!(tx.message().execution.fee, Some(fee));

        let protocol_tx: PublicTransaction = tx.into();
        let restored: lee::PublicTransaction = protocol_tx.try_into().expect("converts back");

        assert_eq!(
            restored.message().execution.fee,
            Some(fee),
            "the fee declaration must survive the round trip",
        );
        assert_eq!(
            restored.hash(),
            original_hash,
            "a dropped fee declaration would change the recomputed hash",
        );
    }

    /// A fee-exempt public transaction round-trips with `fee: None`.
    #[test]
    fn public_exempt_message_survives_roundtrip() {
        let signer = lee::PrivateKey::try_new([1_u8; 32]).expect("valid key");
        let signer_id = lee::AccountId::from(&lee::PublicKey::new_from_private_key(&signer));

        let to = lee::Actor::new(signer_id, lee::AccountId::new([7; 32]));
        let message = lee::public_transaction::Message::try_new(
            to,
            vec![to],
            BTreeMap::from([(signer_id, 0_u128.into())]),
            0_u32,
        )
        .expect("message builds");
        let witness_set = lee::public_transaction::WitnessSet::for_message(&message, &[&signer]);
        let tx = lee::PublicTransaction::new(message, witness_set);
        let original_hash = tx.hash();

        let protocol_tx: PublicTransaction = tx.into();
        let restored: lee::PublicTransaction = protocol_tx.try_into().expect("converts back");

        assert_eq!(restored.message().execution.fee, None);
        assert_eq!(restored.hash(), original_hash);
    }

    fn account_id(tag: u8) -> lee_core::account::AccountId {
        lee_core::account::AccountId::new([tag; 32])
    }

    fn actor(account_tag: u8, program_tag: u8) -> lee_core::account::Actor {
        lee_core::account::Actor::new(account_id(account_tag), account_id(program_tag))
    }

    fn admission_evidence() -> Vec<lee::PublicAccountEvidence> {
        let signer = lee::PrivateKey::try_new([1; 32]).expect("valid key");
        vec![
            lee::PublicAccountEvidence::Key(lee::PublicKey::new_from_private_key(&signer)),
            lee::PublicAccountEvidence::Pda {
                program: account_id(2),
                seed: lee_core::program::PdaSeed::new([3; 32]),
            },
        ]
    }

    #[test]
    fn a_public_message_with_admission_evidence_round_trips_through_the_mirror() {
        let message = lee::public_transaction::Message::new(
            actor(3, 4),
            vec![12],
            vec![actor(5, 6)],
            BTreeMap::from([(account_id(13), lee_core::account::Nonce(7))]),
            Some(lee::FeeDeclaration::new(account_id(8), 9, 10, 11)),
            admission_evidence(),
        );

        let mirrored = PublicMessage::from(message.clone());
        let json = serde_json::to_string(&mirrored).unwrap();
        let restored: PublicMessage = serde_json::from_str(&json).unwrap();

        assert_eq!(
            lee::public_transaction::Message::try_from(restored).unwrap(),
            message
        );
    }

    #[test]
    fn a_public_message_repeating_a_signer_nonce_does_not_convert() {
        let mut mirrored = PublicMessage::from(lee::public_transaction::Message::new(
            actor(1, 2),
            vec![3],
            vec![actor(1, 2)],
            BTreeMap::from([(account_id(1), lee_core::account::Nonce(4))]),
            None,
            Vec::new(),
        ));
        let (repeated, _) = mirrored.nonces[0];
        mirrored.nonces.push((repeated, 5));

        assert!(lee::public_transaction::Message::try_from(mirrored).is_err());
    }

    #[test]
    fn a_private_message_with_a_public_root_round_trips_through_the_mirror() {
        // A repeated send to one actor, and not a palindrome: a set would collapse the
        // sequence and a reversal would show, and execution replays them in emission order.
        let repeated = lee_core::execution_state::Delivery {
            envelope: lee_core::program::MessageEnvelope {
                from: actor(3, 53),
                to: actor(4, 5),
                message: vec![6],
            },
            inherited_authorizations: BTreeSet::new(),
            inherits_entry_authorizations: true,
            pda_seeds: BTreeSet::new(),
        };
        let message = lee::privacy_preserving_transaction::message::Message {
            context: lee_core::execution_state::PublicExecutionContext {
                cast_promotions: BTreeSet::from([27, 28]),
                ..lee_core::execution_state::PublicExecutionContext::default()
            },
            execution: lee_core::ProvenExecution {
                boundary: vec![
                    lee_core::execution_state::BoundaryStep::PrivateToPublic(repeated.clone()),
                    lee_core::execution_state::BoundaryStep::PrivateToPublic(
                        lee_core::execution_state::Delivery {
                            envelope: lee_core::program::MessageEnvelope {
                                from: actor(11, 61),
                                to: actor(8, 9),
                                message: vec![10],
                            },
                            inherited_authorizations: BTreeSet::from([account_id(14)]),
                            inherits_entry_authorizations: true,
                            pda_seeds: BTreeSet::from([lee_core::program::PdaSeed::new([15; 32])]),
                        },
                    ),
                    lee_core::execution_state::BoundaryStep::PrivateToPublic(
                        lee_core::execution_state::Delivery {
                            envelope: lee_core::program::MessageEnvelope {
                                from: actor(40, 90),
                                to: actor(41, 42),
                                message: vec![43],
                            },
                            inherited_authorizations: BTreeSet::new(),
                            inherits_entry_authorizations: true,
                            pda_seeds: BTreeSet::new(),
                        },
                    ),
                    lee_core::execution_state::BoundaryStep::PrivateToPublic(repeated),
                    lee_core::execution_state::BoundaryStep::PublicToPrivate(
                        lee_core::execution_state::Delivery {
                            envelope: lee_core::program::MessageEnvelope {
                                from: actor(16, 17),
                                to: actor(18, 19),
                                message: vec![20],
                            },
                            inherited_authorizations: BTreeSet::new(),
                            inherits_entry_authorizations: false,
                            pda_seeds: BTreeSet::new(),
                        },
                    ),
                    lee_core::execution_state::BoundaryStep::EndPrivateSubtree,
                    lee_core::execution_state::BoundaryStep::EndPublicSubtree,
                ],
                casts: vec![
                    lee_core::SealedCast {
                        commitment: lee_core::Commitment::from_byte_array([22; 32]),
                        note: lee_core::EncryptedNote {
                            epk: lee_core::EphemeralPublicKey(vec![23; 2]),
                            ciphertext: lee_core::encryption::Ciphertext::from_inner(vec![24; 3]),
                        },
                    };
                    2
                ],
                recovery_bindings: vec![],
                public_root: Some(lee_core::RootCall {
                    to: lee_core::account::Actor::new(
                        lee_core::account::AccountId::new([25; 32]),
                        lee_core::account::AccountId::new([26; 32]),
                    ),
                    message: vec![27; 2],
                }),
                private_actions: vec![],
                validity: lee_core::program::ValidityWindows::new_unbounded(),
                program_image_claims: vec![],
            },
            nonces: BTreeMap::new(),
            admission_evidence: admission_evidence(),
        };

        let mirrored = PrivacyPreservingMessage::from(message.clone());
        let json = serde_json::to_string(&mirrored).unwrap();
        let restored: PrivacyPreservingMessage = serde_json::from_str(&json).unwrap();

        assert_eq!(
            lee::privacy_preserving_transaction::message::Message::try_from(restored).unwrap(),
            message
        );
    }

    #[test]
    fn a_sealed_cast_round_trips_through_the_mirror() {
        let cast = lee_core::SealedCast {
            commitment: lee_core::Commitment::from_byte_array([0; 32]),
            note: lee_core::EncryptedNote {
                epk: lee_core::EphemeralPublicKey(vec![1; 2]),
                ciphertext: lee_core::encryption::Ciphertext::from_inner(vec![2; 3]),
            },
        };

        let mirrored = SealedCast::from(cast.clone());
        let json = serde_json::to_string(&mirrored).unwrap();
        let restored: SealedCast = serde_json::from_str(&json).unwrap();

        assert_eq!(lee_core::SealedCast::from(restored), cast);
    }
}
