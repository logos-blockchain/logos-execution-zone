//! Conversions between `indexer_service_protocol` types and `lee/lee_core` types.

use lee_core::account::Nonce;

use crate::{
    Account, AccountId, BedrockStatus, Block, BlockBody, BlockHeader, BlockIngestError, Ciphertext,
    Commitment, CommitmentSetDigest, Data, EncryptedAccountData, EphemeralPublicKey, HashType,
    IndexerStatus, IndexerSyncState, Nullifier, PrivacyPreservingMessage,
    PrivacyPreservingTransaction, PrivateAction, ProgramDeploymentMessage,
    ProgramDeploymentTransaction, ProgramId, Proof, PublicActionWithID, PublicKey, PublicMessage,
    PublicTransaction, Signature, StallReason, Transaction, ValidityWindow, WitnessSet,
};

// ============================================================================
// Account-related conversions
// ============================================================================

impl From<[u32; 8]> for ProgramId {
    fn from(value: [u32; 8]) -> Self {
        Self(value)
    }
}

impl From<ProgramId> for [u32; 8] {
    fn from(value: ProgramId) -> Self {
        value.0
    }
}

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
        let lee_core::account::Account {
            program_owner,
            balance,
            data,
            nonce,
        } = value;

        Self {
            program_owner: program_owner.into(),
            balance,
            data: data.into(),
            nonce: nonce.0,
        }
    }
}

impl TryFrom<Account> for lee_core::account::Account {
    type Error = lee_core::account::data::DataTooBigError;

    fn try_from(value: Account) -> Result<Self, Self::Error> {
        let Account {
            program_owner,
            balance,
            data,
            nonce,
        } = value;

        Ok(Self {
            program_owner: program_owner.into(),
            balance,
            data: data.try_into()?,
            nonce: Nonce(nonce),
        })
    }
}

impl From<lee_core::account::Data> for Data {
    fn from(value: lee_core::account::Data) -> Self {
        Self(value.into_inner())
    }
}

impl TryFrom<Data> for lee_core::account::Data {
    type Error = lee_core::account::data::DataTooBigError;

    fn try_from(value: Data) -> Result<Self, Self::Error> {
        Self::try_from(value.0)
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
// EncryptedAccountData conversions
// ============================================================================

impl From<lee::privacy_preserving_transaction::message::EncryptedAccountData>
    for EncryptedAccountData
{
    fn from(value: lee::privacy_preserving_transaction::message::EncryptedAccountData) -> Self {
        Self {
            ciphertext: value.ciphertext.into(),
            epk: value.epk.into(),
            view_tag: value.view_tag,
        }
    }
}

impl From<EncryptedAccountData>
    for lee::privacy_preserving_transaction::message::EncryptedAccountData
{
    fn from(value: EncryptedAccountData) -> Self {
        Self {
            ciphertext: value.ciphertext.into(),
            epk: value.epk.into(),
            view_tag: value.view_tag,
        }
    }
}

// ============================================================================
// Transaction Message conversions
// ============================================================================

impl From<lee::public_transaction::Message> for PublicMessage {
    fn from(value: lee::public_transaction::Message) -> Self {
        let lee::public_transaction::Message {
            program_id,
            account_ids,
            nonces,
            instruction_data,
            payer,
            gas_limit,
            tip,
            max_fee,
        } = value;
        Self {
            program_id: program_id.into(),
            account_ids: account_ids.into_iter().map(Into::into).collect(),
            nonces: nonces.iter().map(|x| x.0).collect(),
            instruction_data,
            payer: payer.into(),
            gas_limit,
            tip,
            max_fee,
        }
    }
}

impl From<PublicMessage> for lee::public_transaction::Message {
    fn from(value: PublicMessage) -> Self {
        let PublicMessage {
            program_id,
            account_ids,
            nonces,
            instruction_data,
            payer,
            gas_limit,
            tip,
            max_fee,
        } = value;
        Self::new_preserialized(
            program_id.into(),
            account_ids.into_iter().map(Into::into).collect(),
            nonces
                .iter()
                .map(|x| lee_core::account::Nonce(*x))
                .collect(),
            instruction_data,
            lee::FeeFields::new(payer.into(), gas_limit, tip, max_fee),
        )
    }
}

impl From<lee::privacy_preserving_transaction::message::PublicActionWithID> for PublicActionWithID {
    fn from(value: lee::privacy_preserving_transaction::message::PublicActionWithID) -> Self {
        Self {
            account_id: value.account_id.into(),
            post_state: value.post_state.into(),
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

impl From<lee::privacy_preserving_transaction::message::Message> for PrivacyPreservingMessage {
    fn from(value: lee::privacy_preserving_transaction::message::Message) -> Self {
        let lee::privacy_preserving_transaction::message::Message {
            public_actions,
            nonces,
            private_actions,
            block_validity_window,
            timestamp_validity_window,
        } = value;
        Self {
            public_actions: public_actions.into_iter().map(Into::into).collect(),
            nonces: nonces.iter().map(|x| x.0).collect(),
            private_actions: private_actions.into_iter().map(Into::into).collect(),
            block_validity_window: block_validity_window.into(),
            timestamp_validity_window: timestamp_validity_window.into(),
        }
    }
}

impl TryFrom<PublicActionWithID>
    for lee::privacy_preserving_transaction::message::PublicActionWithID
{
    type Error = lee::error::LeeError;

    fn try_from(value: PublicActionWithID) -> Result<Self, Self::Error> {
        Ok(Self {
            account_id: value.account_id.into(),
            post_state: value
                .post_state
                .try_into()
                .map_err(|e| lee::error::LeeError::InvalidInput(format!("{e}")))?,
        })
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
            public_actions,
            nonces,
            private_actions,
            block_validity_window,
            timestamp_validity_window,
        } = value;

        let public_actions = public_actions
            .into_iter()
            .map(TryInto::try_into)
            .collect::<Result<Vec<_>, _>>()?;
        let private_actions = private_actions.into_iter().map(Into::into).collect();

        Ok(Self {
            public_actions,
            nonces: nonces
                .iter()
                .map(|x| lee_core::account::Nonce(*x))
                .collect(),
            private_actions,
            block_validity_window: block_validity_window
                .try_into()
                .map_err(|e| lee::error::LeeError::InvalidInput(format!("{e}")))?,
            timestamp_validity_window: timestamp_validity_window
                .try_into()
                .map_err(|e| lee::error::LeeError::InvalidInput(format!("{e}")))?,
        })
    }
}

impl From<lee::program_deployment_transaction::Message> for ProgramDeploymentMessage {
    fn from(value: lee::program_deployment_transaction::Message) -> Self {
        let lee::FeeFields {
            payer,
            gas_limit,
            tip,
            max_fee,
        } = value.fees();
        Self {
            bytecode: value.into_bytecode(),
            payer: payer.into(),
            gas_limit,
            tip,
            max_fee,
        }
    }
}

impl From<ProgramDeploymentMessage> for lee::program_deployment_transaction::Message {
    fn from(value: ProgramDeploymentMessage) -> Self {
        let ProgramDeploymentMessage {
            bytecode,
            payer,
            gas_limit,
            tip,
            max_fee,
        } = value;
        Self::new(
            bytecode,
            lee::FeeFields::new(payer.into(), gas_limit, tip, max_fee),
        )
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
            fee_witness: value
                .fee_witness()
                .map(|(sig, pk)| (sig.clone().into(), pk.clone().into())),
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
            fee_witness: None,
        }
    }
}

impl TryFrom<WitnessSet> for lee::privacy_preserving_transaction::witness_set::WitnessSet {
    type Error = lee::error::LeeError;

    fn try_from(value: WitnessSet) -> Result<Self, Self::Error> {
        let WitnessSet {
            signatures_and_public_keys,
            proof,
            fee_witness: _,
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

impl TryFrom<WitnessSet> for lee::public_transaction::WitnessSet {
    type Error = lee::error::LeeError;

    fn try_from(value: WitnessSet) -> Result<Self, Self::Error> {
        let WitnessSet {
            signatures_and_public_keys,
            proof: _,
            fee_witness,
        } = value;
        let convert = |(sig, pk): (Signature, PublicKey)| -> Result<_, Self::Error> {
            Ok((sig.into(), pk.try_into()?))
        };

        Ok(Self::from_parts(
            signatures_and_public_keys
                .into_iter()
                .map(convert)
                .collect::<Result<Vec<_>, Self::Error>>()?,
            fee_witness.map(convert).transpose()?,
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
        Ok(Self::new(message.into(), witness_set.try_into()?))
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

impl From<lee::ProgramDeploymentTransaction> for ProgramDeploymentTransaction {
    fn from(value: lee::ProgramDeploymentTransaction) -> Self {
        let hash = HashType(value.hash());
        let lee::ProgramDeploymentTransaction {
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

impl TryFrom<ProgramDeploymentTransaction> for lee::ProgramDeploymentTransaction {
    type Error = lee::error::LeeError;

    fn try_from(value: ProgramDeploymentTransaction) -> Result<Self, Self::Error> {
        let ProgramDeploymentTransaction {
            hash: _,
            message,
            witness_set,
        } = value;
        Ok(Self::new(message.into(), witness_set.try_into()?))
    }
}

impl From<common::transaction::LeeTransaction> for Transaction {
    fn from(value: common::transaction::LeeTransaction) -> Self {
        match value {
            common::transaction::LeeTransaction::Public(tx) => Self::Public(tx.into()),
            common::transaction::LeeTransaction::PrivacyPreserving(tx) => {
                Self::PrivacyPreserving(tx.into())
            }
            common::transaction::LeeTransaction::ProgramDeployment(tx) => {
                Self::ProgramDeployment(tx.into())
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
            Transaction::ProgramDeployment(tx) => Ok(Self::ProgramDeployment(tx.try_into()?)),
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
                common::transaction::LeeTransaction::ProgramDeployment(tx) => {
                    Transaction::ProgramDeployment(tx.into())
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
        match value {
            indexer_core::status::IndexerSyncState::Starting => Self::Starting,
            indexer_core::status::IndexerSyncState::Syncing => Self::Syncing,
            indexer_core::status::IndexerSyncState::CaughtUp => Self::CaughtUp,
            indexer_core::status::IndexerSyncState::Error => Self::Error,
            indexer_core::status::IndexerSyncState::Stalled => Self::Stalled,
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
            indexer_core::BlockIngestError::InvalidProducerSignature { producer } => {
                Self::InvalidProducerSignature {
                    producer: producer.into(),
                }
            }
            indexer_core::BlockIngestError::EmptyBlock => Self::EmptyBlock,
            indexer_core::BlockIngestError::InvalidClockTransaction => {
                Self::InvalidClockTransaction
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
        } = value;

        Self {
            state: sync.state.into(),
            last_error: sync.last_error,
            indexed_block_id,
            stall_reason: stall_reason.map(Into::into),
        }
    }
}
