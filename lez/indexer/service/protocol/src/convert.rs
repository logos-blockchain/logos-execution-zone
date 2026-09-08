//! Conversions between `indexer_service_protocol` types and `lee/lee_core` types.

use lee_core::account::Nonce;

use crate::{
    Account, AccountData, AccountId, BedrockStatus, Block, BlockBody, BlockHeader, BlockId,
    BlockIngestError, Ciphertext, Commitment, CommitmentSetDigest, CrossZoneHalt, Data,
    EncryptedAccountData, EphemeralPublicKey, EventRecord, FeeDeclaration, HashType, IndexerStatus,
    IndexerSyncState, Nullifier, PeerHealth, PeerStatus, PrivacyPreservingMessage,
    PrivacyPreservingTransaction, PrivateAction, ProgramId, ProgramShardSelector, Proof,
    PublicActionWithID, PublicKey, PublicMessage, PublicTransaction, Selector, Signature,
    StallReason, Transaction, ValidityWindow, WitnessSet,
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
        let lee_core::account::Account { nonce, data } = value;

        Self {
            nonce: nonce.0,
            data: data.into(),
        }
    }
}

impl TryFrom<Account> for lee_core::account::Account {
    type Error = lee_core::account::data::DataTooBigError;

    fn try_from(value: Account) -> Result<Self, Self::Error> {
        let Account { nonce, data } = value;

        Ok(Self {
            nonce: Nonce(nonce),
            data: data.try_into()?,
        })
    }
}

impl From<lee_core::account::AccountData> for AccountData {
    fn from(value: lee_core::account::AccountData) -> Self {
        let lee_core::account::AccountData { balance, shards } = value;

        Self {
            balance,
            shards: shards
                .into_iter()
                .map(|(program, data)| (program.into(), data.into()))
                .collect(),
        }
    }
}

impl TryFrom<AccountData> for lee_core::account::AccountData {
    type Error = lee_core::account::data::DataTooBigError;

    fn try_from(value: AccountData) -> Result<Self, Self::Error> {
        let AccountData { balance, shards } = value;

        Ok(Self {
            balance,
            shards: shards
                .into_iter()
                .map(|(program, data)| Ok((program.into(), data.try_into()?)))
                .collect::<Result<_, Self::Error>>()?,
        })
    }
}

impl From<lee_core::account::ProgramShardSelector> for ProgramShardSelector {
    fn from(value: lee_core::account::ProgramShardSelector) -> Self {
        let lee_core::account::ProgramShardSelector {
            account_id,
            program_account_id,
        } = value;

        Self {
            account_id: account_id.into(),
            program_account_id: program_account_id.map(Into::into),
        }
    }
}

impl From<ProgramShardSelector> for lee_core::account::ProgramShardSelector {
    fn from(value: ProgramShardSelector) -> Self {
        let ProgramShardSelector {
            account_id,
            program_account_id,
        } = value;

        Self {
            account_id: account_id.into(),
            program_account_id: program_account_id.map(Into::into),
        }
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
        let lee::public_transaction::Message {
            program_account_id,
            shard_selectors,
            nonces,
            instruction_data,
            fee,
        } = value;
        Self {
            program_id: ProgramId(program_account_id.into()),
            shard_selectors: shard_selectors.into_iter().map(Into::into).collect(),
            nonces: nonces.iter().map(|x| x.0).collect(),
            instruction_data,
            fee: fee.map(Into::into),
        }
    }
}

impl From<PublicMessage> for lee::public_transaction::Message {
    fn from(value: PublicMessage) -> Self {
        let PublicMessage {
            program_id,
            shard_selectors,
            nonces,
            instruction_data,
            fee,
        } = value;
        Self::new_preserialized(
            lee::AccountId::from(program_id.0),
            shard_selectors.into_iter().map(Into::into).collect(),
            nonces
                .iter()
                .map(|x| lee_core::account::Nonce(*x))
                .collect(),
            instruction_data,
            fee.map(Into::into),
        )
    }
}

impl From<lee::privacy_preserving_transaction::message::PublicActionWithID> for PublicActionWithID {
    fn from(value: lee::privacy_preserving_transaction::message::PublicActionWithID) -> Self {
        Self {
            account_id: value.account_id.into(),
            post: value.post.into(),
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
            // Not yet part of this wire protocol; see the `program_image_claims` field doc on
            // `lee::privacy_preserving_transaction::message::Message`. FFI/wallet plumbing for
            // address-flexible program dispatch is tracked separately.
            program_image_claims: _,
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
            post: value
                .post
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
            // Not yet part of this wire protocol; see the corresponding destructure above.
            // A privacy-preserving tx submitted through this protocol will fail proof
            // verification for any program not at its bijection address until this is wired.
            program_image_claims: Vec::new(),
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
            message.into(),
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
                program_id: ProgramId(event.account_id.into()),
                selector: event.event.selector.into(),
                data: event.event.data,
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_nested_account_round_trips_through_the_indexer_mirror() {
        let program = lee_core::account::AccountId::new([3; 32]);
        let account = lee_core::account::Account {
            nonce: lee_core::account::Nonce(u128::MAX),
            data: lee_core::account::AccountData {
                balance: u128::MAX,
                ..lee_core::account::AccountData::default()
            }
            .with_shard(program, b"record".to_vec().try_into().unwrap()),
        };

        let mirrored = Account::from(account.clone());
        let json = serde_json::to_string(&mirrored).unwrap();
        let restored: Account = serde_json::from_str(&json).unwrap();

        assert_eq!(restored.nonce, u128::MAX);
        assert_eq!(restored.data.balance, u128::MAX);
        assert_eq!(
            lee_core::account::Account::try_from(restored).unwrap(),
            account
        );
    }

    #[test]
    fn from_tx_events_copies_block_and_tx_context_onto_every_record() {
        let event = |selector: u8| lee_core::program::TransactionEvent {
            account_id: lee_core::account::AccountId::from([7_u32; 8]),
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
        assert!(
            records
                .iter()
                .all(|r| r.tx_hash == HashType([9_u8; 32]) && r.program_id == ProgramId([7; 8]))
        );
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
        let message = lee::public_transaction::Message::try_new_with_fees(
            [7_u32; 8].into(),
            vec![lee::ProgramShardSelector::balance_only(signer_id)],
            vec![0_u128.into()],
            0_u32,
            fee,
        )
        .expect("message builds");
        let witness_set = lee::public_transaction::WitnessSet::for_message(&message, &[&signer]);
        let tx = lee::PublicTransaction::new(message, witness_set);
        let original_hash = tx.hash();
        assert_eq!(tx.message().fee, Some(fee));

        let protocol_tx: PublicTransaction = tx.into();
        let restored: lee::PublicTransaction = protocol_tx.try_into().expect("converts back");

        assert_eq!(
            restored.message().fee,
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

        let message = lee::public_transaction::Message::try_new(
            [7_u32; 8].into(),
            vec![lee::ProgramShardSelector::balance_only(signer_id)],
            vec![0_u128.into()],
            0_u32,
        )
        .expect("message builds");
        let witness_set = lee::public_transaction::WitnessSet::for_message(&message, &[&signer]);
        let tx = lee::PublicTransaction::new(message, witness_set);
        let original_hash = tx.hash();

        let protocol_tx: PublicTransaction = tx.into();
        let restored: lee::PublicTransaction = protocol_tx.try_into().expect("converts back");

        assert_eq!(restored.message().fee, None);
        assert_eq!(restored.hash(), original_hash);
    }
}
