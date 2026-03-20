//! Conversions between `indexer_service_protocol` types and `nssa/nssa_core` types.

use nssa_core::account::Nonce;

use crate::{
    Account, AccountId, BedrockStatus, Block, BlockBody, BlockHeader, Ciphertext, Commitment,
    CommitmentSetDigest, Data, EncryptedAccountData, EphemeralPublicKey, HashType, MantleMsgId,
    Nullifier, PrivacyPreservingMessage, PrivacyPreservingTransaction, ProgramDeploymentMessage,
    ProgramDeploymentTransaction, ProgramId, Proof, PublicKey, PublicMessage, PublicTransaction,
    Signature, Transaction, WitnessSet,
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

impl From<nssa_core::account::AccountId> for AccountId {
    fn from(value: nssa_core::account::AccountId) -> Self {
        Self {
            value: value.into_value(),
        }
    }
}

impl From<AccountId> for nssa_core::account::AccountId {
    fn from(value: AccountId) -> Self {
        let AccountId { value } = value;
        Self::new(value)
    }
}

impl From<nssa_core::account::Account> for Account {
    fn from(value: nssa_core::account::Account) -> Self {
        let nssa_core::account::Account {
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

impl TryFrom<Account> for nssa_core::account::Account {
    type Error = nssa_core::account::data::DataTooBigError;

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

impl From<nssa_core::account::Data> for Data {
    fn from(value: nssa_core::account::Data) -> Self {
        Self(value.into_inner())
    }
}

impl TryFrom<Data> for nssa_core::account::Data {
    type Error = nssa_core::account::data::DataTooBigError;

    fn try_from(value: Data) -> Result<Self, Self::Error> {
        Self::try_from(value.0)
    }
}

// ============================================================================
// Commitment and Nullifier conversions
// ============================================================================

impl From<nssa_core::Commitment> for Commitment {
    fn from(value: nssa_core::Commitment) -> Self {
        Self(value.to_byte_array())
    }
}

impl From<Commitment> for nssa_core::Commitment {
    fn from(value: Commitment) -> Self {
        Self::from_byte_array(value.0)
    }
}

impl From<nssa_core::Nullifier> for Nullifier {
    fn from(value: nssa_core::Nullifier) -> Self {
        Self(value.to_byte_array())
    }
}

impl From<Nullifier> for nssa_core::Nullifier {
    fn from(value: Nullifier) -> Self {
        Self::from_byte_array(value.0)
    }
}

impl From<nssa_core::CommitmentSetDigest> for CommitmentSetDigest {
    fn from(value: nssa_core::CommitmentSetDigest) -> Self {
        Self(value)
    }
}

impl From<CommitmentSetDigest> for nssa_core::CommitmentSetDigest {
    fn from(value: CommitmentSetDigest) -> Self {
        value.0
    }
}

// ============================================================================
// Encryption-related conversions
// ============================================================================

impl From<nssa_core::encryption::Ciphertext> for Ciphertext {
    fn from(value: nssa_core::encryption::Ciphertext) -> Self {
        Self(value.into_inner())
    }
}

impl From<Ciphertext> for nssa_core::encryption::Ciphertext {
    fn from(value: Ciphertext) -> Self {
        Self::from_inner(value.0)
    }
}

impl From<nssa_core::encryption::EphemeralPublicKey> for EphemeralPublicKey {
    fn from(value: nssa_core::encryption::EphemeralPublicKey) -> Self {
        Self(value.0)
    }
}

impl From<EphemeralPublicKey> for nssa_core::encryption::EphemeralPublicKey {
    fn from(value: EphemeralPublicKey) -> Self {
        Self(value.0)
    }
}

// ============================================================================
// Signature and PublicKey conversions
// ============================================================================

impl From<nssa::Signature> for Signature {
    fn from(value: nssa::Signature) -> Self {
        let nssa::Signature { value } = value;
        Self(value)
    }
}

impl From<Signature> for nssa::Signature {
    fn from(value: Signature) -> Self {
        let Signature(sig_value) = value;
        Self { value: sig_value }
    }
}

impl From<nssa::PublicKey> for PublicKey {
    fn from(value: nssa::PublicKey) -> Self {
        Self(*value.value())
    }
}

impl TryFrom<PublicKey> for nssa::PublicKey {
    type Error = nssa::error::NssaError;

    fn try_from(value: PublicKey) -> Result<Self, Self::Error> {
        Self::try_new(value.0)
    }
}

// ============================================================================
// Proof conversions
// ============================================================================

impl From<nssa::privacy_preserving_transaction::circuit::Proof> for Proof {
    fn from(value: nssa::privacy_preserving_transaction::circuit::Proof) -> Self {
        Self(value.into_inner())
    }
}

impl From<Proof> for nssa::privacy_preserving_transaction::circuit::Proof {
    fn from(value: Proof) -> Self {
        Self::from_inner(value.0)
    }
}

// ============================================================================
// EncryptedAccountData conversions
// ============================================================================

impl From<nssa::privacy_preserving_transaction::message::EncryptedAccountData>
    for EncryptedAccountData
{
    fn from(value: nssa::privacy_preserving_transaction::message::EncryptedAccountData) -> Self {
        Self {
            ciphertext: value.ciphertext.into(),
            epk: value.epk.into(),
            view_tag: value.view_tag,
        }
    }
}

impl From<EncryptedAccountData>
    for nssa::privacy_preserving_transaction::message::EncryptedAccountData
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

impl From<nssa::public_transaction::Message> for PublicMessage {
    fn from(value: nssa::public_transaction::Message) -> Self {
        let nssa::public_transaction::Message {
            program_id,
            account_ids,
            nonces,
            instruction_data,
        } = value;
        Self {
            program_id: program_id.into(),
            account_ids: account_ids.into_iter().map(Into::into).collect(),
            nonces: nonces.iter().map(|x| x.0).collect(),
            instruction_data,
        }
    }
}

impl From<PublicMessage> for nssa::public_transaction::Message {
    fn from(value: PublicMessage) -> Self {
        let PublicMessage {
            program_id,
            account_ids,
            nonces,
            instruction_data,
        } = value;
        Self::new_preserialized(
            program_id.into(),
            account_ids.into_iter().map(Into::into).collect(),
            nonces
                .iter()
                .map(|x| nssa_core::account::Nonce(*x))
                .collect(),
            instruction_data,
        )
    }
}

impl From<nssa::privacy_preserving_transaction::message::Message> for PrivacyPreservingMessage {
    fn from(value: nssa::privacy_preserving_transaction::message::Message) -> Self {
        let nssa::privacy_preserving_transaction::message::Message {
            public_account_ids,
            nonces,
            public_post_states,
            encrypted_private_post_states,
            new_commitments,
            new_nullifiers,
        } = value;
        Self {
            public_account_ids: public_account_ids.into_iter().map(Into::into).collect(),
            nonces: nonces.iter().map(|x| x.0).collect(),
            public_post_states: public_post_states.into_iter().map(Into::into).collect(),
            encrypted_private_post_states: encrypted_private_post_states
                .into_iter()
                .map(Into::into)
                .collect(),
            new_commitments: new_commitments.into_iter().map(Into::into).collect(),
            new_nullifiers: new_nullifiers
                .into_iter()
                .map(|(n, d)| (n.into(), d.into()))
                .collect(),
        }
    }
}

impl TryFrom<PrivacyPreservingMessage> for nssa::privacy_preserving_transaction::message::Message {
    type Error = nssa_core::account::data::DataTooBigError;

    fn try_from(value: PrivacyPreservingMessage) -> Result<Self, Self::Error> {
        let PrivacyPreservingMessage {
            public_account_ids,
            nonces,
            public_post_states,
            encrypted_private_post_states,
            new_commitments,
            new_nullifiers,
        } = value;
        Ok(Self {
            public_account_ids: public_account_ids.into_iter().map(Into::into).collect(),
            nonces: nonces
                .iter()
                .map(|x| nssa_core::account::Nonce(*x))
                .collect(),
            public_post_states: public_post_states
                .into_iter()
                .map(TryInto::try_into)
                .collect::<Result<Vec<_>, _>>()?,
            encrypted_private_post_states: encrypted_private_post_states
                .into_iter()
                .map(Into::into)
                .collect(),
            new_commitments: new_commitments.into_iter().map(Into::into).collect(),
            new_nullifiers: new_nullifiers
                .into_iter()
                .map(|(n, d)| (n.into(), d.into()))
                .collect(),
        })
    }
}

impl From<nssa::program_deployment_transaction::Message> for ProgramDeploymentMessage {
    fn from(value: nssa::program_deployment_transaction::Message) -> Self {
        Self {
            bytecode: value.into_bytecode(),
        }
    }
}

impl From<ProgramDeploymentMessage> for nssa::program_deployment_transaction::Message {
    fn from(value: ProgramDeploymentMessage) -> Self {
        let ProgramDeploymentMessage { bytecode } = value;
        Self::new(bytecode)
    }
}

// ============================================================================
// WitnessSet conversions
// ============================================================================

impl From<nssa::public_transaction::WitnessSet> for WitnessSet {
    fn from(value: nssa::public_transaction::WitnessSet) -> Self {
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

impl From<nssa::privacy_preserving_transaction::witness_set::WitnessSet> for WitnessSet {
    fn from(value: nssa::privacy_preserving_transaction::witness_set::WitnessSet) -> Self {
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

impl TryFrom<WitnessSet> for nssa::privacy_preserving_transaction::witness_set::WitnessSet {
    type Error = nssa::error::NssaError;

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
                .ok_or_else(|| nssa::error::NssaError::InvalidInput("Missing proof".to_owned()))?,
        ))
    }
}

// ============================================================================
// Transaction conversions
// ============================================================================

impl From<nssa::PublicTransaction> for PublicTransaction {
    fn from(value: nssa::PublicTransaction) -> Self {
        let hash = HashType(value.hash());
        let nssa::PublicTransaction {
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

impl TryFrom<PublicTransaction> for nssa::PublicTransaction {
    type Error = nssa::error::NssaError;

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
            nssa::public_transaction::WitnessSet::from_raw_parts(
                signatures_and_public_keys
                    .into_iter()
                    .map(|(sig, pk)| Ok((sig.into(), pk.try_into()?)))
                    .collect::<Result<Vec<_>, Self::Error>>()?,
            ),
        ))
    }
}

impl From<nssa::PrivacyPreservingTransaction> for PrivacyPreservingTransaction {
    fn from(value: nssa::PrivacyPreservingTransaction) -> Self {
        let hash = HashType(value.hash());
        let nssa::PrivacyPreservingTransaction {
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

impl TryFrom<PrivacyPreservingTransaction> for nssa::PrivacyPreservingTransaction {
    type Error = nssa::error::NssaError;

    fn try_from(value: PrivacyPreservingTransaction) -> Result<Self, Self::Error> {
        let PrivacyPreservingTransaction {
            hash: _,
            message,
            witness_set,
        } = value;

        Ok(Self::new(
            message
                .try_into()
                .map_err(|err: nssa_core::account::data::DataTooBigError| {
                    nssa::error::NssaError::InvalidInput(err.to_string())
                })?,
            witness_set.try_into()?,
        ))
    }
}

impl From<nssa::ProgramDeploymentTransaction> for ProgramDeploymentTransaction {
    fn from(value: nssa::ProgramDeploymentTransaction) -> Self {
        let hash = HashType(value.hash());
        let nssa::ProgramDeploymentTransaction { message } = value;

        Self {
            hash,
            message: message.into(),
        }
    }
}

impl From<ProgramDeploymentTransaction> for nssa::ProgramDeploymentTransaction {
    fn from(value: ProgramDeploymentTransaction) -> Self {
        let ProgramDeploymentTransaction { hash: _, message } = value;
        Self::new(message.into())
    }
}

impl From<common::transaction::NSSATransaction> for Transaction {
    fn from(value: common::transaction::NSSATransaction) -> Self {
        match value {
            common::transaction::NSSATransaction::Public(tx) => Self::Public(tx.into()),
            common::transaction::NSSATransaction::PrivacyPreserving(tx) => {
                Self::PrivacyPreserving(tx.into())
            }
            common::transaction::NSSATransaction::ProgramDeployment(tx) => {
                Self::ProgramDeployment(tx.into())
            }
        }
    }
}

impl TryFrom<Transaction> for common::transaction::NSSATransaction {
    type Error = nssa::error::NssaError;

    fn try_from(value: Transaction) -> Result<Self, Self::Error> {
        match value {
            Transaction::Public(tx) => Ok(Self::Public(tx.try_into()?)),
            Transaction::PrivacyPreserving(tx) => Ok(Self::PrivacyPreserving(tx.try_into()?)),
            Transaction::ProgramDeployment(tx) => Ok(Self::ProgramDeployment(tx.into())),
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
            signature,
        } = value;
        Self {
            block_id,
            prev_block_hash: prev_block_hash.into(),
            hash: hash.into(),
            timestamp,
            signature: signature.into(),
        }
    }
}

impl TryFrom<BlockHeader> for common::block::BlockHeader {
    type Error = nssa::error::NssaError;

    fn try_from(value: BlockHeader) -> Result<Self, Self::Error> {
        let BlockHeader {
            block_id,
            prev_block_hash,
            hash,
            timestamp,
            signature,
        } = value;
        Ok(Self {
            block_id,
            prev_block_hash: prev_block_hash.into(),
            hash: hash.into(),
            timestamp,
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
                common::transaction::NSSATransaction::Public(tx) => Transaction::Public(tx.into()),
                common::transaction::NSSATransaction::PrivacyPreserving(tx) => {
                    Transaction::PrivacyPreserving(tx.into())
                }
                common::transaction::NSSATransaction::ProgramDeployment(tx) => {
                    Transaction::ProgramDeployment(tx.into())
                }
            })
            .collect();

        Self { transactions }
    }
}

impl TryFrom<BlockBody> for common::block::BlockBody {
    type Error = nssa::error::NssaError;

    fn try_from(value: BlockBody) -> Result<Self, Self::Error> {
        let BlockBody { transactions } = value;

        let transactions = transactions
            .into_iter()
            .map(|tx| {
                let nssa_tx: common::transaction::NSSATransaction = tx.try_into()?;
                Ok::<_, nssa::error::NssaError>(nssa_tx)
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
            bedrock_parent_id,
        } = value;

        Self {
            header: header.into(),
            body: body.into(),
            bedrock_status: bedrock_status.into(),
            bedrock_parent_id: MantleMsgId(bedrock_parent_id),
        }
    }
}

impl TryFrom<Block> for common::block::Block {
    type Error = nssa::error::NssaError;

    fn try_from(value: Block) -> Result<Self, Self::Error> {
        let Block {
            header,
            body,
            bedrock_status,
            bedrock_parent_id,
        } = value;

        Ok(Self {
            header: header.try_into()?,
            body: body.try_into()?,
            bedrock_status: bedrock_status.into(),
            bedrock_parent_id: bedrock_parent_id.0,
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
