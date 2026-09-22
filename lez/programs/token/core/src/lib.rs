//! This crate contains core data structures and utilities for the Token Program.

use borsh::{BorshDeserialize, BorshSerialize};
use lee_core::account::{AccountId, ShardData};
use serde::{Deserialize, Serialize};

/// Token Program Instruction.
///
/// All inputs select this program's shard. "Empty" and "initialized" refer to that shard.
#[derive(BorshSerialize, BorshDeserialize)]
pub enum Instruction {
    /// Transfer tokens from sender to recipient.
    ///
    /// Required accounts:
    /// - Sender's Token Holding account (initialized, authorized),
    /// - Recipient's Token Holding account (initialized or empty).
    Transfer {
        amount_to_transfer: u128,
        descriptor: TokenDescriptor,
    },

    /// Create a new fungible token definition without metadata.
    ///
    /// Required accounts:
    /// - Token Definition account (empty),
    /// - Token Holding account (empty).
    NewFungibleDefinition { name: String, total_supply: u128 },

    /// Create a new fungible or non-fungible token definition with metadata.
    ///
    /// Required accounts:
    /// - Token Definition account (empty),
    /// - Token Holding account (empty),
    /// - Token Metadata account (empty).
    NewDefinitionWithMetadata {
        new_definition: NewTokenDefinition,
        /// Boxed to avoid large enum variant size.
        metadata: Box<NewTokenMetadata>,
    },

    /// Initialize a token holding account for a given token definition.
    ///
    /// Required accounts:
    /// - Token Definition account (initialized),
    /// - Token Holding account,
    InitializeAccount { kind: TokenKind },

    /// Burn tokens from the holder's account.
    ///
    /// Required accounts:
    /// - Token Definition account (initialized),
    /// - Token Holding account (initialized, authorized).
    Burn {
        amount_to_burn: u128,
        kind: TokenKind,
    },

    /// Mint new tokens to the holder's account.
    ///
    /// Required accounts:
    /// - Token Definition account (initialized, authorized),
    /// - Token Holding account (initialized or empty).
    Mint { amount_to_mint: u128 },

    /// Print a new NFT from the master copy.
    ///
    /// Required accounts:
    /// - NFT Master Token Holding account (initialized, authorized),
    /// - NFT Printed Copy Token Holding account (empty).
    PrintNft { definition_id: AccountId },
}

#[derive(BorshSerialize, BorshDeserialize)]
pub enum NewTokenDefinition {
    Fungible {
        name: String,
        total_supply: u128,
    },
    NonFungible {
        name: String,
        printable_supply: u128,
    },
}

#[derive(Debug, PartialEq, Eq, Serialize, Deserialize, BorshSerialize, BorshDeserialize)]
pub enum TokenDefinition {
    Fungible {
        name: String,
        total_supply: u128,
        metadata_id: Option<AccountId>,
    },
    NonFungible {
        name: String,
        printable_supply: u128,
        metadata_id: AccountId,
    },
}

impl TryFrom<&ShardData> for TokenDefinition {
    type Error = std::io::Error;

    fn try_from(data: &ShardData) -> Result<Self, Self::Error> {
        Self::try_from_slice(data.as_ref())
    }
}

impl From<&TokenDefinition> for ShardData {
    fn from(definition: &TokenDefinition) -> Self {
        // Using size_of_val as size hint for Vec allocation
        let mut data = Vec::with_capacity(std::mem::size_of_val(definition));

        BorshSerialize::serialize(definition, &mut data)
            .expect("Serialization to Vec should not fail");

        Self::try_from(data).expect("Token definition encoded data should fit into ShardData")
    }
}

#[derive(Debug, PartialEq, Eq, Serialize, Deserialize, BorshSerialize, BorshDeserialize)]
pub enum TokenHolding {
    Fungible {
        definition_id: AccountId,
        balance: u128,
    },
    NftMaster {
        definition_id: AccountId,
        /// The amount of printed copies left - 1 (1 reserved for master copy itself).
        print_balance: u128,
    },
    NftPrintedCopy {
        definition_id: AccountId,
        /// Whether nft is owned by the holder.
        owned: bool,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct TokenDescriptor {
    pub definition_id: AccountId,
    pub kind: TokenKind,
}

impl TokenDescriptor {
    #[must_use]
    pub const fn zeroized(&self) -> TokenHolding {
        match self.kind {
            TokenKind::Fungible => TokenHolding::Fungible {
                definition_id: self.definition_id,
                balance: 0,
            },
            TokenKind::NftMaster => TokenHolding::NftMaster {
                definition_id: self.definition_id,
                print_balance: 0,
            },
            TokenKind::NftPrintedCopy => TokenHolding::NftPrintedCopy {
                definition_id: self.definition_id,
                owned: false,
            },
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub enum TokenKind {
    Fungible,
    NftMaster,
    NftPrintedCopy,
}

impl TokenKind {
    #[must_use]
    pub const fn from_definition(definition: &TokenDefinition) -> Self {
        match definition {
            TokenDefinition::Fungible { .. } => Self::Fungible,
            TokenDefinition::NonFungible { .. } => Self::NftPrintedCopy,
        }
    }
}

impl TokenHolding {
    #[must_use]
    pub const fn kind(&self) -> TokenKind {
        match self {
            Self::Fungible { .. } => TokenKind::Fungible,
            Self::NftMaster { .. } => TokenKind::NftMaster,
            Self::NftPrintedCopy { .. } => TokenKind::NftPrintedCopy,
        }
    }

    #[must_use]
    pub const fn definition_id(&self) -> AccountId {
        match self {
            Self::Fungible { definition_id, .. }
            | Self::NftMaster { definition_id, .. }
            | Self::NftPrintedCopy { definition_id, .. } => *definition_id,
        }
    }
}

impl TryFrom<&ShardData> for TokenHolding {
    type Error = std::io::Error;

    fn try_from(data: &ShardData) -> Result<Self, Self::Error> {
        Self::try_from_slice(data.as_ref())
    }
}

impl From<&TokenHolding> for ShardData {
    fn from(holding: &TokenHolding) -> Self {
        // Using size_of_val as size hint for Vec allocation
        let mut data = Vec::with_capacity(std::mem::size_of_val(holding));

        BorshSerialize::serialize(holding, &mut data)
            .expect("Serialization to Vec should not fail");

        Self::try_from(data).expect("Token holding encoded data should fit into ShardData")
    }
}

#[derive(Clone, BorshSerialize, BorshDeserialize)]
pub struct NewTokenMetadata {
    /// Metadata standard.
    pub standard: MetadataStandard,
    /// Pointer to off-chain metadata.
    pub uri: String,
    /// Creators of the token.
    pub creators: String,
}

#[derive(Debug, PartialEq, Eq, Serialize, Deserialize, BorshSerialize, BorshDeserialize)]
pub struct TokenMetadata {
    /// Token Definition account id.
    pub definition_id: AccountId,
    /// Metadata standard .
    pub standard: MetadataStandard,
    /// Pointer to off-chain metadata.
    pub uri: String,
    /// Creators of the token.
    pub creators: String,
    /// Block id of primary sale.
    pub primary_sale_date: u64,
}

/// Metadata standard defining the expected format of JSON located off-chain.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, BorshSerialize, BorshDeserialize)]
pub enum MetadataStandard {
    Simple,
    Expanded,
}

impl TryFrom<&ShardData> for TokenMetadata {
    type Error = std::io::Error;

    fn try_from(data: &ShardData) -> Result<Self, Self::Error> {
        Self::try_from_slice(data.as_ref())
    }
}

impl From<&TokenMetadata> for ShardData {
    fn from(metadata: &TokenMetadata) -> Self {
        // Using size_of_val as size hint for Vec allocation
        let mut data = Vec::with_capacity(std::mem::size_of_val(metadata));

        BorshSerialize::serialize(metadata, &mut data)
            .expect("Serialization to Vec should not fail");

        Self::try_from(data).expect("Token metadata encoded data should fit into ShardData")
    }
}
