//! This crate contains core data structures and utilities for the Token Program.

use borsh::{BorshDeserialize, BorshSerialize};
use nssa_core::account::{AccountId, Data};
use serde::{Deserialize, Serialize};

/// Token Program Instruction.
#[derive(Serialize, Deserialize)]
pub enum Instruction {
    /// Transfer tokens from sender to recipient.
    ///
    /// Required accounts:
    /// - Sender's Token Holding account (authorized),
    /// - Recipient's Token Holding account.
    Transfer { amount_to_transfer: u128 },

    /// Create a new fungible token definition without metadata.
    ///
    /// Required accounts:
    /// - Token Definition account (uninitialized),
    /// - Token Holding account (uninitialized).
    NewFungibleDefinition { name: String, total_supply: u128 },

    /// Create a new fungible or non-fungible token definition with metadata.
    ///
    /// Required accounts:
    /// - Token Definition account (uninitialized),
    /// - Token Holding account (uninitialized),
    /// - Token Metadata account (uninitialized).
    NewDefinitionWithMetadata {
        new_definition: NewTokenDefinition,
        /// Boxed to avoid large enum variant size.
        metadata: Box<NewTokenMetadata>,
    },

    /// Initialize a token holding account for a given token definition.
    ///
    /// Required accounts:
    /// - Token Definition account (initialized),
    /// - Token Holding account (uninitialized),
    InitializeAccount,

    /// Burn tokens from the holder's account.
    ///
    /// Required accounts:
    /// - Token Definition account (initialized),
    /// - Token Holding account (authorized).
    Burn { amount_to_burn: u128 },

    /// Mint new tokens to the holder's account.
    ///
    /// Required accounts:
    /// - Token Definition account (authorized),
    /// - Token Holding account (uninitialized or initialized).
    Mint { amount_to_mint: u128 },

    /// Print a new NFT from the master copy.
    ///
    /// Required accounts:
    /// - NFT Master Token Holding account (authorized),
    /// - NFT Printed Copy Token Holding account (uninitialized).
    PrintNft,
}

#[derive(Serialize, Deserialize)]
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

impl TryFrom<&Data> for TokenDefinition {
    type Error = std::io::Error;

    fn try_from(data: &Data) -> Result<Self, Self::Error> {
        Self::try_from_slice(data.as_ref())
    }
}

impl From<&TokenDefinition> for Data {
    fn from(definition: &TokenDefinition) -> Self {
        // Using size_of_val as size hint for Vec allocation
        let mut data = Vec::with_capacity(std::mem::size_of_val(definition));

        BorshSerialize::serialize(definition, &mut data)
            .expect("Serialization to Vec should not fail");

        Self::try_from(data).expect("Token definition encoded data should fit into Data")
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

impl TokenHolding {
    #[must_use]
    pub const fn zeroized_clone_from(other: &Self) -> Self {
        match other {
            Self::Fungible { definition_id, .. } => Self::Fungible {
                definition_id: *definition_id,
                balance: 0,
            },
            Self::NftMaster { definition_id, .. } => Self::NftMaster {
                definition_id: *definition_id,
                print_balance: 0,
            },
            Self::NftPrintedCopy { definition_id, .. } => Self::NftPrintedCopy {
                definition_id: *definition_id,
                owned: false,
            },
        }
    }

    #[must_use]
    pub const fn zeroized_from_definition(
        definition_id: AccountId,
        definition: &TokenDefinition,
    ) -> Self {
        match definition {
            TokenDefinition::Fungible { .. } => Self::Fungible {
                definition_id,
                balance: 0,
            },
            TokenDefinition::NonFungible { .. } => Self::NftPrintedCopy {
                definition_id,
                owned: false,
            },
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

impl TryFrom<&Data> for TokenHolding {
    type Error = std::io::Error;

    fn try_from(data: &Data) -> Result<Self, Self::Error> {
        Self::try_from_slice(data.as_ref())
    }
}

impl From<&TokenHolding> for Data {
    fn from(holding: &TokenHolding) -> Self {
        // Using size_of_val as size hint for Vec allocation
        let mut data = Vec::with_capacity(std::mem::size_of_val(holding));

        BorshSerialize::serialize(holding, &mut data)
            .expect("Serialization to Vec should not fail");

        Self::try_from(data).expect("Token holding encoded data should fit into Data")
    }
}

#[derive(Serialize, Deserialize)]
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
#[derive(Debug, PartialEq, Eq, Serialize, Deserialize, BorshSerialize, BorshDeserialize)]
pub enum MetadataStandard {
    Simple,
    Expanded,
}

impl TryFrom<&Data> for TokenMetadata {
    type Error = std::io::Error;

    fn try_from(data: &Data) -> Result<Self, Self::Error> {
        Self::try_from_slice(data.as_ref())
    }
}

impl From<&TokenMetadata> for Data {
    fn from(metadata: &TokenMetadata) -> Self {
        // Using size_of_val as size hint for Vec allocation
        let mut data = Vec::with_capacity(std::mem::size_of_val(metadata));

        BorshSerialize::serialize(metadata, &mut data)
            .expect("Serialization to Vec should not fail");

        Self::try_from(data).expect("Token metadata encoded data should fit into Data")
    }
}
