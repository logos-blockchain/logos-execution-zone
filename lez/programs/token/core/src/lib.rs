//! This crate contains core data structures and utilities for the Token Program.

use borsh::{BorshDeserialize, BorshSerialize};
use lee_core::account::{AccountId, Actor, ActorState};
use serde::{Deserialize, Serialize};

pub const TOKEN_NAME: [u8; 5] = *b"token";

#[derive(Clone, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub enum Message {
    Transfer {
        to: AccountId,
        descriptor: TokenDescriptor,
        amount: u128,
        notify: Option<Notify>,
    },
    Credit {
        descriptor: TokenDescriptor,
        amount: u128,
        notify: Option<Notify>,
    },
    EnsureHolding {
        descriptor: TokenDescriptor,
    },
    Burn {
        descriptor: TokenDescriptor,
        amount: u128,
        definition: AccountId,
    },
    PrintNft {
        printed: AccountId,
        definition_id: AccountId,
    },
    NewDefinition {
        definition: NewTokenDefinition,
        holding: AccountId,
        metadata: Option<(AccountId, NewTokenMetadata)>,
    },
    Mint {
        to: AccountId,
        amount: u128,
    },
    BurnSupply {
        definition_id: AccountId,
        kind: TokenKind,
        amount: u128,
    },
    AssertKind {
        kind: TokenKind,
    },
    Create(ActorState),
    Notification(Notification),
}

/// The target is called from the credit and inherits its grants: a transfer casts its credit, so
/// the target inherits none of the transfer's grants.
#[derive(Clone, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct Notify {
    pub to: Actor,
    pub payload: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct Notification {
    pub descriptor: TokenDescriptor,
    pub amount: u128,
    pub payload: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
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

impl TryFrom<&ActorState> for TokenDefinition {
    type Error = std::io::Error;

    fn try_from(data: &ActorState) -> Result<Self, Self::Error> {
        Self::try_from_slice(data.as_ref())
    }
}

impl From<&TokenDefinition> for ActorState {
    fn from(definition: &TokenDefinition) -> Self {
        // Using size_of_val as size hint for Vec allocation
        let mut data = Vec::with_capacity(std::mem::size_of_val(definition));

        BorshSerialize::serialize(definition, &mut data)
            .expect("Serialization to Vec should not fail");

        Self::from(data)
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
    pub const fn fungible(definition_id: AccountId) -> Self {
        Self {
            definition_id,
            kind: TokenKind::Fungible,
        }
    }

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

impl TryFrom<&ActorState> for TokenHolding {
    type Error = std::io::Error;

    fn try_from(data: &ActorState) -> Result<Self, Self::Error> {
        Self::try_from_slice(data.as_ref())
    }
}

impl From<&TokenHolding> for ActorState {
    fn from(holding: &TokenHolding) -> Self {
        // Using size_of_val as size hint for Vec allocation
        let mut data = Vec::with_capacity(std::mem::size_of_val(holding));

        BorshSerialize::serialize(holding, &mut data)
            .expect("Serialization to Vec should not fail");

        Self::from(data)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
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

impl TryFrom<&ActorState> for TokenMetadata {
    type Error = std::io::Error;

    fn try_from(data: &ActorState) -> Result<Self, Self::Error> {
        Self::try_from_slice(data.as_ref())
    }
}

impl From<&TokenMetadata> for ActorState {
    fn from(metadata: &TokenMetadata) -> Self {
        // Using size_of_val as size hint for Vec allocation
        let mut data = Vec::with_capacity(std::mem::size_of_val(metadata));

        BorshSerialize::serialize(metadata, &mut data)
            .expect("Serialization to Vec should not fail");

        Self::from(data)
    }
}

#[must_use]
pub fn same_asset(holding: TokenKind, descriptor: TokenKind) -> bool {
    holding == descriptor || (holding != TokenKind::Fungible && descriptor != TokenKind::Fungible)
}

#[must_use]
pub fn token_account_id() -> AccountId {
    AccountId::from_builtin_program_name(&TOKEN_NAME)
}
