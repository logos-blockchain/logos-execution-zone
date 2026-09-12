//! This crate contains core data structures and utilities for the Token Program.

use borsh::{BorshDeserialize, BorshSerialize};
use lee_core::{
    account::{AccountId, AccountIdData, ShardData},
    program::{AccountInput, PdaSeed},
};
use serde::{Deserialize, Serialize};

/// Token Program Instruction.
///
/// Holding, definition and metadata inputs select this program's shard; owner inputs are
/// balance-only. "Empty" and "initialized" refer to that shard.
#[derive(BorshSerialize, BorshDeserialize)]
pub enum Instruction {
    /// Transfer tokens from sender to recipient.
    ///
    /// Required accounts:
    /// - Sender's Token Holding account (initialized),
    /// - Recipient's Token Holding account (initialized or empty),
    /// - Sender's owner (authorized).
    Transfer {
        sender: HoldingTarget,
        recipient: HoldingTarget,
        amount_to_transfer: u128,
    },

    /// Create a new fungible token definition without metadata.
    ///
    /// Required accounts:
    /// - Token Definition account (empty, authorized),
    /// - Holder's Token Holding account (empty).
    NewFungibleDefinition {
        name: String,
        total_supply: u128,
        holder: HoldingTarget,
    },

    /// Create a new fungible or non-fungible token definition with metadata.
    ///
    /// Required accounts:
    /// - Token Definition account (empty, authorized),
    /// - Holder's Token Holding account (empty),
    /// - Token Metadata account (empty, authorized).
    NewDefinitionWithMetadata {
        new_definition: NewTokenDefinition,
        /// Boxed to avoid large enum variant size.
        metadata: Box<NewTokenMetadata>,
        holder: HoldingTarget,
    },

    /// Initialize a token holding account for a given token definition.
    ///
    /// Required accounts:
    /// - Token Definition account (initialized),
    /// - Holder's Token Holding account (empty, or already initialized for the definition).
    InitializeAccount { holder: HoldingTarget },

    /// Burn tokens from the holder's account.
    ///
    /// Required accounts:
    /// - Token Definition account (initialized),
    /// - Holder's Token Holding account (initialized),
    /// - Holder's owner (authorized).
    Burn {
        holder: HoldingTarget,
        amount_to_burn: u128,
    },

    /// Mint new tokens to the holder's account.
    ///
    /// Required accounts:
    /// - Token Definition account (initialized, authorized),
    /// - Holder's Token Holding account (initialized or empty).
    Mint {
        holder: HoldingTarget,
        amount_to_mint: u128,
    },

    /// Print a new NFT from the master copy.
    ///
    /// Required accounts:
    /// - Master holder's NFT Master Token Holding account (initialized),
    /// - Copy holder's NFT Printed Copy Token Holding account (empty, or initialized and unowned),
    /// - Master holder's owner (authorized).
    PrintNft {
        master_holder: HoldingTarget,
        copy_holder: HoldingTarget,
    },
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
pub enum HoldingKind {
    Fungible,
    NftMaster,
    NftPrintedCopy,
}

impl HoldingKind {
    const fn tag(self) -> u8 {
        match self {
            Self::Fungible => 0,
            Self::NftMaster => 1,
            Self::NftPrintedCopy => 2,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct HoldingTarget {
    pub owner_id: AccountId,
    pub account_id_data: AccountIdData,
}

impl TokenHolding {
    #[must_use]
    pub const fn kind(&self) -> HoldingKind {
        match self {
            Self::Fungible { .. } => HoldingKind::Fungible,
            Self::NftMaster { .. } => HoldingKind::NftMaster,
            Self::NftPrintedCopy { .. } => HoldingKind::NftPrintedCopy,
        }
    }

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

#[must_use]
pub fn holding_seed(owner_id: AccountId, definition_id: AccountId, kind: HoldingKind) -> PdaSeed {
    use risc0_zkvm::sha::{Impl, Sha256 as _};
    const PREFIX: &[u8; 32] = b"/LEE/TokenHolding/v1/\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00";

    let mut bytes = [0; 97];
    bytes[..32].copy_from_slice(PREFIX);
    bytes[32] = kind.tag();
    bytes[33..65].copy_from_slice(owner_id.as_ref());
    bytes[65..].copy_from_slice(definition_id.as_ref());
    PdaSeed::new(
        Impl::hash_bytes(&bytes)
            .as_bytes()
            .try_into()
            .expect("Hash output must be exactly 32 bytes long"),
    )
}

#[must_use]
pub fn holding_id(
    holder: &HoldingTarget,
    token_program_id: AccountId,
    definition_id: AccountId,
    kind: HoldingKind,
) -> AccountId {
    holder.account_id_data.derive_pda_id(
        token_program_id,
        &holding_seed(holder.owner_id, definition_id, kind),
    )
}

pub fn verify_holding(
    holder: &HoldingTarget,
    holding: &AccountInput,
    token_program_id: AccountId,
    definition_id: AccountId,
    kind: HoldingKind,
) {
    assert_eq!(
        holding.account_id,
        holding_id(holder, token_program_id, definition_id, kind),
        "Holding account ID does not match its derivation"
    );
}
