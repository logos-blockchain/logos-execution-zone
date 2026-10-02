//! This crate contains core data structures and utilities for the Token Program.

use borsh::{BorshDeserialize, BorshSerialize};
use lee_core::{
    account::{AccountId, Actor, ActorState},
    program::{Call, Cast},
};
use serde::{Deserialize, Serialize};

pub const TOKEN_NAME: [u8; 5] = *b"token";

#[derive(Clone, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub enum Message {
    Transfer {
        to: AccountId,
        descriptor: TokenDescriptor,
        amount: u128,
        notify: Option<Notify>,
        delivery: Delivery,
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

/// The target is called from the credit and inherits its grants: a transfer delivered as a Call
/// passes any custody grant it holds into the target's subtree.
#[derive(Clone, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct Notify {
    pub to: Actor,
    pub payload: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct Notification {
    pub credited_account: AccountId,
    pub descriptor: TokenDescriptor,
    pub amount: u128,
    pub payload: Vec<u8>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub enum Delivery {
    Call,
    Cast,
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

        Self::try_from(data).expect("Token definition encoded data should fit into ActorState")
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

        Self::try_from(data).expect("Token holding encoded data should fit into ActorState")
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

        Self::try_from(data).expect("Token metadata encoded data should fit into ActorState")
    }
}

#[must_use]
pub fn expected_sends(receiver: Actor, message: &Message) -> (Vec<Call>, Vec<Cast>) {
    let own = |account_id: AccountId| Actor::new(account_id, receiver.program_account_id);
    let create = |to: AccountId, data: ActorState| Call::new(own(to), &Message::Create(data));
    let calls = match message {
        Message::Transfer {
            to,
            descriptor,
            amount,
            notify,
            delivery,
        } => {
            let credit = Message::Credit {
                descriptor: *descriptor,
                amount: *amount,
                notify: notify.clone(),
            };
            match delivery {
                Delivery::Call => vec![Call::new(own(*to), &credit)],
                Delivery::Cast => return (Vec::new(), vec![Cast::new(own(*to), &credit)]),
            }
        }
        Message::Credit {
            descriptor,
            amount,
            notify,
        } => notify
            .iter()
            .map(|target| {
                Call::new(
                    target.to,
                    &Message::Notification(Notification {
                        credited_account: receiver.account_id,
                        descriptor: *descriptor,
                        amount: *amount,
                        payload: target.payload.clone(),
                    }),
                )
            })
            .collect(),
        Message::Burn {
            descriptor,
            amount,
            definition,
        } => vec![Call::new(
            own(*definition),
            &Message::BurnSupply {
                definition_id: descriptor.definition_id,
                kind: descriptor.kind,
                amount: *amount,
            },
        )],
        Message::PrintNft {
            printed,
            definition_id,
        } => vec![create(
            *printed,
            ActorState::from(&TokenHolding::NftPrintedCopy {
                definition_id: *definition_id,
                owned: true,
            }),
        )],
        Message::NewDefinition {
            definition,
            holding,
            metadata,
        } => {
            let created = match definition {
                NewTokenDefinition::Fungible { total_supply, .. } => TokenHolding::Fungible {
                    definition_id: receiver.account_id,
                    balance: *total_supply,
                },
                NewTokenDefinition::NonFungible {
                    printable_supply, ..
                } => TokenHolding::NftMaster {
                    definition_id: receiver.account_id,
                    print_balance: *printable_supply,
                },
            };
            std::iter::once(create(*holding, ActorState::from(&created)))
                .chain(metadata.iter().map(|(metadata_id, new_metadata)| {
                    create(
                        *metadata_id,
                        ActorState::from(&TokenMetadata {
                            definition_id: receiver.account_id,
                            standard: new_metadata.standard.clone(),
                            uri: new_metadata.uri.clone(),
                            creators: new_metadata.creators.clone(),
                            primary_sale_date: 0, // TODO #261: future works to implement this
                        }),
                    )
                }))
                .collect()
        }
        Message::Mint { to, amount } => vec![Call::new(
            own(*to),
            &Message::Credit {
                descriptor: TokenDescriptor {
                    definition_id: receiver.account_id,
                    kind: TokenKind::Fungible,
                },
                amount: *amount,
                notify: None,
            },
        )],
        Message::EnsureHolding { .. }
        | Message::BurnSupply { .. }
        | Message::AssertKind { .. }
        | Message::Create(_)
        | Message::Notification(_) => Vec::new(),
    };
    (calls, Vec::new())
}

#[must_use]
pub fn same_asset(holding: TokenKind, descriptor: TokenKind) -> bool {
    holding == descriptor || (holding != TokenKind::Fungible && descriptor != TokenKind::Fungible)
}

#[must_use]
pub fn token_account_id() -> AccountId {
    AccountId::from_builtin_program_name(&TOKEN_NAME)
}
