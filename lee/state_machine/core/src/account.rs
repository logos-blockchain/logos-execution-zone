use std::{collections::BTreeMap, fmt::Display, str::FromStr};

use base58::{FromBase58 as _, ToBase58 as _};
use borsh::{BorshDeserialize, BorshSerialize};
pub use data::Data;
use risc0_zkvm::sha::{Impl, Sha256 as _};
use serde::{Deserialize, Serialize};
use serde_with::{DeserializeFromStr, SerializeDisplay};

use crate::NullifierSecretKey;

pub mod data;

#[derive(Copy, Debug, Default, Clone, Eq, PartialEq)]
pub struct Nonce(pub u128);

impl Nonce {
    pub const fn public_account_nonce_increment(&mut self) {
        self.0 = self
            .0
            .checked_add(1)
            .expect("Overflow when incrementing nonce");
    }

    #[must_use]
    pub fn private_account_nonce_init(account_id: &AccountId) -> Self {
        let mut bytes: [u8; 64] = [0_u8; 64];
        bytes[..32].copy_from_slice(account_id.value());
        let result: [u8; 32] = Impl::hash_bytes(&bytes).as_bytes().try_into().unwrap();
        let result = result.first_chunk::<16>().unwrap();

        Self(u128::from_le_bytes(*result))
    }

    #[must_use]
    pub fn private_account_nonce_increment(self, nsk: &NullifierSecretKey) -> Self {
        let mut bytes: [u8; 64] = [0_u8; 64];
        bytes[..32].copy_from_slice(nsk);
        bytes[32..48].copy_from_slice(&self.0.to_le_bytes());
        let result: [u8; 32] = Impl::hash_bytes(&bytes).as_bytes().try_into().unwrap();
        let result = result.first_chunk::<16>().unwrap();

        Self(u128::from_le_bytes(*result))
    }
}

impl From<u128> for Nonce {
    fn from(value: u128) -> Self {
        Self(value)
    }
}

impl From<Nonce> for u128 {
    fn from(value: Nonce) -> Self {
        value.0
    }
}

impl Serialize for Nonce {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        Serialize::serialize(&self.0, serializer)
    }
}

impl<'de> Deserialize<'de> for Nonce {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        Ok(<u128 as Deserialize>::deserialize(deserializer)?.into())
    }
}

impl BorshSerialize for Nonce {
    fn serialize<W: std::io::Write>(&self, writer: &mut W) -> std::io::Result<()> {
        BorshSerialize::serialize(&self.0, writer)
    }
}

impl BorshDeserialize for Nonce {
    fn deserialize_reader<R: std::io::Read>(reader: &mut R) -> std::io::Result<Self> {
        Ok(<u128 as BorshDeserialize>::deserialize_reader(reader)?.into())
    }
}

pub type Balance = u128;

/// A single program's namespace inside an account. Every program may read every slot,
/// may write only its own, and may credit balance to any.
#[derive(
    Debug, Default, Clone, Eq, PartialEq, Serialize, Deserialize, BorshSerialize, BorshDeserialize,
)]
pub struct Slot {
    pub balance: Balance,
    pub data: Data,
}

impl Slot {
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self == &Self::default()
    }
}

/// Account to be used both in public and private contexts.
///
/// There is no owner: an account is a map from program to that program's private namespace.
/// `BTreeMap` rather than `HashMap` because the account is hashed into commitments, so its
/// encoding must be canonical. Empty slots are never stored (see `validate_execution`), so
/// equal accounts always encode identically.
#[derive(
    Debug, Default, Clone, Eq, PartialEq, Serialize, Deserialize, BorshSerialize, BorshDeserialize,
)]
pub struct Account {
    pub nonce: Nonce,
    pub slots: BTreeMap<AccountId, Slot>,
}

impl Account {
    #[must_use]
    pub fn slot(&self, program: impl Into<AccountId>) -> Option<&Slot> {
        self.slots.get(&program.into())
    }

    /// The slot a program reads through, detached from the account. Vacant slots read as empty.
    #[must_use]
    pub fn slot_or_empty(&self, program: impl Into<AccountId>) -> Slot {
        self.slot(program).cloned().unwrap_or_default()
    }

    /// The slot a program writes through. Vacant slots materialize as empty.
    pub fn slot_mut(&mut self, program: impl Into<AccountId>) -> &mut Slot {
        self.slots.entry(program.into()).or_default()
    }

    /// Writes a slot back, dropping it if it emptied so the encoding stays canonical.
    pub fn set_slot(&mut self, program: impl Into<AccountId>, slot: Slot) {
        let program = program.into();
        if slot.is_empty() {
            self.slots.remove(&program);
        } else {
            self.slots.insert(program, slot);
        }
    }

    #[must_use]
    pub fn balance(&self, program: impl Into<AccountId>) -> Balance {
        self.slot(program).map_or(0, |slot| slot.balance)
    }

    #[must_use]
    pub fn data(&self, program: impl Into<AccountId>) -> &Data {
        const EMPTY: &Data = &Data::empty();
        self.slot(program).map_or(EMPTY, |slot| &slot.data)
    }

    /// Drops slots that have become empty, keeping the encoding canonical.
    pub fn prune(&mut self) {
        self.slots.retain(|_, slot| !slot.is_empty());
    }

    /// An account whose only occupied slot belongs to `program_id`.
    #[must_use]
    pub fn single(
        program: impl Into<AccountId>,
        balance: Balance,
        data: Data,
        nonce: Nonce,
    ) -> Self {
        let slot = Slot { balance, data };
        let mut account = Self {
            nonce,
            slots: BTreeMap::new(),
        };
        if !slot.is_empty() {
            account.slots.insert(program.into(), slot);
        }
        account
    }
}

/// The slot a transaction names, as it appears in the signed message. `program` is `None` for
/// a position that carries only an address: a marker, an authority, a PDA-derivation input.
#[derive(
    Debug,
    Copy,
    Clone,
    Eq,
    PartialEq,
    Hash,
    Serialize,
    Deserialize,
    BorshSerialize,
    BorshDeserialize,
)]
pub struct SlotRef {
    pub account_id: AccountId,
    pub program: Option<AccountId>,
}

impl SlotRef {
    /// A position naming `program`'s namespace at `account_id`.
    #[must_use]
    pub fn new(account_id: AccountId, program: impl Into<AccountId>) -> Self {
        Self {
            account_id,
            program: Some(program.into()),
        }
    }

    /// A position carrying only an address: a marker, an authority, a derivation input.
    #[must_use]
    pub const fn address_only(account_id: AccountId) -> Self {
        Self {
            account_id,
            program: None,
        }
    }
}

/// The position an [`Input`] occupies, dropping what it holds there. The exact inverse of
/// reading a `SlotRef` out of the state, and the key both validators use to tell one position
/// from another.
impl From<&Input> for SlotRef {
    fn from(input: &Input) -> Self {
        Self {
            account_id: input.account_id,
            program: input.slot.as_ref().map(|(program, _)| *program),
        }
    }
}

/// One namespace at one account, as handed to a program. An account needing two namespaces
/// occupies two positions; no two positions may name the same pair.
#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize, BorshSerialize, BorshDeserialize)]
pub struct Input {
    pub account_id: AccountId,
    pub is_authorized: bool,
    pub slot: Option<(AccountId, Slot)>,
}

impl Input {
    /// A position naming `program`'s namespace, holding `slot`.
    #[must_use]
    pub fn named(
        account_id: AccountId,
        is_authorized: bool,
        program: impl Into<AccountId>,
        slot: Slot,
    ) -> Self {
        Self {
            account_id,
            is_authorized,
            slot: Some((program.into(), slot)),
        }
    }

    /// A position carrying only an address: a marker, an authority, a derivation input.
    #[must_use]
    pub const fn address_only(account_id: AccountId, is_authorized: bool) -> Self {
        Self {
            account_id,
            is_authorized,
            slot: None,
        }
    }

    /// The position `slot_ref` names, read out of `account`. The inverse of the `SlotRef`
    /// conversion above: a vacant slot reads as empty, and an address-only ref reads nothing.
    #[must_use]
    pub fn at(slot_ref: SlotRef, is_authorized: bool, account: &Account) -> Self {
        Self {
            account_id: slot_ref.account_id,
            is_authorized,
            slot: slot_ref
                .program
                .map(|program| (program, account.slot_or_empty(program))),
        }
    }

    /// The named slot, checked to be `program`'s. The check lives here so a program cannot
    /// forget it: a caller naming some other namespace must not read as an empty one.
    #[must_use]
    pub fn slot_of(&self, program: impl Into<AccountId>) -> &Slot {
        let (named, slot) = self.slot.as_ref().expect("Position names no slot");
        assert_eq!(*named, program.into(), "Position names another namespace");
        slot
    }

    /// The same position carrying a different slot, for building the pre-state a chained call
    /// will see once the calls before it have run. The namespace is the one this position
    /// already names: a position may change what its slot holds, never which slot it is.
    #[must_use]
    pub fn with_slot(mut self, slot: Slot) -> Self {
        let (program, _) = self.slot.expect("Position names no slot");
        self.slot = Some((program, slot));
        self
    }

    /// The post state of a position the program leaves alone.
    #[must_use]
    pub fn unchanged(&self) -> Option<Slot> {
        self.slot.as_ref().map(|(_, slot)| slot.clone())
    }

    /// The named slot by value, whichever namespace it is. Only for a program crediting a
    /// namespace its caller chose; anywhere the program knows what it expects, name it and let
    /// [`Self::into_slot_of`] check.
    #[must_use]
    pub fn into_caller_named_slot(self) -> Slot {
        self.slot.expect("Position names no slot").1
    }

    /// The named slot by value, for a program building its post state.
    #[must_use]
    pub fn into_slot_of(self, program: impl Into<AccountId>) -> Slot {
        let (named, slot) = self.slot.expect("Position names no slot");
        assert_eq!(named, program.into(), "Position names another namespace");
        slot
    }

    #[must_use]
    pub fn balance(&self, program: impl Into<AccountId>) -> Balance {
        self.slot_of(program).balance
    }

    #[must_use]
    pub fn data(&self, program: impl Into<AccountId>) -> &Data {
        &self.slot_of(program).data
    }
}

#[derive(
    Default,
    Copy,
    Clone,
    SerializeDisplay,
    DeserializeFromStr,
    PartialEq,
    Eq,
    Hash,
    PartialOrd,
    Ord,
    BorshSerialize,
    BorshDeserialize,
)]
pub struct AccountId {
    value: [u8; 32],
}

impl std::fmt::Debug for AccountId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.value.to_base58())
    }
}

impl AccountId {
    #[must_use]
    pub const fn new(value: [u8; 32]) -> Self {
        Self { value }
    }

    #[must_use]
    pub const fn value(&self) -> &[u8; 32] {
        &self.value
    }

    #[must_use]
    pub const fn into_value(self) -> [u8; 32] {
        self.value
    }
}

impl AsRef<[u8]> for AccountId {
    fn as_ref(&self) -> &[u8] {
        &self.value
    }
}

#[derive(Debug, thiserror::Error)]
pub enum AccountIdError {
    #[error("invalid base58: {0:?}")]
    InvalidBase58(base58::FromBase58Error),
    #[error("invalid length: expected 32 bytes, got {0}")]
    InvalidLength(usize),
}

impl FromStr for AccountId {
    type Err = AccountIdError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let bytes = s.from_base58().map_err(AccountIdError::InvalidBase58)?;
        if bytes.len() != 32 {
            return Err(AccountIdError::InvalidLength(bytes.len()));
        }
        let mut value = [0_u8; 32];
        value.copy_from_slice(&bytes);
        Ok(Self { value })
    }
}

impl Display for AccountId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.value.to_base58())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::{DEFAULT_PROGRAM_ID, ProgramId};

    const OTHER_PROGRAM_ID: ProgramId = [9; 8];

    fn input_naming(program: ProgramId) -> Input {
        Input {
            account_id: AccountId::new([0; 32]),
            is_authorized: true,
            slot: Some((
                program.into(),
                Slot {
                    balance: 42,
                    data: b"named".to_vec().try_into().unwrap(),
                },
            )),
        }
    }

    #[test]
    fn zero_balance_account_data_creation() {
        let new_acc = Account::default();

        assert_eq!(new_acc.balance(DEFAULT_PROGRAM_ID), 0);
    }

    #[test]
    fn zero_nonce_account_data_creation() {
        let new_acc = Account::default();

        assert_eq!(new_acc.nonce.0, 0);
    }

    #[test]
    fn empty_data_account_data_creation() {
        let new_acc = Account::default();

        assert!(new_acc.data(DEFAULT_PROGRAM_ID).is_empty());
    }

    #[test]
    fn no_slots_on_account_data_creation() {
        let new_acc = Account::default();

        assert!(new_acc.slots.is_empty());
    }

    #[test]
    fn vacant_slot_reads_as_empty() {
        assert!(
            Account::default()
                .slot_or_empty(DEFAULT_PROGRAM_ID)
                .is_empty()
        );
    }

    #[test]
    fn slot_round_trips_through_set_slot() {
        let slot = Slot {
            balance: 7,
            data: b"round_trip".to_vec().try_into().unwrap(),
        };
        let mut account = Account::default();

        account.set_slot(DEFAULT_PROGRAM_ID, slot.clone());

        assert_eq!(account.slot_or_empty(DEFAULT_PROGRAM_ID), slot);
    }

    #[test]
    fn set_slot_drops_a_slot_that_emptied() {
        let mut account = Account::single(DEFAULT_PROGRAM_ID, 5, Data::empty(), Nonce(0));

        account.set_slot(DEFAULT_PROGRAM_ID, Slot::default());

        assert!(account.slots.is_empty());
    }

    #[test]
    fn input_reads_through_the_named_slot() {
        let input = input_naming(DEFAULT_PROGRAM_ID);

        assert_eq!(input.balance(DEFAULT_PROGRAM_ID), 42);
        assert_eq!(input.data(DEFAULT_PROGRAM_ID).as_ref(), b"named".as_slice());
    }

    #[test]
    fn into_slot_of_takes_the_named_slot() {
        let slot = input_naming(DEFAULT_PROGRAM_ID).into_slot_of(DEFAULT_PROGRAM_ID);

        assert_eq!(slot.balance, 42);
    }

    #[test]
    #[should_panic(expected = "Position names another namespace")]
    fn input_refuses_a_namespace_it_does_not_name() {
        let balance = input_naming(DEFAULT_PROGRAM_ID).balance(OTHER_PROGRAM_ID);

        unreachable!("reading an unnamed namespace must panic, got {balance}");
    }

    #[test]
    #[should_panic(expected = "Position names no slot")]
    fn input_refuses_a_position_carrying_only_an_address() {
        let address_only = Input {
            account_id: AccountId::new([0; 32]),
            is_authorized: true,
            slot: None,
        };

        let balance = address_only.balance(DEFAULT_PROGRAM_ID);

        unreachable!("reading an address-only position must panic, got {balance}");
    }

    #[test]
    fn set_slot_leaves_other_slots_alone() {
        let mut account = Account::single(DEFAULT_PROGRAM_ID, 7, Data::empty(), Nonce(0));

        account.set_slot(
            OTHER_PROGRAM_ID,
            Slot {
                balance: 1,
                data: Data::empty(),
            },
        );

        assert_eq!(account.balance(DEFAULT_PROGRAM_ID), 7);
        assert_eq!(account.balance(OTHER_PROGRAM_ID), 1);
    }

    #[test]
    fn set_slot_never_stores_an_empty_slot() {
        let mut account = Account::default();

        account.set_slot(DEFAULT_PROGRAM_ID, Slot::default());

        assert!(account.slots.is_empty());
    }

    #[cfg(feature = "host")]
    #[test]
    fn parse_valid_account_id() {
        let base58_str = "11111111111111111111111111111111";
        let account_id: AccountId = base58_str.parse().unwrap();
        assert_eq!(account_id.value, [0_u8; 32]);
    }

    #[cfg(feature = "host")]
    #[test]
    fn parse_invalid_base58() {
        let base58_str = "00".repeat(32); // invalid base58 chars
        let result = base58_str.parse::<AccountId>().unwrap_err();
        assert!(matches!(result, AccountIdError::InvalidBase58(_)));
    }

    #[cfg(feature = "host")]
    #[test]
    fn parse_wrong_length_short() {
        let base58_str = "11".repeat(31); // 62 chars = 31 bytes
        let result = base58_str.parse::<AccountId>().unwrap_err();
        assert!(matches!(result, AccountIdError::InvalidLength(_)));
    }

    #[cfg(feature = "host")]
    #[test]
    fn parse_wrong_length_long() {
        let base58_str = "11".repeat(33); // 66 chars = 33 bytes
        let result = base58_str.parse::<AccountId>().unwrap_err();
        assert!(matches!(result, AccountIdError::InvalidLength(_)));
    }

    #[test]
    fn default_account_id() {
        let default_account_id = AccountId::default();
        let expected_account_id = AccountId::new([0; 32]);
        assert!(default_account_id == expected_account_id);
    }

    #[test]
    fn initialize_private_nonce() {
        let account_id = AccountId::new([42; 32]);
        let nonce = Nonce::private_account_nonce_init(&account_id);
        let expected_nonce = Nonce(37_937_661_125_547_691_021_612_781_941_709_513_486);
        assert_eq!(nonce, expected_nonce);
    }

    #[test]
    fn increment_private_nonce() {
        let nsk: NullifierSecretKey = [42_u8; 32];
        let nonce = Nonce(37_937_661_125_547_691_021_612_781_941_709_513_486)
            .private_account_nonce_increment(&nsk);
        let expected_nonce = Nonce(327_300_903_218_789_900_388_409_116_014_290_259_894);
        assert_eq!(nonce, expected_nonce);
    }

    #[test]
    fn increment_public_nonce() {
        let value = 42_u128;
        let mut nonce = Nonce(value);
        nonce.public_account_nonce_increment();
        let expected_nonce = Nonce(value + 1);
        assert_eq!(nonce, expected_nonce);
    }

    #[test]
    fn serde_roundtrip_for_nonce() {
        let nonce: Nonce = 7_u128.into();

        let serde_serialized_nonce = serde_json::to_vec(&nonce).unwrap();

        let nonce_restored = serde_json::from_slice(&serde_serialized_nonce).unwrap();

        assert_eq!(nonce, nonce_restored);
    }

    #[test]
    fn account_round_trips_through_json() {
        // The wallet persists accounts as JSON, and `ProgramId` is `[u32; 8]`, which serde_json
        // refuses as a map key. Serializing `slots` as pairs is what keeps that working.
        let account = Account::single(
            [1, 2, 3, 4, 5, 6, 7, 8],
            42,
            b"hello".to_vec().try_into().unwrap(),
            Nonce(7),
        );
        let json = serde_json::to_string(&account).expect("account must serialize as JSON");
        let decoded: Account = serde_json::from_str(&json).expect("account must round trip");
        assert_eq!(account, decoded);
    }

    #[test]
    fn borsh_roundtrip_for_nonce() {
        let nonce: Nonce = 7_u128.into();

        let borsh_serialized_nonce = borsh::to_vec(&nonce).unwrap();

        let nonce_restored = borsh::from_slice(&borsh_serialized_nonce).unwrap();

        assert_eq!(nonce, nonce_restored);
    }
}
