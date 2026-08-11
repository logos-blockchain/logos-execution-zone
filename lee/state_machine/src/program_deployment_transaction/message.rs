use borsh::{BorshDeserialize, BorshSerialize};
use lee_core::{account::AccountId, program::ProgramId};
use sha2::{Digest as _, Sha256};

const PREFIX: &[u8; 32] = b"/LEE/v0.3/Message/ProgramDeploy/";

#[derive(Clone, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub enum Message {
    Init(InitMessage),
    Upgrade(UpgradeMessage),
}

#[derive(Clone, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct InitMessage {
    pub(crate) elf: Vec<u8>,
    pub(crate) upgrade_auth: Option<AccountId>,
}

#[derive(Clone, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct UpgradeMessage {
    pub program_id: ProgramId,
    pub auth_withdraw: bool,
    pub elf: Vec<u8>,
}

impl std::fmt::Debug for Message {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Init(init) => f.debug_tuple("Init").field(init).finish(),
            Self::Upgrade(upgrade) => f.debug_tuple("Upgrade").field(upgrade).finish(),
        }
    }
}

impl std::fmt::Debug for InitMessage {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("InitMessage")
            .field("elf", &format_args!("<{} bytes>", self.elf.len()))
            .field("upgrade_auth", &self.upgrade_auth)
            .finish()
    }
}

impl std::fmt::Debug for UpgradeMessage {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("UpgradeMessage")
            .field("program_id", &self.program_id)
            .field("auth_withdraw", &self.auth_withdraw)
            .field("elf", &format_args!("<{} bytes>", self.elf.len()))
            .finish()
    }
}

impl Message {
    #[must_use]
    pub const fn new(elf: Vec<u8>) -> Self {
        Self::new_with_upgrade_auth(elf, None)
    }

    #[must_use]
    pub const fn new_with_upgrade_auth(elf: Vec<u8>, upgrade_auth: Option<AccountId>) -> Self {
        Self::Init(InitMessage { elf, upgrade_auth })
    }

    #[must_use]
    pub fn hash(&self) -> [u8; 32] {
        let bytes = self.to_bytes();
        let mut preimage = Vec::with_capacity(
            PREFIX
                .len()
                .checked_add(bytes.len())
                .expect("length overflow"),
        );
        preimage.extend_from_slice(PREFIX);
        preimage.extend_from_slice(&bytes);

        Sha256::digest(preimage).into()
    }
}

impl InitMessage {
    #[must_use]
    pub fn into_elf(self) -> Vec<u8> {
        self.elf
    }

    #[must_use]
    pub const fn upgrade_auth(&self) -> Option<AccountId> {
        self.upgrade_auth
    }
}

#[cfg(test)]
mod tests {
    use super::{InitMessage, Message};

    #[test]
    fn elf_roundtrip() {
        // `Message::new(b)` must produce an `Init` variant whose elf is exactly `b`. Catches
        // mutations of `into_elf` returning `vec![]`, `vec![0]`, or `vec![1]`.
        let elf = vec![0x7F_u8, 0x45, 0x4C, 0x46]; // ELF magic
        let Message::Init(InitMessage { elf: got, .. }) = Message::new(elf.clone()) else {
            panic!("Message::new must produce an Init variant");
        };
        assert_eq!(got, elf);
    }
}
