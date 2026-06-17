use core::fmt;

use anyhow::Result;
use key_protocol::key_management::ephemeral_key_holder::EphemeralKeyHolder;
use keycard_wallet::{KeycardWallet, python_path};
use lee::{AccountId, PrivateKey, PublicKey, Signature};
use lee_core::{
    CommitmentSetDigest, DUMMY_COMMITMENT_HASH, Identifier, InputAccountIdentity, MembershipProof,
    NullifierPublicKey, NullifierSecretKey, SharedSecretKey,
    account::{AccountWithMetadata, Nonce},
    encryption::{EncryptedAccountData, EphemeralPublicKey, ViewingPublicKey},
};

use crate::{ExecutionFailureKind, WalletCore};

#[derive(Clone, PartialEq, Eq)]
pub enum AccountIdentity {
    Public(AccountId),
    /// A public account without signing. Would not try to sign, even if account is owned.
    PublicNoSign(AccountId),
    /// A public account from keycard. Mandatory signing.
    PublicKeycard {
        account_id: AccountId,
        key_path: String,
    },
    PrivateOwned(AccountId),
    PrivateForeign {
        npk: NullifierPublicKey,
        vpk: ViewingPublicKey,
        identifier: Identifier,
    },
    /// An owned private PDA: wallet holds the nsk/npk; `account_id` was derived via
    /// [`AccountId::for_private_pda`].
    PrivatePdaOwned(AccountId),
    /// A foreign private PDA: wallet knows the recipient's npk/vpk but not their nsk.
    /// Uses a default (uninitialised) account.
    PrivatePdaForeign {
        account_id: AccountId,
        npk: NullifierPublicKey,
        vpk: ViewingPublicKey,
        identifier: Identifier,
    },
    /// A shared regular private account with externally-provided keys (e.g. from GMS).
    /// Uses standard `AccountId = from((&npk, identifier))` with authorized/unauthorized private
    /// paths. Works with `authenticated_transfer` and all existing programs out of the box.
    PrivateShared {
        nsk: NullifierSecretKey,
        npk: NullifierPublicKey,
        vpk: ViewingPublicKey,
        identifier: Identifier,
    },
    /// A shared private PDA with externally-provided keys (e.g. from GMS).
    /// `account_id` was derived via [`AccountId::for_private_pda`].
    PrivatePdaShared {
        account_id: AccountId,
        nsk: NullifierSecretKey,
        npk: NullifierPublicKey,
        vpk: ViewingPublicKey,
        identifier: Identifier,
    },
}

impl fmt::Debug for AccountIdentity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Public(id) => f.debug_tuple("Public").field(id).finish(),
            Self::PublicNoSign(id) => f.debug_tuple("PublicNoSign").field(id).finish(),
            Self::PublicKeycard {
                account_id,
                key_path: _,
            } => f
                .debug_struct("PublicKeycard")
                .field("account_id", account_id)
                .field("key_path", &"<redacted>")
                .finish(),
            Self::PrivateOwned(id) => f.debug_tuple("PrivateOwned").field(id).finish(),
            Self::PrivateForeign {
                npk,
                vpk,
                identifier,
            } => f
                .debug_struct("PrivateForeign")
                .field("npk", npk)
                .field("vpk", vpk)
                .field("identifier", identifier)
                .finish(),
            Self::PrivatePdaOwned(id) => f.debug_tuple("PrivatePdaOwned").field(id).finish(),
            Self::PrivatePdaForeign {
                account_id,
                npk,
                vpk,
                identifier,
            } => f
                .debug_struct("PrivatePdaForeign")
                .field("account_id", account_id)
                .field("npk", npk)
                .field("vpk", vpk)
                .field("identifier", identifier)
                .finish(),
            Self::PrivateShared {
                npk,
                vpk,
                identifier,
                ..
            } => f
                .debug_struct("PrivateShared")
                .field("nsk", &"<redacted>")
                .field("npk", npk)
                .field("vpk", vpk)
                .field("identifier", identifier)
                .finish(),
            Self::PrivatePdaShared {
                account_id,
                npk,
                vpk,
                identifier,
                ..
            } => f
                .debug_struct("PrivatePdaShared")
                .field("account_id", account_id)
                .field("nsk", &"<redacted>")
                .field("npk", npk)
                .field("vpk", vpk)
                .field("identifier", identifier)
                .finish(),
        }
    }
}

impl AccountIdentity {
    #[must_use]
    /// Note: `PublicNoSign` still counts as public, the variant just suppresses the signing-key
    /// lookup.
    pub const fn is_public(&self) -> bool {
        matches!(
            &self,
            Self::Public(_) | Self::PublicNoSign(_) | Self::PublicKeycard { .. }
        )
    }

    /// Returns the `AccountId` for public variants. Used by facades that need the raw ID
    /// for derived-address computation alongside the identity.
    #[must_use]
    pub const fn public_account_id(&self) -> Option<lee::AccountId> {
        match self {
            Self::Public(id) | Self::PublicNoSign(id) => Some(*id),
            Self::PublicKeycard { account_id, .. } => Some(*account_id),
            Self::PrivateOwned(_)
            | Self::PrivateForeign { .. }
            | Self::PrivatePdaOwned(_)
            | Self::PrivatePdaForeign { .. }
            | Self::PrivateShared { .. }
            | Self::PrivatePdaShared { .. } => None,
        }
    }

    #[must_use]
    pub const fn is_private(&self) -> bool {
        matches!(
            &self,
            Self::PrivateOwned(_)
                | Self::PrivateForeign { .. }
                | Self::PrivatePdaOwned(_)
                | Self::PrivatePdaForeign { .. }
                | Self::PrivateShared { .. }
                | Self::PrivatePdaShared { .. }
        )
    }
}

pub struct PrivateAccountKeys {
    pub ssk: SharedSecretKey,
}

enum State {
    Public {
        account: AccountWithMetadata,
        sk: Option<PrivateKey>,
    },
    PublicKeycard {
        account: AccountWithMetadata,
        key_path: String,
    },
    Private(AccountPreparedData),
}

pub struct AccountManager {
    states: Vec<State>,
    pin: Option<String>,
    dummy_commitment_root: CommitmentSetDigest,
}

impl AccountManager {
    pub async fn new(
        wallet: &WalletCore,
        accounts: Vec<AccountIdentity>,
    ) -> Result<Self, ExecutionFailureKind> {
        let mut states = Vec::with_capacity(accounts.len());
        let mut pin = None;

        for account in accounts {
            let state = match account {
                AccountIdentity::Public(account_id) => {
                    prepare_public_state(wallet, account_id, true).await?
                }
                AccountIdentity::PublicNoSign(account_id) => {
                    prepare_public_state(wallet, account_id, false).await?
                }
                AccountIdentity::PublicKeycard {
                    account_id,
                    key_path,
                } => {
                    if pin.is_none() {
                        pin = Some(
                            crate::helperfunctions::read_pin()
                                .map_err(|e| {
                                    ExecutionFailureKind::KeycardError(pyo3::PyErr::new::<
                                        pyo3::exceptions::PyRuntimeError,
                                        _,
                                    >(
                                        e.to_string()
                                    ))
                                })?
                                .as_str()
                                .to_owned(),
                        );
                    }
                    prepare_public_keycard_state(wallet, account_id, key_path).await?
                }
                AccountIdentity::PrivateOwned(account_id) => State::Private(
                    private_key_tree_acc_preparation(wallet, account_id, false).await?,
                ),
                AccountIdentity::PrivateForeign {
                    npk,
                    vpk,
                    identifier,
                } => State::Private(private_foreign_acc_preparation(npk, vpk, identifier)),
                AccountIdentity::PrivatePdaOwned(account_id) => State::Private(
                    private_key_tree_acc_preparation(wallet, account_id, true).await?,
                ),
                AccountIdentity::PrivatePdaForeign {
                    account_id,
                    npk,
                    vpk,
                    identifier,
                } => State::Private(private_pda_foreign_acc_preparation(
                    account_id, npk, vpk, identifier,
                )),
                AccountIdentity::PrivateShared {
                    nsk,
                    npk,
                    vpk,
                    identifier,
                } => {
                    let account_id = lee::AccountId::from((&npk, identifier));
                    State::Private(
                        private_shared_acc_preparation(
                            wallet, account_id, nsk, npk, vpk, identifier, false,
                        )
                        .await?,
                    )
                }
                AccountIdentity::PrivatePdaShared {
                    account_id,
                    nsk,
                    npk,
                    vpk,
                    identifier,
                } => State::Private(
                    private_shared_acc_preparation(
                        wallet, account_id, nsk, npk, vpk, identifier, true,
                    )
                    .await?,
                ),
            };

            states.push(state);
        }

        let has_init_account = states
            .iter()
            .any(|s| matches!(s, State::Private(pre) if pre.proof.is_none()));
        let dummy_commitment_root = if has_init_account {
            wallet
                .get_commitment_root()
                .await
                .map_err(ExecutionFailureKind::SequencerError)?
                .unwrap_or(DUMMY_COMMITMENT_HASH)
        } else {
            DUMMY_COMMITMENT_HASH
        };

        Ok(Self {
            states,
            pin,
            dummy_commitment_root,
        })
    }

    pub fn pre_states(&self) -> Vec<AccountWithMetadata> {
        self.states
            .iter()
            .map(|state| match state {
                State::Public { account, .. } | State::PublicKeycard { account, .. } => {
                    account.clone()
                }
                State::Private(pre) => pre.pre_state.clone(),
            })
            .collect()
    }

    pub fn public_account_nonces(&self) -> Vec<Nonce> {
        // Must match the signature order produced by sign_message(): local accounts first,
        // keycard accounts second.
        let local = self.states.iter().filter_map(|state| match state {
            State::Public { account, sk } => sk.as_ref().map(|_| account.account.nonce),
            State::PublicKeycard { .. } | State::Private(_) => None,
        });
        let keycard = self.states.iter().filter_map(|state| match state {
            State::PublicKeycard { account, .. } => Some(account.account.nonce),
            State::Public { .. } | State::Private(_) => None,
        });
        local.chain(keycard).collect()
    }

    pub fn private_account_keys(&self) -> Vec<PrivateAccountKeys> {
        self.states
            .iter()
            .filter_map(|state| match state {
                State::Private(pre) => Some(PrivateAccountKeys { ssk: pre.ssk }),
                State::Public { .. } | State::PublicKeycard { .. } => None,
            })
            .collect()
    }

    /// Build the per-account input vec for the privacy-preserving circuit. Each variant carries
    /// exactly the fields the circuit's code path for that account needs, with the ephemeral
    /// keys (`ssk`) drawn from the cached values that `private_account_keys` and the message
    /// construction also use, so all three views agree on the same ephemeral key.
    pub fn account_identities(&self) -> Vec<InputAccountIdentity> {
        self.states
            .iter()
            .map(|state| match state {
                State::Public { .. } | State::PublicKeycard { .. } => InputAccountIdentity::Public,
                State::Private(pre) if pre.is_pda => match (pre.nsk, pre.proof.clone()) {
                    (Some(nsk), Some(membership_proof)) => InputAccountIdentity::PrivatePdaUpdate {
                        epk: pre.epk.clone(),
                        view_tag: EncryptedAccountData::compute_view_tag(&pre.npk, &pre.vpk),
                        ssk: pre.ssk,
                        nsk,
                        membership_proof,
                        identifier: pre.identifier,
                        seed: None,
                    },
                    _ => InputAccountIdentity::PrivatePdaInit {
                        epk: pre.epk.clone(),
                        view_tag: EncryptedAccountData::compute_view_tag(&pre.npk, &pre.vpk),
                        npk: pre.npk,
                        ssk: pre.ssk,
                        identifier: pre.identifier,
                        commitment_root: self.dummy_commitment_root,
                        seed: None,
                    },
                },
                State::Private(pre) => match (pre.nsk, pre.proof.clone()) {
                    (Some(nsk), Some(membership_proof)) => {
                        InputAccountIdentity::PrivateAuthorizedUpdate {
                            epk: pre.epk.clone(),
                            view_tag: EncryptedAccountData::compute_view_tag(&pre.npk, &pre.vpk),
                            ssk: pre.ssk,
                            nsk,
                            membership_proof,
                            identifier: pre.identifier,
                        }
                    }
                    (Some(nsk), None) => InputAccountIdentity::PrivateAuthorizedInit {
                        epk: pre.epk.clone(),
                        view_tag: EncryptedAccountData::compute_view_tag(&pre.npk, &pre.vpk),
                        ssk: pre.ssk,
                        nsk,
                        identifier: pre.identifier,
                        commitment_root: self.dummy_commitment_root,
                    },
                    (None, _) => InputAccountIdentity::PrivateUnauthorized {
                        epk: pre.epk.clone(),
                        view_tag: EncryptedAccountData::compute_view_tag(&pre.npk, &pre.vpk),
                        npk: pre.npk,
                        ssk: pre.ssk,
                        identifier: pre.identifier,
                        commitment_root: self.dummy_commitment_root,
                    },
                },
            })
            .collect()
    }

    pub fn public_account_ids(&self) -> Vec<AccountId> {
        self.states
            .iter()
            .filter_map(|state| match state {
                State::Public { account, .. } | State::PublicKeycard { account, .. } => {
                    Some(account.account_id)
                }
                State::Private(_) => None,
            })
            .collect()
    }

    pub fn public_non_keycard_account_auth(&self) -> Vec<&PrivateKey> {
        self.states
            .iter()
            .filter_map(|state| match state {
                State::Public { sk, .. } => sk.as_ref(),
                State::PublicKeycard { .. } | State::Private(_) => None,
            })
            .collect()
    }

    pub fn sign_message(&self, message_hash: [u8; 32]) -> Result<Vec<(Signature, PublicKey)>> {
        let mut sigs: Vec<(Signature, PublicKey)> = self
            .public_non_keycard_account_auth()
            .into_iter()
            .map(|key| {
                (
                    Signature::new(key, &message_hash),
                    PublicKey::new_from_private_key(key),
                )
            })
            .collect();

        let keycard_paths: Vec<&str> = self
            .states
            .iter()
            .filter_map(|state| match state {
                State::PublicKeycard { key_path, .. } => Some(key_path.as_str()),
                State::Private(_) | State::Public { .. } => None,
            })
            .collect();

        if let Some(pin) = self.pin.clone() {
            pyo3::Python::attach(|py| -> pyo3::PyResult<()> {
                python_path::add_python_path(py)?;
                let wallet = KeycardWallet::new(py)?;
                wallet.connect(py, &pin)?;
                for path in keycard_paths {
                    sigs.push(wallet.sign_message_for_path(py, path, &message_hash)?);
                }
                let _res = wallet.close_session(py);
                Ok(())
            })
            .map_err(anyhow::Error::from)?;
        }

        Ok(sigs)
    }
}

struct AccountPreparedData {
    nsk: Option<NullifierSecretKey>,
    npk: NullifierPublicKey,
    identifier: Identifier,
    vpk: ViewingPublicKey,
    pre_state: AccountWithMetadata,
    proof: Option<MembershipProof>,
    /// Cached shared-secret key derived once at `AccountManager::new`. Reused for both the
    /// circuit input variant (`account_identities()`) and the message ephemeral-key tuples
    /// (`private_account_keys()`), so all consumers see the same key. The corresponding
    /// `EphemeralKeyHolder` uses `OsRng` and would produce a different value on a second call.
    ssk: SharedSecretKey,
    /// Cached ephemeral public key, paired with `ssk`.
    epk: EphemeralPublicKey,
    /// True when this account is a private PDA (owned or foreign). Used by `account_identities()`
    /// to select `PrivatePdaInit`/`PrivatePdaUpdate` rather than the standalone private variants.
    is_pda: bool,
}

async fn prepare_public_state(
    wallet: &WalletCore,
    account_id: AccountId,
    lookup_signing_key: bool,
) -> Result<State, ExecutionFailureKind> {
    let acc = wallet
        .get_account_public(account_id)
        .await
        .map_err(ExecutionFailureKind::SequencerError)?;
    let sk = if lookup_signing_key {
        wallet.get_account_public_signing_key(account_id).cloned()
    } else {
        None
    };
    let account = AccountWithMetadata::new(acc, sk.is_some(), account_id);
    Ok(State::Public { account, sk })
}

async fn prepare_public_keycard_state(
    wallet: &WalletCore,
    account_id: AccountId,
    key_path: String,
) -> Result<State, ExecutionFailureKind> {
    let acc = wallet
        .get_account_public(account_id)
        .await
        .map_err(ExecutionFailureKind::SequencerError)?;
    let account = AccountWithMetadata::new(acc, true, account_id);
    Ok(State::PublicKeycard { account, key_path })
}

async fn private_key_tree_acc_preparation(
    wallet: &WalletCore,
    account_id: AccountId,
    is_pda: bool,
) -> Result<AccountPreparedData, ExecutionFailureKind> {
    let Some(from_acc) = wallet.storage.key_chain().private_account(account_id) else {
        return Err(ExecutionFailureKind::KeyNotFoundError);
    };

    let from_identifier = from_acc.kind.identifier();
    let from_keys = &from_acc.key_chain;
    let nsk = from_keys.private_key_holder.nullifier_secret_key;
    let from_npk = from_keys.nullifier_public_key;
    let from_vpk = from_keys.viewing_public_key.clone();

    // TODO: Remove this unwrap, error types must be compatible
    let proof = wallet
        .check_private_account_initialized(account_id)
        .await
        .unwrap();

    // TODO: Technically we could allow unauthorized owned accounts, but currently we don't have
    // support from that in the wallet.
    let sender_pre = AccountWithMetadata::new(from_acc.account.clone(), true, account_id);

    let eph_holder = EphemeralKeyHolder::new(&from_vpk);
    let ssk = eph_holder.calculate_shared_secret_sender();
    let epk = eph_holder.ephemeral_public_key().clone();

    Ok(AccountPreparedData {
        nsk: Some(nsk),
        npk: from_npk,
        identifier: from_identifier,
        vpk: from_vpk,
        pre_state: sender_pre,
        proof,
        ssk,
        epk,
        is_pda,
    })
}

async fn private_shared_acc_preparation(
    wallet: &WalletCore,
    account_id: AccountId,
    nsk: NullifierSecretKey,
    npk: NullifierPublicKey,
    vpk: ViewingPublicKey,
    identifier: Identifier,
    is_pda: bool,
) -> Result<AccountPreparedData, ExecutionFailureKind> {
    let acc = wallet
        .storage()
        .key_chain()
        .shared_private_account(account_id)
        .map(|e| e.account.clone())
        .unwrap_or_default();

    let pre_state = AccountWithMetadata::new(acc, true, account_id);

    let proof = wallet
        .check_private_account_initialized(account_id)
        .await
        .unwrap_or(None);

    let eph_holder = EphemeralKeyHolder::new(&vpk);
    let ssk = eph_holder.calculate_shared_secret_sender();
    let epk = eph_holder.ephemeral_public_key().clone();

    Ok(AccountPreparedData {
        nsk: Some(nsk),
        npk,
        identifier,
        vpk,
        pre_state,
        proof,
        ssk,
        epk,
        is_pda,
    })
}

fn private_foreign_acc_preparation(
    npk: NullifierPublicKey,
    vpk: ViewingPublicKey,
    identifier: Identifier,
) -> AccountPreparedData {
    let acc = lee_core::account::Account::default();
    let pre_state = AccountWithMetadata::new(acc, false, (&npk, identifier));
    let eph_holder = EphemeralKeyHolder::new(&vpk);
    let ssk = eph_holder.calculate_shared_secret_sender();
    let epk = eph_holder.ephemeral_public_key().clone();

    AccountPreparedData {
        nsk: None,
        npk,
        identifier,
        vpk,
        pre_state,
        proof: None,
        ssk,
        epk,
        is_pda: false,
    }
}

fn private_pda_foreign_acc_preparation(
    account_id: AccountId,
    npk: NullifierPublicKey,
    vpk: ViewingPublicKey,
    identifier: Identifier,
) -> AccountPreparedData {
    let acc = lee_core::account::Account::default();
    let pre_state = AccountWithMetadata::new(acc, false, account_id);
    let eph_holder = EphemeralKeyHolder::new(&vpk);
    let ssk = eph_holder.calculate_shared_secret_sender();
    let epk = eph_holder.ephemeral_public_key().clone();

    AccountPreparedData {
        nsk: None,
        npk,
        identifier,
        vpk,
        pre_state,
        proof: None,
        ssk,
        epk,
        is_pda: true,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn private_shared_is_private() {
        let acc = AccountIdentity::PrivateShared {
            nsk: [0; 32],
            npk: NullifierPublicKey([1; 32]),
            vpk: ViewingPublicKey::from_seed(&[2_u8; 32], &[3_u8; 32]),
            identifier: 42,
        };
        assert!(acc.is_private());
        assert!(!acc.is_public());
    }
}
