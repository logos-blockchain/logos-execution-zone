use anyhow::Result;
use key_protocol::key_management::ephemeral_key_holder::EphemeralKeyHolder;
use nssa::{AccountId, PrivateKey};
use nssa_core::{
    Identifier, InputAccountIdentity, MembershipProof, NullifierPublicKey, NullifierSecretKey,
    SharedSecretKey,
    account::{AccountWithMetadata, Nonce},
    encryption::{EphemeralPublicKey, ViewingPublicKey},
};

use crate::{ExecutionFailureKind, WalletCore};

#[derive(Clone)]
pub enum PrivacyPreservingAccount {
    Public(AccountId),
    PrivateOwned(AccountId),
    PrivateForeign {
        npk: NullifierPublicKey,
        vpk: ViewingPublicKey,
        identifier: Identifier,
    },
}

impl PrivacyPreservingAccount {
    #[must_use]
    pub const fn is_public(&self) -> bool {
        matches!(&self, Self::Public(_))
    }

    #[must_use]
    pub const fn is_private(&self) -> bool {
        matches!(
            &self,
            Self::PrivateOwned(_)
                | Self::PrivateForeign {
                    npk: _,
                    vpk: _,
                    identifier: _,
                }
        )
    }
}

pub struct PrivateAccountKeys {
    pub npk: NullifierPublicKey,
    pub ssk: SharedSecretKey,
    pub vpk: ViewingPublicKey,
    pub epk: EphemeralPublicKey,
}

enum State {
    Public {
        account: AccountWithMetadata,
        sk: Option<PrivateKey>,
    },
    Private(AccountPreparedData),
}

pub struct AccountManager {
    states: Vec<State>,
}

impl AccountManager {
    pub async fn new(
        wallet: &WalletCore,
        accounts: Vec<PrivacyPreservingAccount>,
    ) -> Result<Self, ExecutionFailureKind> {
        let mut states = Vec::with_capacity(accounts.len());

        for account in accounts {
            let state = match account {
                PrivacyPreservingAccount::Public(account_id) => {
                    let acc = wallet
                        .get_account_public(account_id)
                        .await
                        .map_err(ExecutionFailureKind::SequencerError)?;

                    let sk = wallet.get_account_public_signing_key(account_id).cloned();
                    let account = AccountWithMetadata::new(acc.clone(), sk.is_some(), account_id);

                    State::Public { account, sk }
                }
                PrivacyPreservingAccount::PrivateOwned(account_id) => {
                    let pre = private_acc_preparation(wallet, account_id).await?;

                    State::Private(pre)
                }
                PrivacyPreservingAccount::PrivateForeign {
                    npk,
                    vpk,
                    identifier,
                } => {
                    let acc = nssa_core::account::Account::default();
                    let auth_acc = AccountWithMetadata::new(acc, false, (&npk, identifier));
                    let eph_holder = EphemeralKeyHolder::new(&npk);
                    let ssk = eph_holder.calculate_shared_secret_sender(&vpk);
                    let epk = eph_holder.generate_ephemeral_public_key();
                    let pre = AccountPreparedData {
                        nsk: None,
                        npk,
                        identifier,
                        vpk,
                        pre_state: auth_acc,
                        proof: None,
                        ssk,
                        epk,
                    };

                    State::Private(pre)
                }
            };

            states.push(state);
        }

        Ok(Self { states })
    }

    pub fn pre_states(&self) -> Vec<AccountWithMetadata> {
        self.states
            .iter()
            .map(|state| match state {
                State::Public { account, .. } => account.clone(),
                State::Private(pre) => pre.pre_state.clone(),
            })
            .collect()
    }

    pub fn public_account_nonces(&self) -> Vec<Nonce> {
        self.states
            .iter()
            .filter_map(|state| match state {
                State::Public { account, sk } => sk.as_ref().map(|_| account.account.nonce),
                State::Private(_) => None,
            })
            .collect()
    }

    pub fn private_account_keys(&self) -> Vec<PrivateAccountKeys> {
        self.states
            .iter()
            .filter_map(|state| match state {
                State::Private(pre) => Some(PrivateAccountKeys {
                    npk: pre.npk,
                    ssk: pre.ssk,
                    vpk: pre.vpk.clone(),
                    epk: pre.epk.clone(),
                }),
                State::Public { .. } => None,
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
                State::Public { .. } => InputAccountIdentity::Public,
                State::Private(pre) => match (pre.nsk, pre.proof.clone()) {
                    (Some(nsk), Some(membership_proof)) => {
                        InputAccountIdentity::PrivateAuthorizedUpdate {
                            ssk: pre.ssk,
                            nsk,
                            membership_proof,
                            identifier: pre.identifier,
                        }
                    }
                    (Some(nsk), None) => InputAccountIdentity::PrivateAuthorizedInit {
                        ssk: pre.ssk,
                        nsk,
                        identifier: pre.identifier,
                    },
                    (None, _) => InputAccountIdentity::PrivateUnauthorized {
                        npk: pre.npk,
                        ssk: pre.ssk,
                        identifier: pre.identifier,
                    },
                },
            })
            .collect()
    }

    pub fn public_account_ids(&self) -> Vec<AccountId> {
        self.states
            .iter()
            .filter_map(|state| match state {
                State::Public { account, .. } => Some(account.account_id),
                State::Private(_) => None,
            })
            .collect()
    }

    pub fn public_account_auth(&self) -> Vec<&PrivateKey> {
        self.states
            .iter()
            .filter_map(|state| match state {
                State::Public { sk, .. } => sk.as_ref(),
                State::Private(_) => None,
            })
            .collect()
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
}

async fn private_acc_preparation(
    wallet: &WalletCore,
    account_id: AccountId,
) -> Result<AccountPreparedData, ExecutionFailureKind> {
    let Some((from_keys, from_acc, from_identifier)) =
        wallet.storage.user_data.get_private_account(account_id)
    else {
        return Err(ExecutionFailureKind::KeyNotFoundError);
    };

    let nsk = from_keys.private_key_holder.nullifier_secret_key;

    let from_npk = from_keys.nullifier_public_key;
    let from_vpk = from_keys.viewing_public_key;

    // TODO: Remove this unwrap, error types must be compatible
    let proof = wallet
        .check_private_account_initialized(account_id)
        .await
        .unwrap();

    // TODO: Technically we could allow unauthorized owned accounts, but currently we don't have
    // support from that in the wallet.
    let sender_pre = AccountWithMetadata::new(from_acc.clone(), true, (&from_npk, from_identifier));

    let eph_holder = EphemeralKeyHolder::new(&from_npk);
    let ssk = eph_holder.calculate_shared_secret_sender(&from_vpk);
    let epk = eph_holder.generate_ephemeral_public_key();

    Ok(AccountPreparedData {
        nsk: Some(nsk),
        npk: from_npk,
        identifier: from_identifier,
        vpk: from_vpk,
        pre_state: sender_pre,
        proof,
        ssk,
        epk,
    })
}
