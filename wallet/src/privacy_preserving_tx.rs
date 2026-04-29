use anyhow::Result;
use key_protocol::key_management::ephemeral_key_holder::EphemeralKeyHolder;
use nssa::{AccountId, PrivateKey};
use nssa_core::{
    MembershipProof, NullifierPublicKey, NullifierSecretKey, SharedSecretKey,
    account::{AccountWithMetadata, Nonce},
    encryption::{EphemeralPublicKey, ViewingPublicKey},
    program::{PdaSeed, ProgramId},
};

use crate::{ExecutionFailureKind, WalletCore};

#[derive(Clone)]
pub enum PrivacyPreservingAccount {
    Public(AccountId),
    PrivateOwned(AccountId),
    PrivateForeign {
        npk: NullifierPublicKey,
        vpk: ViewingPublicKey,
    },
    /// A private PDA owned by a group. The wallet derives keys from the
    /// `GroupKeyHolder` stored under `group_label`, then computes the
    /// `AccountId` via `AccountId::for_private_pda(program_id, seed, npk)`.
    PrivateGroupPda {
        group_label: String,
        program_id: ProgramId,
        seed: PdaSeed,
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
                | Self::PrivateForeign { npk: _, vpk: _ }
                | Self::PrivateGroupPda { .. }
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
    visibility_mask: Vec<u8>,
}

impl AccountManager {
    pub async fn new(
        wallet: &WalletCore,
        accounts: Vec<PrivacyPreservingAccount>,
    ) -> Result<Self, ExecutionFailureKind> {
        let mut pre_states = Vec::with_capacity(accounts.len());
        let mut visibility_mask = Vec::with_capacity(accounts.len());

        for account in accounts {
            let (state, mask) = match account {
                PrivacyPreservingAccount::Public(account_id) => {
                    let acc = wallet
                        .get_account_public(account_id)
                        .await
                        .map_err(ExecutionFailureKind::SequencerError)?;

                    let sk = wallet.get_account_public_signing_key(account_id).cloned();
                    let account = AccountWithMetadata::new(acc.clone(), sk.is_some(), account_id);

                    (State::Public { account, sk }, 0)
                }
                PrivacyPreservingAccount::PrivateOwned(account_id) => {
                    let pre = private_acc_preparation(wallet, account_id).await?;
                    let mask = if pre.pre_state.is_authorized { 1 } else { 2 };

                    (State::Private(pre), mask)
                }
                PrivacyPreservingAccount::PrivateForeign { npk, vpk } => {
                    let acc = nssa_core::account::Account::default();
                    let auth_acc = AccountWithMetadata::new(acc, false, &npk);
                    let pre = AccountPreparedData {
                        nsk: None,
                        npk,
                        vpk,
                        pre_state: auth_acc,
                        proof: None,
                    };

                    (State::Private(pre), 2)
                }
                PrivacyPreservingAccount::PrivateGroupPda {
                    group_label,
                    program_id,
                    seed,
                } => {
                    let pre =
                        group_pda_preparation(wallet, &group_label, &program_id, &seed).await?;

                    (State::Private(pre), 3)
                }
            };

            pre_states.push(state);
            visibility_mask.push(mask);
        }

        Ok(Self {
            states: pre_states,
            visibility_mask,
        })
    }

    #[must_use]
    pub fn pre_states(&self) -> Vec<AccountWithMetadata> {
        self.states
            .iter()
            .map(|state| match state {
                State::Public { account, .. } => account.clone(),
                State::Private(pre) => pre.pre_state.clone(),
            })
            .collect()
    }

    #[must_use]
    pub fn visibility_mask(&self) -> &[u8] {
        &self.visibility_mask
    }

    #[must_use]
    pub fn public_account_nonces(&self) -> Vec<Nonce> {
        self.states
            .iter()
            .filter_map(|state| match state {
                State::Public { account, sk } => sk.as_ref().map(|_| account.account.nonce),
                State::Private(_) => None,
            })
            .collect()
    }

    #[must_use]
    pub fn private_account_keys(&self) -> Vec<PrivateAccountKeys> {
        self.states
            .iter()
            .filter_map(|state| match state {
                State::Private(pre) => {
                    let eph_holder = EphemeralKeyHolder::new(&pre.npk);

                    Some(PrivateAccountKeys {
                        npk: pre.npk,
                        ssk: eph_holder.calculate_shared_secret_sender(&pre.vpk),
                        vpk: pre.vpk.clone(),
                        epk: eph_holder.generate_ephemeral_public_key(),
                    })
                }
                State::Public { .. } => None,
            })
            .collect()
    }

    #[must_use]
    pub fn private_account_auth(&self) -> Vec<NullifierSecretKey> {
        self.states
            .iter()
            .filter_map(|state| match state {
                State::Private(pre) => pre.nsk,
                State::Public { .. } => None,
            })
            .collect()
    }

    #[must_use]
    pub fn private_account_membership_proofs(&self) -> Vec<Option<MembershipProof>> {
        self.states
            .iter()
            .filter_map(|state| match state {
                State::Private(pre) => Some(pre.proof.clone()),
                State::Public { .. } => None,
            })
            .collect()
    }

    #[must_use]
    pub fn public_account_ids(&self) -> Vec<AccountId> {
        self.states
            .iter()
            .filter_map(|state| match state {
                State::Public { account, .. } => Some(account.account_id),
                State::Private(_) => None,
            })
            .collect()
    }

    #[must_use]
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
    vpk: ViewingPublicKey,
    pre_state: AccountWithMetadata,
    proof: Option<MembershipProof>,
}

async fn group_pda_preparation(
    wallet: &WalletCore,
    group_label: &str,
    program_id: &ProgramId,
    seed: &PdaSeed,
) -> Result<AccountPreparedData, ExecutionFailureKind> {
    let holder = wallet
        .storage
        .user_data
        .group_key_holder(group_label)
        .ok_or(ExecutionFailureKind::KeyNotFoundError)?;

    let keys = holder.derive_keys_for_pda(seed);
    let npk = keys.generate_nullifier_public_key();
    let vpk = keys.generate_viewing_public_key();
    let nsk = keys.nullifier_secret_key;
    let account_id = nssa::AccountId::for_private_pda(program_id, seed, &npk);

    // Check local cache first (private PDA state is encrypted on-chain, the sequencer
    // only stores commitments). Fall back to default for new PDAs.
    let acc = wallet
        .storage
        .user_data
        .group_pda_accounts
        .get(&account_id)
        .cloned()
        .unwrap_or_default();

    let exists = acc != nssa_core::account::Account::default();

    // is_authorized tracks whether the account existed on-chain before this tx.
    // NSK is only provided for existing accounts: the circuit consumes NSKs sequentially
    // from an iterator and asserts none are left over, so supplying an NSK for a new
    // (unauthorized) account would trigger the over-supply assertion. This matches the
    // PrivateForeign path (nsk: None for unauthorized accounts).
    let pre_state = AccountWithMetadata::new(acc, exists, account_id);

    let proof = if exists {
        wallet
            .check_private_account_initialized(account_id)
            .await
            .unwrap_or(None)
    } else {
        None
    };

    Ok(AccountPreparedData {
        nsk: exists.then_some(nsk),
        npk,
        vpk,
        pre_state,
        proof,
    })
}

async fn private_acc_preparation(
    wallet: &WalletCore,
    account_id: AccountId,
) -> Result<AccountPreparedData, ExecutionFailureKind> {
    let Some((from_keys, from_acc)) = wallet
        .storage
        .user_data
        .get_private_account(account_id)
        .cloned()
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
    let sender_pre = AccountWithMetadata::new(from_acc.clone(), true, &from_npk);

    Ok(AccountPreparedData {
        nsk: Some(nsk),
        npk: from_npk,
        vpk: from_vpk,
        pre_state: sender_pre,
        proof,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn private_group_pda_is_private() {
        let acc = PrivacyPreservingAccount::PrivateGroupPda {
            group_label: String::from("test"),
            program_id: [1; 8],
            seed: PdaSeed::new([2; 32]),
        };
        assert!(acc.is_private());
        assert!(!acc.is_public());
    }
}
