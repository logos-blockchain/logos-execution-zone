use core::fmt;

use anyhow::Result;
use keycard_wallet::{KeycardWallet, python_path};
use lee::{AccountId, PrivateKey, PublicKey, Signature};
use lee_core::{
    AuthorizationSecretKey, Commitment, CommitmentSetDigest, Identifier, MembershipProof,
    NullifierPublicKey, NullifierSecretKey, NullifierWitness, PrivateAccountKind, PrivateKind,
    PrivateWitness, SharedSecretKey,
    account::{AccountWithMetadata, Nonce},
    compute_digest_for_path, derive_nullifier_secret_key,
    encryption::ViewingPublicKey,
    program::{PdaSeed, ProgramId},
};
use rand::{RngCore as _, rngs::OsRng};

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
        seed: (PdaSeed, ProgramId),
    },
    /// A shared regular private account with externally-provided keys (e.g. from GMS).
    PrivateShared {
        ask: AuthorizationSecretKey,
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
        seed: (PdaSeed, ProgramId),
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
                seed,
            } => f
                .debug_struct("PrivatePdaForeign")
                .field("account_id", account_id)
                .field("npk", npk)
                .field("vpk", vpk)
                .field("identifier", identifier)
                .field("seed", seed)
                .finish(),
            Self::PrivateShared {
                vpk, identifier, ..
            } => f
                .debug_struct("PrivateShared")
                .field("ask", &"<redacted>")
                .field("vpk", vpk)
                .field("identifier", identifier)
                .finish(),
            Self::PrivatePdaShared {
                account_id,
                npk,
                vpk,
                identifier,
                seed,
                ..
            } => f
                .debug_struct("PrivatePdaShared")
                .field("account_id", account_id)
                .field("nsk", &"<redacted>")
                .field("npk", npk)
                .field("vpk", vpk)
                .field("identifier", identifier)
                .field("seed", seed)
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
    Private(Box<AccountPreparedData>),
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
                    let acc = wallet
                        .get_account_public(account_id)
                        .await
                        .map_err(ExecutionFailureKind::SequencerError)?;

                    let sk = wallet.get_account_public_signing_key(account_id).cloned();
                    let account = AccountWithMetadata::new(acc.clone(), sk.is_some(), account_id);

                    State::Public { account, sk }
                }
                AccountIdentity::PublicNoSign(account_id) => {
                    let acc = wallet
                        .get_account_public(account_id)
                        .await
                        .map_err(ExecutionFailureKind::SequencerError)?;

                    let sk = None;
                    let account = AccountWithMetadata::new(acc.clone(), sk.is_some(), account_id);

                    State::Public { account, sk }
                }
                AccountIdentity::PublicKeycard {
                    account_id,
                    key_path,
                } => {
                    let acc = wallet
                        .get_account_public(account_id)
                        .await
                        .map_err(ExecutionFailureKind::SequencerError)?;

                    let account = AccountWithMetadata::new(acc.clone(), true, account_id);

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

                    State::PublicKeycard { account, key_path }
                }
                AccountIdentity::PrivateOwned(account_id)
                | AccountIdentity::PrivatePdaOwned(account_id) => {
                    let pre = private_key_tree_acc_preparation(wallet, account_id)?;

                    State::Private(Box::new(pre))
                }
                AccountIdentity::PrivateForeign {
                    npk,
                    vpk,
                    identifier,
                } => {
                    let acc = lee_core::account::Account::default();
                    let account_id = AccountId::for_regular_private_account(&npk, &vpk, identifier);
                    let kind = PrivateKind::Regular { ask: None };
                    let auth_acc = AccountWithMetadata::new(acc, is_authorized(&kind), account_id);
                    let mut random_seed: [u8; 32] = [0; 32];
                    OsRng.fill_bytes(&mut random_seed);
                    let pre = AccountPreparedData {
                        nullifier: PreparedNullifier::Foreign,
                        npk,
                        kind,
                        identifier,
                        vpk,
                        pre_state: auth_acc,
                        random_seed,
                    };

                    State::Private(Box::new(pre))
                }
                AccountIdentity::PrivatePdaForeign {
                    account_id,
                    npk,
                    vpk,
                    identifier,
                    seed,
                } => {
                    let acc = lee_core::account::Account::default();
                    let kind = PrivateKind::Pda { seed };
                    let auth_acc = AccountWithMetadata::new(acc, is_authorized(&kind), account_id);
                    let mut random_seed: [u8; 32] = [0; 32];
                    OsRng.fill_bytes(&mut random_seed);
                    let pre = AccountPreparedData {
                        nullifier: PreparedNullifier::Foreign,
                        npk,
                        kind,
                        identifier,
                        vpk,
                        pre_state: auth_acc,
                        random_seed,
                    };
                    State::Private(Box::new(pre))
                }
                AccountIdentity::PrivateShared {
                    ask,
                    vpk,
                    identifier,
                } => {
                    let nsk = derive_nullifier_secret_key(&ask);
                    let npk = NullifierPublicKey::from(&nsk);
                    let account_id = AccountId::for_regular_private_account(&npk, &vpk, identifier);
                    let pre = private_shared_acc_preparation(
                        wallet,
                        account_id,
                        nsk,
                        npk,
                        vpk,
                        identifier,
                        PrivateKind::Regular { ask: Some(ask) },
                    );

                    State::Private(Box::new(pre))
                }
                AccountIdentity::PrivatePdaShared {
                    account_id,
                    nsk,
                    npk,
                    vpk,
                    identifier,
                    seed,
                } => {
                    let pre = private_shared_acc_preparation(
                        wallet,
                        account_id,
                        nsk,
                        npk,
                        vpk,
                        identifier,
                        PrivateKind::Pda { seed },
                    );

                    State::Private(Box::new(pre))
                }
            };

            states.push(state);
        }

        let dummy_commitment_root = fetch_private_proofs_and_root(wallet, &mut states).await?;

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
                State::Private(pre) => Some(pre),
                State::Public { .. } | State::PublicKeycard { .. } => None,
            })
            .map(|pre| {
                let nonce = match &pre.nullifier {
                    PreparedNullifier::Owned {
                        nsk,
                        proof: Some(_),
                    } => pre
                        .pre_state
                        .account
                        .nonce
                        .private_account_nonce_increment(nsk),
                    PreparedNullifier::Owned { proof: None, .. } | PreparedNullifier::Foreign => {
                        lee_core::account::Nonce::private_account_nonce_init(
                            &pre.pre_state.account_id,
                        )
                    }
                };
                let esk = lee_core::EphemeralSecretKey::new(
                    &pre.pre_state.account_id,
                    &pre.random_seed,
                    &nonce,
                );
                PrivateAccountKeys {
                    ssk: SharedSecretKey::encapsulate_deterministic(&pre.vpk, &esk).0,
                }
            })
            .collect()
    }

    /// Build the witness row for every private account. Public accounts contribute no row —
    /// that absence is what declares them public. Each row carries exactly the fields the
    /// circuit's code path for that account needs, with the ephemeral keys (`ssk`) drawn from
    /// the cached values that `private_account_keys` and the message construction also use, so
    /// all three views agree on the same ephemeral key. Order is irrelevant: the circuit keys
    /// rows by the `AccountId` each one derives.
    pub fn private_rows(&self) -> Vec<PrivateWitness> {
        self.states
            .iter()
            .filter_map(|state| match state {
                State::Public { .. } | State::PublicKeycard { .. } => None,
                State::Private(pre) => Some(pre),
            })
            .map(|pre| {
                let nullifier = match &pre.nullifier {
                    PreparedNullifier::Owned {
                        nsk,
                        proof: Some(membership_proof),
                    } => NullifierWitness::Update {
                        nsk: *nsk,
                        membership_proof: membership_proof.clone(),
                        pre_account: pre.pre_state.account.clone(),
                    },
                    PreparedNullifier::Owned { proof: None, .. } | PreparedNullifier::Foreign => {
                        NullifierWitness::Init {
                            npk: pre.npk,
                            commitment_root: self.dummy_commitment_root,
                        }
                    }
                };
                PrivateWitness {
                    vpk: pre.vpk.clone(),
                    random_seed: pre.random_seed,
                    identifier: pre.identifier,
                    kind: pre.kind.clone(),
                    nullifier,
                }
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

/// What the wallet knows about consuming an account at preparation time: whether it holds the
/// spend key. Init-vs-update is *not* known here — it is decided later by
/// [`fetch_private_proofs_and_root`], since a fresh owned account has no commitment in the tree
/// yet. Keeping the proof inside `Owned` makes a membership proof without a spend key
/// unrepresentable.
enum PreparedNullifier {
    Foreign,
    Owned {
        nsk: NullifierSecretKey,
        proof: Option<MembershipProof>,
    },
}

struct AccountPreparedData {
    nullifier: PreparedNullifier,
    npk: NullifierPublicKey,
    kind: PrivateKind,
    identifier: Identifier,
    vpk: ViewingPublicKey,
    pre_state: AccountWithMetadata,
    random_seed: [u8; 32],
}

const fn is_authorized(kind: &PrivateKind) -> bool {
    matches!(kind, PrivateKind::Regular { ask: Some(_) })
}

fn private_key_tree_acc_preparation(
    wallet: &WalletCore,
    account_id: AccountId,
) -> Result<AccountPreparedData, ExecutionFailureKind> {
    let Some(from_acc) = wallet.storage.key_chain().private_account(account_id) else {
        return Err(ExecutionFailureKind::KeyNotFoundError);
    };

    let from_identifier = from_acc.kind.identifier();
    let from_keys = &from_acc.key_chain;
    let nsk = from_keys.private_key_holder.nullifier_secret_key;
    let from_npk = from_keys.nullifier_public_key;
    let from_vpk = from_keys.viewing_public_key.clone();

    // TODO: Technically we could allow unauthorized owned accounts, but currently we don't have
    // support from that in the wallet.
    let kind = match from_acc.kind {
        PrivateAccountKind::Regular(_) => PrivateKind::Regular {
            ask: Some(from_keys.private_key_holder.authorization_secret_key),
        },
        PrivateAccountKind::Pda {
            program_id, seed, ..
        } => PrivateKind::Pda {
            seed: (*seed, *program_id),
        },
    };

    let sender_pre =
        AccountWithMetadata::new(from_acc.account.clone(), is_authorized(&kind), account_id);

    let mut random_seed: [u8; 32] = [0; 32];
    OsRng.fill_bytes(&mut random_seed);

    Ok(AccountPreparedData {
        nullifier: PreparedNullifier::Owned { nsk, proof: None },
        npk: from_npk,
        kind,
        identifier: from_identifier,
        vpk: from_vpk,
        pre_state: sender_pre,
        random_seed,
    })
}

fn private_shared_acc_preparation(
    wallet: &WalletCore,
    account_id: AccountId,
    nsk: NullifierSecretKey,
    npk: NullifierPublicKey,
    vpk: ViewingPublicKey,
    identifier: Identifier,
    kind: PrivateKind,
) -> AccountPreparedData {
    let acc = wallet
        .storage()
        .key_chain()
        .shared_private_account(account_id)
        .map(|e| e.account.clone())
        .unwrap_or_default();

    let pre_state = AccountWithMetadata::new(acc, is_authorized(&kind), account_id);

    let mut random_seed: [u8; 32] = [0; 32];
    OsRng.fill_bytes(&mut random_seed);

    AccountPreparedData {
        nullifier: PreparedNullifier::Owned { nsk, proof: None },
        npk,
        kind,
        identifier,
        vpk,
        pre_state,
        random_seed,
    }
}

async fn fetch_private_proofs_and_root(
    wallet: &WalletCore,
    states: &mut [State],
) -> Result<CommitmentSetDigest, ExecutionFailureKind> {
    let (mut private, commitments): (Vec<&mut AccountPreparedData>, Vec<Commitment>) = states
        .iter_mut()
        .filter_map(|state| match state {
            State::Private(pre) => {
                let commitment = wallet.get_private_account_commitment(pre.pre_state.account_id)?;
                Some((&mut **pre, commitment))
            }
            State::Public { .. } | State::PublicKeycard { .. } => None,
        })
        .unzip();

    let (proofs, root) = wallet
        .get_proofs_and_root(commitments.clone())
        .await
        .map_err(ExecutionFailureKind::SequencerError)?;

    validate_proofs_against_root(&commitments, &proofs, root)?;

    for (pre, proof) in private.iter_mut().zip(proofs) {
        match (&mut pre.nullifier, proof) {
            (PreparedNullifier::Owned { proof: slot, .. }, proof) => *slot = proof,
            (PreparedNullifier::Foreign, None) => {}
            // The caller declared an account foreign, but it is spendable on-chain and the wallet
            // holds no key for it. Building an init witness here would nullify an already-consumed
            // initialization; fail now rather than ship a doomed transaction.
            (PreparedNullifier::Foreign, Some(_)) => {
                return Err(ExecutionFailureKind::AccountDataError(
                    pre.pre_state.account_id,
                ));
            }
        }
    }

    Ok(root)
}

fn validate_proofs_against_root(
    commitments: &[Commitment],
    proofs: &[Option<MembershipProof>],
    root: CommitmentSetDigest,
) -> Result<(), ExecutionFailureKind> {
    if proofs.len() != commitments.len() {
        return Err(ExecutionFailureKind::SequencerError(anyhow::anyhow!(
            "Sequencer returned {} proofs for {} commitments.",
            proofs.len(),
            commitments.len(),
        )));
    }

    for (commitment, proof) in commitments.iter().zip(proofs) {
        if let Some(proof) = proof
            && compute_digest_for_path(commitment, proof) != root
        {
            return Err(ExecutionFailureKind::SequencerError(anyhow::anyhow!(
                "Membership proof for {commitment:?} does not reproduce the appropriate root {root:?}.",
            )));
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn private_shared_is_private() {
        let acc = AccountIdentity::PrivateShared {
            ask: [4; 32],
            vpk: ViewingPublicKey::from_seed(&[2_u8; 32], &[3_u8; 32]),
            identifier: 42,
        };
        assert!(acc.is_private());
        assert!(!acc.is_public());
    }
}
