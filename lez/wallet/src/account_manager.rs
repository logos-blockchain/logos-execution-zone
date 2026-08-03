use core::fmt;

use anyhow::Result;
use keycard_wallet::KeycardWallet;
use lee::{AccountId, PrivateKey, PublicKey, Signature};
use lee_core::{
    AuthorizationSecretKey, Commitment, CommitmentSetDigest, DummyInput, Identifier,
    InputAccountIdentity, MembershipProof, NullifierPublicKey, NullifierSecretKey,
    NullifierWitness, PrivateAccountKind, PrivateWitness, SharedSecretKey, WitnessKind,
    account::{Account, AccountWithMetadata, Nonce},
    compute_digest_for_path,
    encryption::{
        Ciphertext, EncryptedAccountData, MlKem768EncapsulationKey, ViewTag, ViewingPublicKey,
    },
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
    },
    /// A shared regular private account with externally-provided keys (e.g. from GMS).
    /// Carries the authorization secret key: the `nsk` and `npk` behind
    /// `AccountId = from((&npk, &vpk, identifier))` are derived from it.
    /// Works with `authenticated_transfer` and all existing programs out of the box.
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
    /// The private-account count that every privacy-preserving transaction is padded up to with
    /// dummy inputs via the default interface.
    ///
    /// The value is selected based on the largest account number per-tx currently supported
    /// (it is 7 for AMM). It is recommended to reassess this value per new actively supported
    /// application and that all users share the value for a larger anonymity set.
    const MAX_PRIVATE_ACCOUNTS: usize = 7;

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
                                .map_err(ExecutionFailureKind::SignError)?
                                .as_str()
                                .to_owned(),
                        );
                    }

                    State::PublicKeycard { account, key_path }
                }
                AccountIdentity::PrivateOwned(account_id) => {
                    let pre = private_key_tree_acc_preparation(wallet, account_id, false)?;

                    State::Private(pre)
                }
                AccountIdentity::PrivateForeign {
                    npk,
                    vpk,
                    identifier,
                } => {
                    let account_id = lee::AccountId::from((&npk, &vpk, identifier));
                    State::Private(private_foreign_acc_preparation(
                        account_id, npk, vpk, identifier, false,
                    ))
                }
                AccountIdentity::PrivatePdaOwned(account_id) => {
                    let pre = private_key_tree_acc_preparation(wallet, account_id, true)?;
                    State::Private(pre)
                }
                AccountIdentity::PrivatePdaForeign {
                    account_id,
                    npk,
                    vpk,
                    identifier,
                } => State::Private(private_foreign_acc_preparation(
                    account_id, npk, vpk, identifier, true,
                )),
                AccountIdentity::PrivateShared {
                    ask,
                    vpk,
                    identifier,
                } => {
                    let nsk = NullifierSecretKey::from(&ask);
                    let npk = NullifierPublicKey::from(&nsk);
                    let account_id = lee::AccountId::from((&npk, &vpk, identifier));
                    let pre = private_shared_acc_preparation(
                        wallet,
                        account_id,
                        nsk,
                        npk,
                        vpk,
                        identifier,
                        Some(ask),
                        false,
                    );

                    State::Private(pre)
                }
                AccountIdentity::PrivatePdaShared {
                    account_id,
                    nsk,
                    npk,
                    vpk,
                    identifier,
                } => {
                    let pre = private_shared_acc_preparation(
                        wallet, account_id, nsk, npk, vpk, identifier, None, true,
                    );

                    State::Private(pre)
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
                let nonce = if pre.proof.is_some() {
                    pre.pre_state.account.nonce.private_account_nonce_increment(
                        pre.nsk.as_ref().expect("update variant must have nsk"),
                    )
                } else {
                    lee_core::account::Nonce::private_account_nonce_init(&pre.pre_state.account_id)
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

    /// Given a count, generate that many dummy inputs with randomized seeds and notes.
    /// Uses the given commitment root from the account.
    pub fn dummy_inputs(&self, count: usize) -> Vec<DummyInput> {
        std::iter::repeat_with(|| DummyInput {
            nullifier_seed: random_bytes(),
            commitment_seed: random_bytes(),
            note: random_dummy_note(),
            commitment_root: self.dummy_commitment_root,
        })
        .take(count)
        .collect()
    }

    /// Generate the dummy inputs that pad this transaction's private-account count up to
    /// `MAX_PRIVATE_ACCOUNTS`.
    pub fn dummy_inputs_default(&self) -> Vec<DummyInput> {
        let private_count = self
            .states
            .iter()
            .filter(|state| matches!(state, State::Private(_)))
            .count();
        if private_count > Self::MAX_PRIVATE_ACCOUNTS {
            log::warn!(
                "private account count {private_count} exceeds MAX_PRIVATE_ACCOUNTS ({}); \
                 padding saturates and the private-input count is not hidden",
                Self::MAX_PRIVATE_ACCOUNTS
            );
        }
        self.dummy_inputs(Self::MAX_PRIVATE_ACCOUNTS.saturating_sub(private_count))
    }

    /// Build the per-account input vec for the privacy-preserving circuit. The `kind` and
    /// `nullifier` axes select exactly the fields the circuit's code path for that account
    /// needs, with the ephemeral keys (`ssk`) drawn from the cached values that
    /// `private_account_keys` and the message construction also use, so all three views agree
    /// on the same ephemeral key.
    pub fn account_identities(&self) -> Vec<InputAccountIdentity> {
        self.states
            .iter()
            .map(|state| match state {
                State::Public { .. } | State::PublicKeycard { .. } => InputAccountIdentity::Public,
                State::Private(pre) => InputAccountIdentity::Private(PrivateWitness {
                    vpk: pre.vpk.clone(),
                    random_seed: pre.random_seed,
                    identifier: pre.identifier,
                    kind: if pre.is_pda {
                        WitnessKind::Pda { binding: None }
                    } else {
                        WitnessKind::Regular { ask: pre.ask }
                    },
                    nullifier: match (pre.nsk, pre.proof.clone()) {
                        (Some(nsk), Some(membership_proof)) => NullifierWitness::Update {
                            view_tag: random_view_tag(),
                            nsk,
                            membership_proof,
                        },
                        (nsk, _) => NullifierWitness::Init {
                            // A regular init recomputes the npk from the key the wallet holds;
                            // a PDA's stored npk is the owner's, so it is passed through.
                            npk: match nsk {
                                Some(nsk) if !pre.is_pda => NullifierPublicKey::from(&nsk),
                                _ => pre.npk,
                            },
                            commitment_root: self.dummy_commitment_root,
                        },
                    },
                }),
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
            let mut wallet = KeycardWallet::new()?;
            wallet.connect(&pin)?;
            for path in keycard_paths {
                sigs.push(wallet.sign_message_for_path(path, &message_hash)?);
            }
        }

        Ok(sigs)
    }
}

struct AccountPreparedData {
    ask: Option<AuthorizationSecretKey>,
    nsk: Option<NullifierSecretKey>,
    npk: NullifierPublicKey,
    identifier: Identifier,
    vpk: ViewingPublicKey,
    pre_state: AccountWithMetadata,
    proof: Option<MembershipProof>,
    random_seed: [u8; 32],
    /// True when this account is a private PDA (owned or foreign). Used by `account_identities()`
    /// to select `WitnessKind::Pda` rather than `WitnessKind::Regular`.
    is_pda: bool,
}

fn private_key_tree_acc_preparation(
    wallet: &WalletCore,
    account_id: AccountId,
    is_pda: bool,
) -> Result<AccountPreparedData, ExecutionFailureKind> {
    let Some(from_acc) = wallet.storage.key_chain().private_account(account_id) else {
        return Err(ExecutionFailureKind::KeyNotFoundError);
    };

    let from_identifier = from_acc.kind.identifier();
    let from_keys = &from_acc.key_chain;
    let ask = from_keys.private_key_holder.authorization_secret_key;
    let nsk = from_keys.private_key_holder.nullifier_secret_key();
    let from_npk = from_keys.nullifier_public_key;
    let from_vpk = from_keys.viewing_public_key.clone();

    // TODO: Technically we could allow unauthorized owned accounts, but currently we don't have
    // support from that in the wallet.
    let sender_pre = AccountWithMetadata::new(from_acc.account.clone(), true, account_id);

    let random_seed = random_bytes();

    Ok(AccountPreparedData {
        // A PDA is program-authorized and carries no credential of its own.
        ask: (!is_pda).then_some(ask),
        nsk: Some(nsk),
        npk: from_npk,
        identifier: from_identifier,
        vpk: from_vpk,
        pre_state: sender_pre,
        proof: None,
        random_seed,
        is_pda,
    })
}

/// Prepare a private account with no secret key knowledge, i.e. for inits.
fn private_foreign_acc_preparation(
    account_id: AccountId,
    npk: NullifierPublicKey,
    vpk: ViewingPublicKey,
    identifier: Identifier,
    is_pda: bool,
) -> AccountPreparedData {
    AccountPreparedData {
        // The wallet holds no key for a recipient, so it can neither spend the account nor
        // consent on its behalf. The program still claims it: a private claim never requires
        // authorization.
        ask: None,
        nsk: None,
        npk,
        identifier,
        vpk,
        pre_state: AccountWithMetadata::new(Account::default(), false, account_id),
        proof: None,
        random_seed: random_bytes(),
        is_pda,
    }
}

#[expect(clippy::too_many_arguments, reason = "All keys need to be supplied")]
fn private_shared_acc_preparation(
    wallet: &WalletCore,
    account_id: AccountId,
    nsk: NullifierSecretKey,
    npk: NullifierPublicKey,
    vpk: ViewingPublicKey,
    identifier: Identifier,
    ask: Option<AuthorizationSecretKey>,
    is_pda: bool,
) -> AccountPreparedData {
    let acc = wallet
        .storage()
        .key_chain()
        .shared_private_account(account_id)
        .map(|e| e.account.clone())
        .unwrap_or_default();

    let pre_state = AccountWithMetadata::new(acc, true, account_id);

    let random_seed = random_bytes();

    AccountPreparedData {
        ask,
        nsk: Some(nsk),
        npk,
        identifier,
        vpk,
        pre_state,
        proof: None,
        random_seed,
        is_pda,
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
                Some((pre, commitment))
            }
            State::Public { .. } | State::PublicKeycard { .. } => None,
        })
        .unzip();

    let (proofs, root) = wallet
        .get_proofs_and_root(&commitments)
        .await
        .map_err(ExecutionFailureKind::SequencerError)?;

    validate_proofs_against_root(&commitments, &proofs, root)?;

    for (pre, proof) in private.iter_mut().zip(proofs) {
        pre.proof = proof;
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

/// Generate random byte using OS randomness.
fn random_view_tag() -> ViewTag {
    let mut byte: [u8; 1] = [0; 1];
    OsRng.fill_bytes(&mut byte);
    byte[0]
}

fn random_bytes() -> [u8; 32] {
    let mut bytes = [0; 32];
    OsRng.fill_bytes(&mut bytes);
    bytes
}

fn random_vec(len: usize) -> Vec<u8> {
    let mut bytes = vec![0; len];
    OsRng.fill_bytes(&mut bytes);
    bytes
}

/// Generates a dummy note: random bytes sized to a default-account ciphertext, a real
/// ML-KEM ciphertext epk toward a throwaway key, and a random view tag.
fn random_dummy_note() -> EncryptedAccountData {
    // Sized to a default-account ciphertext; matching real data sizes is a separate issue.
    let ciphertext_len = PrivateAccountKind::HEADER_LEN
        .checked_add(Account::default().to_bytes().len())
        .expect("dummy ciphertext length fits in usize");
    let throwaway_ek = MlKem768EncapsulationKey::from_seed(&random_bytes(), &random_bytes());
    let (_, epk) = SharedSecretKey::encapsulate(&throwaway_ek);
    EncryptedAccountData {
        ciphertext: Ciphertext::from_inner(random_vec(ciphertext_len)),
        epk,
        view_tag: random_view_tag(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn private_shared_is_private() {
        let acc = AccountIdentity::PrivateShared {
            ask: AuthorizationSecretKey([0; 32]),
            vpk: ViewingPublicKey::from_seed(&[2_u8; 32], &[3_u8; 32]),
            identifier: 42,
        };
        assert!(acc.is_private());
        assert!(!acc.is_public());
    }

    fn private_state() -> State {
        let npk = NullifierPublicKey([0; 32]);
        let vpk = ViewingPublicKey::from_seed(&[0; 32], &[0; 32]);
        let pre_state = AccountWithMetadata::new(Account::default(), false, (&npk, &vpk, 0));
        State::Private(AccountPreparedData {
            ask: None,
            nsk: None,
            npk,
            identifier: 0,
            vpk,
            pre_state,
            proof: None,
            random_seed: [0; 32],
            is_pda: false,
        })
    }

    fn public_state() -> State {
        let npk = NullifierPublicKey([0; 32]);
        let vpk = ViewingPublicKey::from_seed(&[0; 32], &[0; 32]);
        let account = AccountWithMetadata::new(Account::default(), false, (&npk, &vpk, 0));
        State::Public { account, sk: None }
    }

    fn manager(states: Vec<State>) -> AccountManager {
        AccountManager {
            states,
            pin: None,
            dummy_commitment_root: [0; 32],
        }
    }

    #[test]
    fn foreign_private_init_is_unauthorized() {
        let npk = NullifierPublicKey([7; 32]);
        let vpk = ViewingPublicKey::from_seed(&[8; 32], &[9; 32]);
        let account_id = lee::AccountId::from((&npk, &vpk, 0));
        let pre = private_foreign_acc_preparation(account_id, npk, vpk, 0, false);

        assert!(pre.ask.is_none());
        assert!(!pre.pre_state.is_authorized);

        let identities = manager(vec![State::Private(pre)]).account_identities();
        let InputAccountIdentity::Private(witness) = &identities[0] else {
            panic!("expected a private witness");
        };
        assert!(matches!(witness.kind, WitnessKind::Regular { ask: None }));
    }

    #[test]
    fn dummy_inputs_default_pads_private_count_to_max() {
        let max = AccountManager::MAX_PRIVATE_ACCOUNTS;

        // Empty txs get padded to the max.
        assert_eq!(manager(vec![]).dummy_inputs_default().len(), max);
        // In a padded transaction, the padding amount depends on
        // the amount of private accounts used.
        assert_eq!(
            manager(vec![private_state(), private_state()])
                .dummy_inputs_default()
                .len(),
            max - 2
        );
        assert_eq!(
            manager(vec![private_state(), public_state(), private_state()])
                .dummy_inputs_default()
                .len(),
            max - 2
        );

        // If the private accounts in the transaction exceed the max, no padding
        // is done.
        let full: Vec<State> = std::iter::repeat_with(private_state).take(max).collect();
        assert_eq!(manager(full).dummy_inputs_default().len(), 0);
        let over: Vec<State> = std::iter::repeat_with(private_state)
            .take(max + 2)
            .collect();
        assert_eq!(manager(over).dummy_inputs_default().len(), 0);
    }
}
