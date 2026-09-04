use core::fmt;
use std::collections::{HashMap, HashSet};

use anyhow::Result;
use keycard_wallet::KeycardWallet;
use lee::{AccountId, PrivateKey, PublicKey, Signature};
use lee_core::{
    AuthorizationSecretKey, Commitment, CommitmentSetDigest, DummyInput, Identifier,
    MembershipProof, NullifierPublicKey, NullifierSecretKey, NullifierWitness, PrivateAccountKind,
    PrivateWitness, SharedSecretKey, WitnessKind,
    account::{Account, Input, Nonce, Position},
    compute_digest_for_path,
    encryption::{
        Ciphertext, EncryptedAccountData, MlKem768EncapsulationKey, ViewTag, ViewingPublicKey,
    },
    program::PdaSeed,
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
    /// [`AccountId::for_private_pda`] from `(authority, seed)`, which the witness carries so the
    /// circuit can re-derive the address.
    PrivatePdaOwned {
        account_id: AccountId,
        authority: AccountId,
        seed: PdaSeed,
    },
    /// A foreign private PDA: wallet knows the recipient's npk/vpk but not their nsk.
    /// Uses a default (uninitialised) account.
    PrivatePdaForeign {
        account_id: AccountId,
        authority: AccountId,
        seed: PdaSeed,
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
    /// `account_id` was derived via [`AccountId::for_private_pda`] from `(authority, seed)`; its
    /// `npk` is derived from the `nsk` at use.
    PrivatePdaShared {
        account_id: AccountId,
        authority: AccountId,
        seed: PdaSeed,
        nsk: NullifierSecretKey,
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
            Self::PrivatePdaOwned {
                account_id,
                authority,
                seed,
            } => f
                .debug_struct("PrivatePdaOwned")
                .field("account_id", account_id)
                .field("authority", authority)
                .field("seed", seed)
                .finish(),
            Self::PrivatePdaForeign {
                account_id,
                authority,
                seed,
                npk,
                vpk,
                identifier,
            } => f
                .debug_struct("PrivatePdaForeign")
                .field("account_id", account_id)
                .field("authority", authority)
                .field("seed", seed)
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
                authority,
                seed,
                vpk,
                identifier,
                ..
            } => f
                .debug_struct("PrivatePdaShared")
                .field("account_id", account_id)
                .field("authority", authority)
                .field("seed", seed)
                .field("nsk", &"<redacted>")
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
            | Self::PrivatePdaOwned { .. }
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
                | Self::PrivatePdaOwned { .. }
                | Self::PrivatePdaForeign { .. }
                | Self::PrivateShared { .. }
                | Self::PrivatePdaShared { .. }
        )
    }

    /// Names this account under `program`'s namespace: the call reads and writes that program's
    /// record here.
    #[must_use]
    pub const fn in_namespace(self, program: AccountId) -> AccountMention {
        AccountMention {
            identity: self,
            namespace: Some(program),
        }
    }

    /// Names this account without a namespace: the call only moves its balance or checks its
    /// address.
    #[must_use]
    pub const fn balance_only(self) -> AccountMention {
        AccountMention {
            identity: self,
            namespace: None,
        }
    }
}

/// One account as a transaction names it: which account, and whose record at it — `None` when
/// the call only moves its balance or checks its address.
pub struct AccountMention {
    pub identity: AccountIdentity,
    pub namespace: Option<AccountId>,
}

pub struct PrivateAccountKeys {
    pub ssk: SharedSecretKey,
}

/// A fetched account with what a position needs beside it: which account it is and whether this
/// transaction authorizes it.
struct PreparedAccount {
    account_id: AccountId,
    account: Account,
    is_authorized: bool,
}

/// One account the transaction names, with the namespace it names it under.
struct State {
    namespace: Option<AccountId>,
    kind: StateKind,
}

enum StateKind {
    Public {
        account: PreparedAccount,
        sk: Option<PrivateKey>,
    },
    PublicKeycard {
        account: PreparedAccount,
        key_path: String,
    },
    /// Boxed to avoid a large enum variant size.
    Private(Box<AccountPreparedData>),
}

impl State {
    fn account(&self) -> &PreparedAccount {
        match &self.kind {
            StateKind::Public { account, .. } | StateKind::PublicKeycard { account, .. } => account,
            StateKind::Private(pre) => &pre.pre_state,
        }
    }

    fn position(&self) -> Position {
        let account_id = self.account().account_id;
        self.namespace.map_or_else(
            || Position::balance_only(account_id),
            |program| Position::new(account_id, program),
        )
    }

    fn input(&self) -> Input {
        let account = self.account();
        Input::at(self.position(), account.is_authorized, &account.account)
    }
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
        mentions: Vec<AccountMention>,
    ) -> Result<Self, ExecutionFailureKind> {
        let mut states = Vec::with_capacity(mentions.len());
        let mut pin = None;

        for AccountMention {
            identity,
            namespace,
        } in mentions
        {
            let kind = match identity {
                AccountIdentity::Public(account_id) => {
                    let account = wallet
                        .get_account_public(account_id)
                        .await
                        .map_err(ExecutionFailureKind::SequencerError)?;

                    let sk = wallet.get_account_public_signing_key(account_id).cloned();
                    let account = PreparedAccount {
                        account_id,
                        account,
                        is_authorized: sk.is_some(),
                    };

                    StateKind::Public { account, sk }
                }
                AccountIdentity::PublicNoSign(account_id) => {
                    let account = wallet
                        .get_account_public(account_id)
                        .await
                        .map_err(ExecutionFailureKind::SequencerError)?;

                    let account = PreparedAccount {
                        account_id,
                        account,
                        is_authorized: false,
                    };

                    StateKind::Public { account, sk: None }
                }
                AccountIdentity::PublicKeycard {
                    account_id,
                    key_path,
                } => {
                    let account = wallet
                        .get_account_public(account_id)
                        .await
                        .map_err(ExecutionFailureKind::SequencerError)?;

                    let account = PreparedAccount {
                        account_id,
                        account,
                        is_authorized: true,
                    };

                    if pin.is_none() {
                        pin = Some(
                            crate::helperfunctions::read_pin()
                                .map_err(ExecutionFailureKind::SignError)?
                                .as_str()
                                .to_owned(),
                        );
                    }

                    StateKind::PublicKeycard { account, key_path }
                }
                AccountIdentity::PrivateOwned(account_id) => {
                    let pre = private_key_tree_acc_preparation(wallet, account_id, None)?;

                    StateKind::Private(Box::new(pre))
                }
                AccountIdentity::PrivateForeign {
                    npk,
                    vpk,
                    identifier,
                } => {
                    let account_id = lee::AccountId::from((&npk, &vpk, identifier));
                    StateKind::Private(Box::new(private_foreign_acc_preparation(
                        account_id, npk, vpk, identifier, None,
                    )))
                }
                AccountIdentity::PrivatePdaOwned {
                    account_id,
                    authority,
                    seed,
                } => {
                    let pre = private_key_tree_acc_preparation(
                        wallet,
                        account_id,
                        Some((authority, seed)),
                    )?;
                    StateKind::Private(Box::new(pre))
                }
                AccountIdentity::PrivatePdaForeign {
                    account_id,
                    authority,
                    seed,
                    npk,
                    vpk,
                    identifier,
                } => StateKind::Private(Box::new(private_foreign_acc_preparation(
                    account_id,
                    npk,
                    vpk,
                    identifier,
                    Some((authority, seed)),
                ))),
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
                        vpk,
                        identifier,
                        Some(ask),
                        None,
                    );

                    StateKind::Private(Box::new(pre))
                }
                AccountIdentity::PrivatePdaShared {
                    account_id,
                    authority,
                    seed,
                    nsk,
                    vpk,
                    identifier,
                } => {
                    let pre = private_shared_acc_preparation(
                        wallet,
                        account_id,
                        nsk,
                        vpk,
                        identifier,
                        None,
                        Some((authority, seed)),
                    );

                    StateKind::Private(Box::new(pre))
                }
            };

            states.push(State { namespace, kind });
        }

        let dummy_commitment_root = fetch_private_proofs_and_root(wallet, &mut states).await?;

        Ok(Self {
            states,
            pin,
            dummy_commitment_root,
        })
    }

    /// The per-position inputs a guest would see: the account's balance plus the named shard.
    pub fn pre_states(&self) -> Vec<Input> {
        self.states.iter().map(State::input).collect()
    }

    /// What the transaction names, in declaration order.
    pub fn positions(&self) -> Vec<Position> {
        self.states.iter().map(State::position).collect()
    }

    /// The public accounts whose signature this transaction carries.
    pub fn signers(&self) -> HashSet<AccountId> {
        self.states
            .iter()
            .filter_map(|state| match &state.kind {
                StateKind::Public {
                    account,
                    sk: Some(_),
                }
                | StateKind::PublicKeycard { account, .. } => Some(account.account_id),
                StateKind::Public { sk: None, .. } | StateKind::Private(_) => None,
            })
            .collect()
    }

    /// Every named public account's whole current account, for the prover to materialize the
    /// namespaces the call graph reaches beyond the ones named here.
    pub fn public_accounts(&self) -> HashMap<AccountId, Account> {
        self.states
            .iter()
            .filter_map(|state| match &state.kind {
                StateKind::Public { account, .. } | StateKind::PublicKeycard { account, .. } => {
                    Some((account.account_id, account.account.clone()))
                }
                StateKind::Private(_) => None,
            })
            .collect()
    }

    pub fn public_account_nonces(&self) -> Vec<Nonce> {
        // Must match the signature order produced by sign_message(): local accounts first,
        // keycard accounts second.
        let local = self.states.iter().filter_map(|state| match &state.kind {
            StateKind::Public { account, sk } => sk.as_ref().map(|_| account.account.nonce),
            StateKind::PublicKeycard { .. } | StateKind::Private(_) => None,
        });
        let keycard = self.states.iter().filter_map(|state| match &state.kind {
            StateKind::PublicKeycard { account, .. } => Some(account.account.nonce),
            StateKind::Public { .. } | StateKind::Private(_) => None,
        });
        local.chain(keycard).collect()
    }

    pub fn private_account_keys(&self) -> Vec<PrivateAccountKeys> {
        self.private_states()
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
        let private_count = self.private_states().count();
        if private_count > Self::MAX_PRIVATE_ACCOUNTS {
            log::warn!(
                "private account count {private_count} exceeds MAX_PRIVATE_ACCOUNTS ({}); \
                 padding saturates and the private-input count is not hidden",
                Self::MAX_PRIVATE_ACCOUNTS
            );
        }
        self.dummy_inputs(Self::MAX_PRIVATE_ACCOUNTS.saturating_sub(private_count))
    }

    fn private_states(&self) -> impl Iterator<Item = &AccountPreparedData> {
        self.states.iter().filter_map(|state| match &state.kind {
            StateKind::Private(pre) => Some(pre.as_ref()),
            StateKind::Public { .. } | StateKind::PublicKeycard { .. } => None,
        })
    }

    /// One witness per private account, each carrying the whole committed account — the
    /// untouched shards reach the commitment through here and nowhere else. The `kind` and
    /// `nullifier` axes select exactly the fields the circuit's code path for that account
    /// needs, with the ephemeral keys (`ssk`) drawn from the cached values that
    /// `private_account_keys` and the message construction also use, so all three views agree
    /// on the same ephemeral key.
    pub fn private_witnesses(&self) -> Vec<PrivateWitness> {
        self.private_states()
            .map(|pre| PrivateWitness {
                account: pre.pre_state.account.clone(),
                vpk: pre.vpk.clone(),
                random_seed: pre.random_seed,
                identifier: pre.identifier,
                kind: pre
                    .binding
                    .map_or(WitnessKind::Regular { ask: pre.ask }, |binding| {
                        WitnessKind::Pda { binding }
                    }),
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
                            Some(nsk) if pre.binding.is_none() => NullifierPublicKey::from(&nsk),
                            _ => pre.npk,
                        },
                        commitment_root: self.dummy_commitment_root,
                    },
                },
            })
            .collect()
    }

    /// The account that pays this transaction's fee: the first public signing
    /// account that holds a balance. Its ordinary signature covers the message,
    /// so it is fee-authorized without a separate fee witness. Non-signing
    /// public accounts (`sk: None`) are skipped.
    ///
    /// If no signing account is funded, falls back to the first signing account.
    /// A fee-exempt transaction carries a vestigial fee declaration the sequencer
    /// never charges, so it still needs a payer id to fill. Only a wallet with no
    /// signing account at all yields `None`.
    pub fn fee_payer_account_id(&self) -> Option<AccountId> {
        let signing = || {
            self.states.iter().filter_map(|state| match &state.kind {
                StateKind::Public {
                    account,
                    sk: Some(_),
                }
                | StateKind::PublicKeycard { account, .. } => Some(account),
                StateKind::Public { sk: None, .. } | StateKind::Private(_) => None,
            })
        };
        signing()
            .find(|account| account.account.balance > 0)
            .or_else(|| signing().next())
            .map(|account| account.account_id)
    }

    pub fn public_non_keycard_account_auth(&self) -> Vec<&PrivateKey> {
        self.states
            .iter()
            .filter_map(|state| match &state.kind {
                StateKind::Public { sk, .. } => sk.as_ref(),
                StateKind::PublicKeycard { .. } | StateKind::Private(_) => None,
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
            .filter_map(|state| match &state.kind {
                StateKind::PublicKeycard { key_path, .. } => Some(key_path.as_str()),
                StateKind::Private(_) | StateKind::Public { .. } => None,
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
    pre_state: PreparedAccount,
    proof: Option<MembershipProof>,
    random_seed: [u8; 32],
    /// `Some` when this account is a private PDA (owned or foreign): the `(authority, seed)` pair
    /// its address was derived from. The witness carries it, so the circuit re-derives the
    /// address rather than trusting the caller.
    binding: Option<(AccountId, PdaSeed)>,
}

fn private_key_tree_acc_preparation(
    wallet: &WalletCore,
    account_id: AccountId,
    binding: Option<(AccountId, PdaSeed)>,
) -> Result<AccountPreparedData, ExecutionFailureKind> {
    let Some(from_acc) = wallet.storage.key_chain().private_account(account_id) else {
        return Err(ExecutionFailureKind::KeyNotFoundError);
    };

    let from_identifier = from_acc.kind.identifier();
    let from_keys = &from_acc.key_chain;
    // A PDA is program-authorized and carries no credential of its own.
    let ask = binding
        .is_none()
        .then_some(from_keys.private_key_holder.authorization_secret_key);
    let nsk = from_keys.private_key_holder.nullifier_secret_key();
    let from_npk = from_keys.nullifier_public_key;
    let from_vpk = from_keys.viewing_public_key.clone();

    // TODO: Technically we could allow unauthorized owned accounts, but currently we don't have
    // support from that in the wallet.
    let sender_pre = PreparedAccount {
        account_id,
        account: from_acc.account.clone(),
        is_authorized: ask.is_some(),
    };

    let random_seed = random_bytes();

    Ok(AccountPreparedData {
        ask,
        nsk: Some(nsk),
        npk: from_npk,
        identifier: from_identifier,
        vpk: from_vpk,
        pre_state: sender_pre,
        proof: None,
        random_seed,
        binding,
    })
}

/// Prepare a private account with no secret key knowledge, i.e. for inits.
fn private_foreign_acc_preparation(
    account_id: AccountId,
    npk: NullifierPublicKey,
    vpk: ViewingPublicKey,
    identifier: Identifier,
    binding: Option<(AccountId, PdaSeed)>,
) -> AccountPreparedData {
    AccountPreparedData {
        // The wallet holds no key for a recipient, so it can neither spend the account nor
        // consent on its behalf.
        ask: None,
        nsk: None,
        npk,
        identifier,
        vpk,
        pre_state: PreparedAccount {
            account_id,
            account: Account::default(),
            is_authorized: false,
        },
        proof: None,
        random_seed: random_bytes(),
        binding,
    }
}

fn private_shared_acc_preparation(
    wallet: &WalletCore,
    account_id: AccountId,
    nsk: NullifierSecretKey,
    vpk: ViewingPublicKey,
    identifier: Identifier,
    ask: Option<AuthorizationSecretKey>,
    binding: Option<(AccountId, PdaSeed)>,
) -> AccountPreparedData {
    let npk = NullifierPublicKey::from(&nsk);
    let account = wallet
        .storage()
        .key_chain()
        .shared_private_account(account_id)
        .map(|e| e.account.clone())
        .unwrap_or_default();

    let pre_state = PreparedAccount {
        account_id,
        account,
        is_authorized: ask.is_some(),
    };

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
        binding,
    }
}

async fn fetch_private_proofs_and_root(
    wallet: &WalletCore,
    states: &mut [State],
) -> Result<CommitmentSetDigest, ExecutionFailureKind> {
    let (mut private, commitments): (Vec<&mut AccountPreparedData>, Vec<Commitment>) = states
        .iter_mut()
        .filter_map(|state| match &mut state.kind {
            StateKind::Private(pre) => {
                let commitment = wallet.get_private_account_commitment(pre.pre_state.account_id)?;
                Some((pre.as_mut(), commitment))
            }
            StateKind::Public { .. } | StateKind::PublicKeycard { .. } => None,
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
        let pre_state = PreparedAccount {
            account_id: lee::AccountId::from((&npk, &vpk, 0)),
            account: Account::default(),
            is_authorized: false,
        };
        State {
            namespace: None,
            kind: StateKind::Private(Box::new(AccountPreparedData {
                ask: None,
                nsk: None,
                npk,
                identifier: 0,
                vpk,
                pre_state,
                proof: None,
                random_seed: [0; 32],
                binding: None,
            })),
        }
    }

    fn public_state() -> State {
        let npk = NullifierPublicKey([0; 32]);
        let vpk = ViewingPublicKey::from_seed(&[0; 32], &[0; 32]);
        let account = PreparedAccount {
            account_id: lee::AccountId::from((&npk, &vpk, 0)),
            account: Account::default(),
            is_authorized: false,
        };
        State {
            namespace: None,
            kind: StateKind::Public { account, sk: None },
        }
    }

    /// A public account the wallet can sign for, holding `balance`.
    fn public_signing_state(seed: u8, balance: u128) -> State {
        let sk = lee::PrivateKey::try_new([seed; 32]).expect("valid key");
        let account_id = lee::AccountId::from(&lee::PublicKey::new_from_private_key(&sk));
        let account = PreparedAccount {
            account_id,
            account: Account {
                balance,
                ..Account::default()
            },
            is_authorized: false,
        };
        State {
            namespace: None,
            kind: StateKind::Public {
                account,
                sk: Some(sk),
            },
        }
    }

    fn manager(states: Vec<State>) -> AccountManager {
        AccountManager {
            states,
            pin: None,
            dummy_commitment_root: [0; 32],
        }
    }

    #[test]
    fn fee_payer_is_the_first_funded_public_signing_account() {
        let first_signing = public_signing_state(1, 1_000);
        let expected = first_signing.account().account_id;
        let manager = manager(vec![
            private_state(),
            first_signing,
            public_signing_state(2, 1_000),
        ]);
        assert_eq!(manager.fee_payer_account_id(), Some(expected));
    }

    #[test]
    fn fee_payer_skips_a_non_signing_public_account() {
        // A tracked but unsignable public account (sk: None, e.g. an AMM pool
        // or definition PDA passed as a non-signing input) must not be
        // designated payer — the first funded signing account is chosen instead.
        let signing = public_signing_state(3, 1_000);
        let signing_id = signing.account().account_id;
        let manager = manager(vec![public_state(), signing]);
        assert_eq!(manager.fee_payer_account_id(), Some(signing_id));
    }

    #[test]
    fn fee_payer_skips_an_unfunded_signing_account_for_a_funded_one() {
        // An empty first signing account must not shadow a funded later one.
        let funded = public_signing_state(6, 1_000);
        let funded_id = funded.account().account_id;
        let manager = manager(vec![public_signing_state(5, 0), funded]);
        assert_eq!(manager.fee_payer_account_id(), Some(funded_id));
    }

    #[test]
    fn no_public_account_means_no_fee_payer() {
        let manager = manager(vec![private_state()]);
        assert_eq!(manager.fee_payer_account_id(), None);
    }

    #[test]
    fn an_all_unfunded_wallet_falls_back_to_the_first_signing_account() {
        // No signing account is funded, but a fee-exempt transaction still needs a
        // payer id to fill: fall back to the first signing account rather than
        // refuse to build.
        let first = public_signing_state(7, 0);
        let first_id = first.account().account_id;
        let manager = manager(vec![first, public_signing_state(8, 0)]);
        assert_eq!(manager.fee_payer_account_id(), Some(first_id));
    }

    #[test]
    fn a_non_signing_public_account_alone_has_no_fee_payer() {
        let manager = manager(vec![public_state()]);
        assert_eq!(manager.fee_payer_account_id(), None);
    }

    #[test]
    fn foreign_private_init_is_unauthorized() {
        let npk = NullifierPublicKey([7; 32]);
        let vpk = ViewingPublicKey::from_seed(&[8; 32], &[9; 32]);
        let account_id = lee::AccountId::from((&npk, &vpk, 0));
        let pre = private_foreign_acc_preparation(account_id, npk, vpk, 0, None);

        assert!(pre.ask.is_none());
        assert!(!pre.pre_state.is_authorized);

        let witnesses = manager(vec![State {
            namespace: None,
            kind: StateKind::Private(Box::new(pre)),
        }])
        .private_witnesses();
        assert!(matches!(
            witnesses[0].kind,
            WitnessKind::Regular { ask: None }
        ));
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
