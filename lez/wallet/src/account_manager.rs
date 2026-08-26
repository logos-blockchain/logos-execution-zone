use core::fmt;

use anyhow::Result;
use keycard_wallet::KeycardWallet;
use lee::{AccountId, PrivateKey, PublicKey, Signature};
use lee_core::{
    AuthorizationSecretKey, Commitment, CommitmentSetDigest, DummyInput, Identifier,
    InputAccountIdentity, MembershipProof, NullifierPublicKey, NullifierSecretKey,
    NullifierWitness, PrivateAccountKind, PrivateWitness, SharedSecretKey, WitnessKind,
    account::{Account, Data, Input, Nonce},
    compute_digest_for_path,
    encryption::{
        Ciphertext, EncryptedAccountData, MlKem768EncapsulationKey, ViewTag, ViewingPublicKey,
    },
    program::{DEFAULT_PROGRAM_ID, PdaSeed, ProgramId},
};
use rand::{RngCore as _, rngs::OsRng};

use crate::{ExecutionFailureKind, WalletCore};

/// The account a transaction position names, paired with the namespace it reads there.
/// `program` is `None` for a position that carries only an address.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct AccountIdentity {
    pub identity: Identity,
    pub program: Option<AccountId>,
}

impl AccountIdentity {
    #[must_use]
    pub const fn is_private(&self) -> bool {
        self.identity.is_private()
    }

    #[must_use]
    pub const fn is_public(&self) -> bool {
        self.identity.is_public()
    }

    #[must_use]
    pub const fn public_account_id(&self) -> Option<lee::AccountId> {
        self.identity.public_account_id()
    }
}

#[derive(Clone, PartialEq, Eq)]
pub enum Identity {
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
    /// Uses a default (uninitialised) account. The `account_id` is derived from `binding`
    /// together with the keys, so the pair proven to the circuit always addresses the account.
    PrivatePdaForeign {
        binding: (ProgramId, PdaSeed),
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
    /// The `account_id` is derived via [`AccountId::for_private_pda`] from `binding` and the
    /// keys; its `npk` is derived from the `nsk` at use.
    PrivatePdaShared {
        binding: (ProgramId, PdaSeed),
        nsk: NullifierSecretKey,
        vpk: ViewingPublicKey,
        identifier: Identifier,
    },
}

impl fmt::Debug for Identity {
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
                binding,
                npk,
                vpk,
                identifier,
            } => f
                .debug_struct("PrivatePdaForeign")
                .field("binding", binding)
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
                binding,
                vpk,
                identifier,
                ..
            } => f
                .debug_struct("PrivatePdaShared")
                .field("binding", binding)
                .field("nsk", &"<redacted>")
                .field("vpk", vpk)
                .field("identifier", identifier)
                .finish(),
        }
    }
}

impl Identity {
    /// This account, read through `program`'s namespace.
    #[must_use]
    pub fn in_namespace(self, program: impl Into<AccountId>) -> AccountIdentity {
        AccountIdentity {
            identity: self,
            program: Some(program.into()),
        }
    }

    /// This account as an address only: a marker, an authority, a derivation input.
    #[must_use]
    pub const fn address_only(self) -> AccountIdentity {
        AccountIdentity {
            identity: self,
            program: None,
        }
    }

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
        account: Input,
        /// The nonce is not part of an `Input` — a program can neither see nor change it —
        /// but the wallet still needs it to build the message it signs.
        nonce: Nonce,
        sk: Option<PrivateKey>,
    },
    PublicKeycard {
        account: Input,
        nonce: Nonce,
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

        for AccountIdentity { identity, program } in accounts {
            let state = match identity {
                Identity::Public(account_id) => {
                    let acc = wallet
                        .get_account_public(account_id)
                        .await
                        .map_err(ExecutionFailureKind::SequencerError)?;

                    let sk = wallet.get_account_public_signing_key(account_id).cloned();
                    let account = public_input(&acc, sk.is_some(), account_id, program);

                    State::Public {
                        account,
                        nonce: acc.nonce,
                        sk,
                    }
                }
                Identity::PublicNoSign(account_id) => {
                    let acc = wallet
                        .get_account_public(account_id)
                        .await
                        .map_err(ExecutionFailureKind::SequencerError)?;

                    let sk = None;
                    let account = public_input(&acc, sk.is_some(), account_id, program);

                    State::Public {
                        account,
                        nonce: acc.nonce,
                        sk,
                    }
                }
                Identity::PublicKeycard {
                    account_id,
                    key_path,
                } => {
                    let acc = wallet
                        .get_account_public(account_id)
                        .await
                        .map_err(ExecutionFailureKind::SequencerError)?;

                    let account = public_input(&acc, true, account_id, program);

                    if pin.is_none() {
                        pin = Some(
                            crate::helperfunctions::read_pin()
                                .map_err(ExecutionFailureKind::SignError)?
                                .as_str()
                                .to_owned(),
                        );
                    }

                    State::PublicKeycard {
                        account,
                        nonce: acc.nonce,
                        key_path,
                    }
                }
                Identity::PrivateOwned(account_id) | Identity::PrivatePdaOwned(account_id) => {
                    let pre = private_key_tree_acc_preparation(wallet, account_id, program)?;

                    State::Private(Box::new(pre))
                }
                Identity::PrivateForeign {
                    npk,
                    vpk,
                    identifier,
                } => State::Private(Box::new(private_foreign_acc_preparation(
                    npk, vpk, identifier, None, program,
                ))),
                Identity::PrivatePdaForeign {
                    binding,
                    npk,
                    vpk,
                    identifier,
                } => State::Private(Box::new(private_foreign_acc_preparation(
                    npk,
                    vpk,
                    identifier,
                    Some(binding),
                    program,
                ))),
                Identity::PrivateShared {
                    ask,
                    vpk,
                    identifier,
                } => {
                    let nsk = NullifierSecretKey::from(&ask);
                    let pre = private_shared_acc_preparation(
                        wallet,
                        nsk,
                        vpk,
                        identifier,
                        Some(ask),
                        None,
                        program,
                    );

                    State::Private(Box::new(pre))
                }
                Identity::PrivatePdaShared {
                    binding,
                    nsk,
                    vpk,
                    identifier,
                } => {
                    let pre = private_shared_acc_preparation(
                        wallet,
                        nsk,
                        vpk,
                        identifier,
                        None,
                        Some(binding),
                        program,
                    );

                    State::Private(Box::new(pre))
                }
            };

            states.push(state);
        }

        align_private_seeds(&mut states);

        let dummy_commitment_root = fetch_private_proofs_and_root(wallet, &mut states).await?;

        Ok(Self {
            states,
            pin,
            dummy_commitment_root,
        })
    }

    pub fn pre_states(&self) -> Vec<Input> {
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
            State::Public { nonce, sk, .. } => sk.as_ref().map(|_| *nonce),
            State::PublicKeycard { .. } | State::Private(_) => None,
        });
        let keycard = self.states.iter().filter_map(|state| match state {
            State::PublicKeycard { nonce, .. } => Some(*nonce),
            State::Public { .. } | State::Private(_) => None,
        });
        local.chain(keycard).collect()
    }

    /// The private accounts this transaction touches, in first-appearance order. The circuit
    /// emits one note per account however many of its namespaces the transaction names, so a
    /// position is not a note: anything counted per note has to come through here.
    fn private_accounts(&self) -> Vec<&AccountPreparedData> {
        let mut seen = Vec::new();
        self.states
            .iter()
            .filter_map(|state| match state {
                State::Private(pre) => Some(pre.as_ref()),
                State::Public { .. } | State::PublicKeycard { .. } => None,
            })
            .filter(|pre| {
                let account_id = pre.pre_state.account_id;
                let fresh = !seen.contains(&account_id);
                if fresh {
                    seen.push(account_id);
                }
                fresh
            })
            .collect()
    }

    pub fn private_account_keys(&self) -> Vec<PrivateAccountKeys> {
        self.private_accounts()
            .into_iter()
            .map(|pre| {
                let nonce = if pre.proof.is_some() {
                    pre.account.nonce.private_account_nonce_increment(
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
        let private_count = self.private_accounts().len();
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
                    account: pre.account.clone(),
                    vpk: pre.vpk.clone(),
                    random_seed: pre.random_seed,
                    identifier: pre.identifier,
                    kind: pre
                        .pda_binding
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
                                Some(nsk) if pre.pda_binding.is_none() => {
                                    NullifierPublicKey::from(&nsk)
                                }
                                _ => pre.npk,
                            },
                            commitment_root: self.dummy_commitment_root,
                        },
                    },
                }),
            })
            .collect()
    }

    pub fn public_slots(&self) -> Vec<lee::SlotRef> {
        self.states
            .iter()
            .filter_map(|state| match state {
                State::Public { account, .. } | State::PublicKeycard { account, .. } => {
                    Some(lee::SlotRef {
                        account_id: account.account_id,
                        program: account.slot.as_ref().map(|(program, _)| *program),
                    })
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
    /// The account's full pre-state, which the circuit needs for the commitment.
    account: Account,
    pre_state: Input,
    proof: Option<MembershipProof>,
    random_seed: [u8; 32],
    /// The authority program and seed when this account is a private PDA. Used by
    /// `account_identities()` to select `WitnessKind::Pda` rather than `WitnessKind::Regular`,
    /// and to derive the address the circuit checks the witness against.
    pda_binding: Option<(ProgramId, PdaSeed)>,
}

/// Derives the address a private witness is proven against, mirroring the circuit's check.
fn derive_account_id(
    npk: &NullifierPublicKey,
    vpk: &ViewingPublicKey,
    identifier: Identifier,
    pda_binding: Option<(ProgramId, PdaSeed)>,
) -> AccountId {
    let kind = pda_binding.map_or(
        PrivateAccountKind::Regular(identifier),
        |(program_id, seed)| PrivateAccountKind::Pda {
            program_id,
            seed,
            identifier,
        },
    );
    AccountId::for_private_account(npk, vpk, &kind)
}

fn private_key_tree_acc_preparation(
    wallet: &WalletCore,
    account_id: AccountId,
    program: Option<AccountId>,
) -> Result<AccountPreparedData, ExecutionFailureKind> {
    let Some(from_acc) = wallet.storage.key_chain().private_account(account_id) else {
        return Err(ExecutionFailureKind::KeyNotFoundError);
    };

    let from_identifier = from_acc.kind.identifier();
    // The stored kind is what `private_account` matched `account_id` against, so its binding
    // reproduces the address the circuit derives from the witness.
    let pda_binding = match from_acc.kind {
        PrivateAccountKind::Pda {
            program_id, seed, ..
        } => Some((*program_id, *seed)),
        PrivateAccountKind::Regular(_) => None,
    };
    let from_keys = &from_acc.key_chain;
    // A PDA is program-authorized and carries no credential of its own.
    let ask = pda_binding
        .is_none()
        .then_some(from_keys.private_key_holder.authorization_secret_key);
    let nsk = from_keys.private_key_holder.nullifier_secret_key();
    let from_npk = from_keys.nullifier_public_key;
    let from_vpk = from_keys.viewing_public_key.clone();

    // TODO: Technically we could allow unauthorized owned accounts, but currently we don't have
    // support from that in the wallet.
    let account = from_acc.account.clone();
    let sender_pre = public_input(&account, ask.is_some(), account_id, program);

    let random_seed = random_bytes();

    Ok(AccountPreparedData {
        ask,
        account,
        nsk: Some(nsk),
        npk: from_npk,
        identifier: from_identifier,
        vpk: from_vpk,
        pre_state: sender_pre,
        proof: None,
        random_seed,
        pda_binding,
    })
}

/// Prepare a private account with no secret key knowledge, i.e. for inits.
fn private_foreign_acc_preparation(
    npk: NullifierPublicKey,
    vpk: ViewingPublicKey,
    identifier: Identifier,
    pda_binding: Option<(ProgramId, PdaSeed)>,
    program: Option<AccountId>,
) -> AccountPreparedData {
    let account_id = derive_account_id(&npk, &vpk, identifier, pda_binding);
    AccountPreparedData {
        account: Account::default(),
        // The wallet holds no key for a recipient, so it can neither spend the account nor
        // consent on its behalf. The program still claims it: a private claim never requires
        // authorization.
        ask: None,
        nsk: None,
        npk,
        identifier,
        vpk,
        pre_state: public_input(&Account::default(), false, account_id, program),
        proof: None,
        random_seed: random_bytes(),
        pda_binding,
    }
}

fn private_shared_acc_preparation(
    wallet: &WalletCore,
    nsk: NullifierSecretKey,
    vpk: ViewingPublicKey,
    identifier: Identifier,
    ask: Option<AuthorizationSecretKey>,
    pda_binding: Option<(ProgramId, PdaSeed)>,
    program: Option<AccountId>,
) -> AccountPreparedData {
    let npk = NullifierPublicKey::from(&nsk);
    let account_id = derive_account_id(&npk, &vpk, identifier, pda_binding);
    let acc = wallet
        .storage()
        .key_chain()
        .shared_private_account(account_id)
        .map(|e| e.account.clone())
        .unwrap_or_default();

    let pre_state = public_input(&acc, ask.is_some(), account_id, program);

    let random_seed = random_bytes();

    AccountPreparedData {
        ask,
        account: acc,
        nsk: Some(nsk),
        npk,
        identifier,
        vpk,
        pre_state,
        proof: None,
        random_seed,
        pda_binding,
    }
}

/// One account, one note: the circuit emits a single commitment per private account however
/// many of its namespaces a transaction touches, and rejects positions whose witnesses disagree.
/// Every witness field but the seed is derived from the identity or the wallet store, so aligning
/// later positions on the first one's seed is what makes two namespaces at one account provable.
fn align_private_seeds(states: &mut [State]) {
    let mut seen: Vec<(AccountId, [u8; 32])> = Vec::new();
    for state in states {
        let State::Private(pre) = state else {
            continue;
        };
        let account_id = pre.pre_state.account_id;
        match seen.iter().find(|(id, _)| *id == account_id) {
            Some((_, seed)) => pre.random_seed = *seed,
            None => seen.push((account_id, pre.random_seed)),
        }
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
                Some((pre.as_mut(), commitment))
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

/// Generates a dummy note: random bytes sized to a single-slot account's ciphertext, a real
/// ML-KEM ciphertext epk toward a throwaway key, and a random view tag.
fn random_dummy_note() -> EncryptedAccountData {
    // A real note always carries at least one occupied slot, so a default (slotless) account
    // would size dummies below every real note. Neither the program nor the balance affects the
    // encoded length; matching accounts with data or further slots is a separate issue.
    let single_slot = Account::single(DEFAULT_PROGRAM_ID, 1, Data::empty(), Nonce::default());
    let ciphertext_len = PrivateAccountKind::HEADER_LEN
        .checked_add(single_slot.to_bytes().len())
        .expect("dummy ciphertext length fits in usize");
    let throwaway_ek = MlKem768EncapsulationKey::from_seed(&random_bytes(), &random_bytes());
    let (_, epk) = SharedSecretKey::encapsulate(&throwaway_ek);
    EncryptedAccountData {
        ciphertext: Ciphertext::from_inner(random_vec(ciphertext_len)),
        epk,
        view_tag: random_view_tag(),
    }
}

/// Narrows a fetched account to the one namespace this position names.
fn public_input(
    account: &Account,
    is_authorized: bool,
    account_id: AccountId,
    program: Option<AccountId>,
) -> Input {
    Input {
        account_id,
        is_authorized,
        slot: program.map(|program| (program, account.slot_or_empty(program))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn private_shared_is_private() {
        let acc = Identity::PrivateShared {
            ask: AuthorizationSecretKey([0; 32]),
            vpk: ViewingPublicKey::from_seed(&[2_u8; 32], &[3_u8; 32]),
            identifier: 42,
        };
        assert!(acc.is_private());
        assert!(!acc.is_public());
    }

    /// A private position at the account `tag` names, reading `program`'s namespace.
    fn private_position(tag: u8, program: lee::AccountId, seed: [u8; 32]) -> State {
        let npk = NullifierPublicKey([tag; 32]);
        let vpk = ViewingPublicKey::from_seed(&[0; 32], &[0; 32]);
        let pre_state = public_input(
            &Account::default(),
            false,
            (&npk, &vpk, 0).into(),
            Some(program),
        );
        State::Private(Box::new(AccountPreparedData {
            ask: None,
            account: Account::default(),
            nsk: None,
            npk,
            identifier: 0,
            vpk,
            pre_state,
            proof: None,
            random_seed: seed,
            pda_binding: None,
        }))
    }

    fn private_state(tag: u8) -> State {
        private_position(
            tag,
            lee::AccountId::from(programs::authenticated_transfer().id()),
            [0; 32],
        )
    }

    fn public_state() -> State {
        let npk = NullifierPublicKey([0; 32]);
        let vpk = ViewingPublicKey::from_seed(&[0; 32], &[0; 32]);
        let account = public_input(
            &Account::default(),
            false,
            (&npk, &vpk, 0).into(),
            Some(lee::AccountId::from(
                programs::authenticated_transfer().id(),
            )),
        );
        State::Public {
            account,
            nonce: Nonce::default(),
            sk: None,
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
    fn foreign_private_init_is_unauthorized() {
        let npk = NullifierPublicKey([7; 32]);
        let vpk = ViewingPublicKey::from_seed(&[8; 32], &[9; 32]);
        let account_id = lee::AccountId::from((&npk, &vpk, 0));
        let pre = private_foreign_acc_preparation(
            npk,
            vpk,
            0,
            None,
            Some(lee::AccountId::from(
                programs::authenticated_transfer().id(),
            )),
        );
        assert_eq!(pre.pre_state.account_id, account_id);

        assert!(pre.ask.is_none());
        assert!(!pre.pre_state.is_authorized);

        let identities = manager(vec![State::Private(Box::new(pre))]).account_identities();
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
            manager(vec![private_state(1), private_state(2)])
                .dummy_inputs_default()
                .len(),
            max - 2
        );
        assert_eq!(
            manager(vec![private_state(1), public_state(), private_state(2)])
                .dummy_inputs_default()
                .len(),
            max - 2
        );

        // If the private accounts in the transaction exceed the max, no padding
        // is done.
        let max_tag = u8::try_from(max).expect("the padding max fits in a tag");
        let full: Vec<State> = (0..max_tag).map(private_state).collect();
        assert_eq!(manager(full).dummy_inputs_default().len(), 0);
        let over: Vec<State> = (0..max_tag.saturating_add(2)).map(private_state).collect();
        assert_eq!(manager(over).dummy_inputs_default().len(), 0);
    }

    /// Two namespaces at one account are one note, so they consume one padding slot, not two.
    /// Counting positions would leave the transaction one note short of the anonymity set.
    #[test]
    fn two_namespaces_at_one_account_pad_as_one_note() {
        let other = lee::AccountId::from(programs::faucet().id());
        let states = vec![
            private_state(1),
            private_position(1, other, [0; 32]),
            private_state(2),
        ];
        let manager = manager(states);

        assert_eq!(manager.private_account_keys().len(), 2);
        assert_eq!(
            manager.dummy_inputs_default().len(),
            AccountManager::MAX_PRIVATE_ACCOUNTS - 2
        );
    }

    /// The circuit rejects positions of one account whose witnesses disagree, and the seed is
    /// the only witness field the wallet draws fresh per position.
    #[test]
    fn positions_of_one_account_share_a_seed() {
        let other = lee::AccountId::from(programs::faucet().id());
        let mut states = vec![
            private_state(1),
            private_position(1, other, [9; 32]),
            private_position(2, other, [4; 32]),
        ];

        align_private_seeds(&mut states);

        let seeds: Vec<[u8; 32]> = states
            .iter()
            .map(|state| match state {
                State::Private(pre) => pre.random_seed,
                State::Public { .. } | State::PublicKeycard { .. } => unreachable!(),
            })
            .collect();
        assert_eq!(seeds[0], seeds[1], "one account, one seed");
        assert_eq!(seeds[2], [4; 32], "a different account keeps its own");
    }
}
