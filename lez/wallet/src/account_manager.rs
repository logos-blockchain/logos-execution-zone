use core::fmt;
use std::{
    collections::{BTreeMap, BTreeSet, HashMap, HashSet},
    future::Future,
};

use anyhow::Result;
use keycard_wallet::KeycardWallet;
use lee::{AccountId, PrivateKey, PublicAccountEvidence, PublicKey, Recipient, Signature};
use lee_core::{
    AuthorizationSecretKey, Commitment, CommitmentSetDigest, DummyInput, DummyOutput,
    MembershipProof, NullifierPublicKey, NullifierSecretKey, NullifierWitness, PrivateAccountKind,
    PrivateWitness, RegularKey, SenderPresentation, SharedSecretKey, WitnessKind,
    account::{Account, Actor, ActorState, Nonce},
    compute_digest_for_path,
    encryption::{Ciphertext, EncryptedNote, MlKem768EncapsulationKey, ViewingPublicKey},
    native_token::NATIVE_TOKEN_PROGRAM_ID,
    program::PdaSeed,
};
use rand::{RngCore as _, rngs::OsRng};

use crate::{ExecutionFailureKind, WalletCore};

/// Length every note ciphertext the wallet emits is padded up to.
///
/// Leaves 427 bytes for actor states, after the 65-byte kind header and the 20 bytes of nonce and
/// actor-state count every `Account` encodes.
/// Token definition and metadata notes carry unbounded strings and can outgrow it; those ship at
/// their own length, which [`WalletCore::send_privacy_preserving_tx_with_pre_check`] warns about.
/// Always on by choice: the only sender who opts out is the distinguishable one.
pub const CIPHERTEXT_PAD_SIZE: u32 = 512;

#[derive(Clone, PartialEq, Eq)]
pub enum AccountIdentity {
    Public(AccountId),
    /// A public account without signing. Would not try to sign, even if account is owned.
    PublicNoSign(AccountId),
    PublicForeign(PublicKey),
    PublicPda {
        program: AccountId,
        seed: PdaSeed,
    },
    /// A public account from keycard. Mandatory signing.
    PublicKeycard {
        account_id: AccountId,
        key_path: String,
    },
    /// A private account whose keys and kind are stored in the wallet.
    PrivateOwned(AccountId),
    /// A private account known only by its public keys and kind: a destination this wallet can
    /// send Casts to but cannot witness.
    PrivateForeign {
        npk: NullifierPublicKey,
        vpk: ViewingPublicKey,
        kind: PrivateAccountKind,
    },
    /// A shared regular private account with externally-provided keys (e.g. from GMS).
    /// Carries the authorization secret key: the `nsk` and `npk` behind
    /// `AccountId = from((&npk, &vpk))` are derived from it.
    /// Works with all existing programs out of the box.
    PrivateShared {
        ask: AuthorizationSecretKey,
        vpk: ViewingPublicKey,
    },
    /// A shared private PDA with externally-provided keys (e.g. from GMS).
    PrivatePdaShared {
        authority: AccountId,
        seed: PdaSeed,
        nsk: NullifierSecretKey,
        vpk: ViewingPublicKey,
    },
}

impl fmt::Debug for AccountIdentity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Public(id) => f.debug_tuple("Public").field(id).finish(),
            Self::PublicNoSign(id) => f.debug_tuple("PublicNoSign").field(id).finish(),
            Self::PublicForeign(pk) => f.debug_tuple("PublicForeign").field(pk).finish(),
            Self::PublicPda { program, seed } => f
                .debug_struct("PublicPda")
                .field("program", program)
                .field("seed", seed)
                .finish(),
            Self::PublicKeycard {
                account_id,
                key_path: _,
            } => f
                .debug_struct("PublicKeycard")
                .field("account_id", account_id)
                .field("key_path", &"<redacted>")
                .finish(),
            Self::PrivateOwned(id) => f.debug_tuple("PrivateOwned").field(id).finish(),
            Self::PrivateForeign { npk, vpk, kind } => f
                .debug_struct("PrivateForeign")
                .field("npk", npk)
                .field("vpk", vpk)
                .field("kind", kind)
                .finish(),
            Self::PrivateShared { vpk, .. } => f
                .debug_struct("PrivateShared")
                .field("ask", &"<redacted>")
                .field("vpk", vpk)
                .finish(),
            Self::PrivatePdaShared {
                authority,
                seed,
                vpk,
                ..
            } => f
                .debug_struct("PrivatePdaShared")
                .field("authority", authority)
                .field("seed", seed)
                .field("nsk", &"<redacted>")
                .field("vpk", vpk)
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
            Self::Public(_)
                | Self::PublicNoSign(_)
                | Self::PublicForeign(_)
                | Self::PublicPda { .. }
                | Self::PublicKeycard { .. }
        )
    }

    /// Returns the `AccountId` for public variants. Used by facades that need the raw ID
    /// for derived-address computation alongside the identity.
    #[must_use]
    pub fn public_account_id(&self) -> Option<lee::AccountId> {
        match self {
            Self::Public(id) | Self::PublicNoSign(id) => Some(*id),
            Self::PublicForeign(pk) => Some(AccountId::from(pk)),
            Self::PublicPda { program, seed } => Some(AccountId::for_public_pda(program, seed)),
            Self::PublicKeycard { account_id, .. } => Some(*account_id),
            Self::PrivateOwned(_)
            | Self::PrivateForeign { .. }
            | Self::PrivateShared { .. }
            | Self::PrivatePdaShared { .. } => None,
        }
    }

    #[must_use]
    pub fn without_signing(self) -> Self {
        match self {
            Self::Public(account_id) | Self::PublicKeycard { account_id, .. } => {
                Self::PublicNoSign(account_id)
            }
            Self::PublicNoSign(_)
            | Self::PublicForeign(_)
            | Self::PublicPda { .. }
            | Self::PrivateOwned(_)
            | Self::PrivateForeign { .. }
            | Self::PrivateShared { .. }
            | Self::PrivatePdaShared { .. } => self,
        }
    }

    #[must_use]
    pub const fn is_private(&self) -> bool {
        matches!(
            &self,
            Self::PrivateOwned(_)
                | Self::PrivateForeign { .. }
                | Self::PrivateShared { .. }
                | Self::PrivatePdaShared { .. }
        )
    }

    #[must_use]
    pub fn account_id(&self) -> AccountId {
        match self {
            Self::Public(id) | Self::PublicNoSign(id) | Self::PrivateOwned(id) => *id,
            Self::PublicForeign(pk) => AccountId::from(pk),
            Self::PublicPda { program, seed } => AccountId::for_public_pda(program, seed),
            Self::PublicKeycard { account_id, .. } => *account_id,
            Self::PrivateForeign { npk, vpk, kind } => {
                AccountId::for_private_account(npk, vpk, kind)
            }
            Self::PrivateShared { ask, vpk } => {
                let npk = NullifierPublicKey::from(&NullifierSecretKey::from(ask));
                AccountId::from((&npk, vpk))
            }
            Self::PrivatePdaShared {
                authority,
                seed,
                nsk,
                vpk,
            } => AccountId::for_private_account(
                &NullifierPublicKey::from(nsk),
                vpk,
                &PrivateAccountKind::Pda {
                    account_id: *authority,
                    seed: *seed,
                },
            ),
        }
    }

    /// Selects `program`'s actor state on this account.
    #[must_use]
    pub fn select_program_actor_state(self, program: AccountId) -> AccountMention {
        AccountMention {
            identity: self,
            program_account_id: program,
            authorizes: true,
            openings: BTreeSet::new(),
        }
        .normalized()
    }

    /// Selects this account's native balance actor state.
    #[must_use]
    pub fn balance(self) -> AccountMention {
        self.select_program_actor_state(NATIVE_TOKEN_PROGRAM_ID)
    }
}

/// An account identity with the program actor state it selects.
#[derive(Clone)]
pub struct AccountMention {
    pub identity: AccountIdentity,
    pub program_account_id: AccountId,
    pub authorizes: bool,
    pub openings: BTreeSet<[u8; 32]>,
}

impl AccountMention {
    #[must_use]
    pub fn actor(&self) -> Actor {
        Actor::new(self.identity.account_id(), self.program_account_id)
    }

    #[must_use]
    pub const fn without_authorization(mut self) -> Self {
        self.authorizes = false;
        self
    }

    // A private account that only receives takes part without spending authority.
    #[must_use]
    pub const fn receiving(self) -> Self {
        if self.identity.is_private() {
            self.without_authorization()
        } else {
            self
        }
    }

    fn normalized(mut self) -> Self {
        if let AccountIdentity::PublicNoSign(account_id) = self.identity {
            self.identity = AccountIdentity::Public(account_id);
            self.authorizes = false;
        }
        self
    }
}

/// An actor state the wallet read. Execution binds the account handle and applies against live
/// state, never this copy.
pub struct SelectedActorState {
    pub selector: Actor,
    pub is_authorized: bool,
    pub data: ActorState,
}

impl SelectedActorState {
    /// Returns the actor state data. Panics unless this row selects `program`'s actor state.
    #[must_use]
    pub fn actor_state_of(&self, program: AccountId) -> &ActorState {
        assert_eq!(
            self.selector.program_account_id, program,
            "SelectedActorState carries another program's actor state"
        );
        &self.data
    }
}

struct PreparedAccount {
    account_id: AccountId,
    account: Account,
}

struct Row {
    account: usize,
    program_account_id: AccountId,
}

/// An account's prepared state and credentials.
enum State {
    Public {
        account: PreparedAccount,
        sk: Option<PrivateKey>,
        admission: Admission,
    },
    PublicKeycard {
        account: PreparedAccount,
        key_path: String,
    },
    Private(Box<AccountPreparedData>),
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum Admission {
    Present,
    Evidence(PublicAccountEvidence),
    Missing,
}

impl Admission {
    fn of(present: bool, evidence: Option<PublicAccountEvidence>) -> Self {
        if present {
            Self::Present
        } else {
            evidence.map_or(Self::Missing, Self::Evidence)
        }
    }
}

impl State {
    fn account(&self) -> &PreparedAccount {
        match self {
            Self::Public { account, .. } | Self::PublicKeycard { account, .. } => account,
            Self::Private(pre) => &pre.pre_state,
        }
    }

    fn account_id(&self) -> AccountId {
        self.account().account_id
    }

    fn is_authorized(&self) -> bool {
        match self {
            Self::Public { sk, .. } => sk.is_some(),
            Self::PublicKeycard { .. } => true,
            Self::Private(pre) => pre.kind.is_authorized(),
        }
    }

    fn selected(&self, selector: Actor) -> SelectedActorState {
        SelectedActorState {
            selector,
            is_authorized: self.is_authorized(),
            data: self
                .account()
                .account
                .data
                .actor_state(selector.program_account_id)
                .clone(),
        }
    }
}

pub struct AccountManager {
    states: Vec<State>,
    rows: Vec<Row>,
    pin: Option<String>,
    dummy_commitment_root: CommitmentSetDigest,
    message_path: Option<MembershipProof>,
}

impl AccountManager {
    /// The private-action count, one per private account and one for a received message, that
    /// every privacy-preserving transaction is padded up to with dummy inputs via the default
    /// interface.
    ///
    /// The value is selected based on the largest account number per-tx currently supported
    /// (it is 7 for AMM). It is recommended to reassess this value per new actively supported
    /// application and that all users share the value for a larger anonymity set.
    const PADDED_PRIVATE_ACTIONS: usize = 7;

    pub async fn new(
        wallet: &WalletCore,
        mentions: Vec<AccountMention>,
        message: Option<(u64, Commitment)>,
    ) -> Result<Self, ExecutionFailureKind> {
        let mut states: Vec<State> = Vec::new();
        let mut rows = Vec::with_capacity(mentions.len());
        let mut prepared: HashMap<AccountId, (usize, AccountIdentity, bool)> = HashMap::new();
        let mut pin = None;

        for mention in mentions {
            let AccountMention {
                identity,
                program_account_id,
                authorizes,
                openings,
            } = mention.normalized();
            let account_id = identity.account_id();
            let actor_state_selector = Actor::new(account_id, program_account_id);

            let known =
                prepared
                    .get(&account_id)
                    .map(|(index, prepared_identity, prepared_authorizes)| {
                        (
                            *index,
                            *prepared_identity == identity && *prepared_authorizes == authorizes,
                        )
                    });

            let index = match known {
                Some((_, false)) => {
                    return Err(ExecutionFailureKind::ConflictingAccountIdentity(account_id));
                }
                Some((index, true)) => {
                    if let State::Public { account, .. } | State::PublicKeycard { account, .. } =
                        &mut states[index]
                    {
                        let view = public_account_view(wallet, actor_state_selector)
                            .await?
                            .unwrap_or_default();
                        merge_public_view(account, &view)?;
                    }
                    index
                }
                None => {
                    let index = states.len();
                    states.push(
                        prepare_account(
                            wallet,
                            identity.clone(),
                            actor_state_selector,
                            authorizes,
                            &mut pin,
                        )
                        .await?,
                    );
                    prepared.insert(account_id, (index, identity, authorizes));
                    index
                }
            };

            if let State::Private(pre) = &mut states[index] {
                pre.openings.extend(openings);
            }
            rows.push(Row {
                account: index,
                program_account_id,
            });
        }

        let (dummy_commitment_root, message_path) =
            fetch_private_proofs_and_root(wallet, &mut states, message).await?;

        Ok(Self {
            states,
            rows,
            pin,
            dummy_commitment_root,
            message_path,
        })
    }

    fn row_selector(&self, row: &Row) -> Actor {
        Actor::new(
            self.states[row.account].account_id(),
            row.program_account_id,
        )
    }

    /// The selected actor states, in declaration order.
    pub fn selected_actor_states(&self) -> Vec<SelectedActorState> {
        self.rows
            .iter()
            .map(|row| self.states[row.account].selected(self.row_selector(row)))
            .collect()
    }

    // The declared public actors' states as read, from which the prover derives the boundary.
    pub fn public_actor_states(&self) -> HashMap<Actor, ActorState> {
        self.rows
            .iter()
            .filter(|row| !matches!(self.states[row.account], State::Private(_)))
            .map(|row| {
                let actor_state = self.states[row.account].selected(self.row_selector(row));
                (actor_state.selector, actor_state.data)
            })
            .collect()
    }

    // In mention order, deduplicated.
    pub fn public_actors(&self) -> Vec<Actor> {
        let mut actors = Vec::new();
        for row in &self.rows {
            let actor = self.row_selector(row);
            if !matches!(self.states[row.account], State::Private(_)) && !actors.contains(&actor) {
                actors.push(actor);
            }
        }
        actors
    }

    /// The public accounts whose signature this transaction carries.
    pub fn signers(&self) -> HashSet<AccountId> {
        self.states
            .iter()
            .filter_map(|state| match state {
                State::Public {
                    account,
                    sk: Some(_),
                    ..
                }
                | State::PublicKeycard { account, .. } => Some(account.account_id),
                State::Public { sk: None, .. } | State::Private(_) => None,
            })
            .collect()
    }

    pub fn admission_evidence(&self) -> Vec<PublicAccountEvidence> {
        self.states
            .iter()
            .filter_map(|state| match state {
                State::Public {
                    sk: None,
                    admission: Admission::Evidence(evidence),
                    ..
                } => Some(evidence.clone()),
                State::Public { .. } | State::PublicKeycard { .. } | State::Private(_) => None,
            })
            .collect()
    }

    pub fn admitted_accounts(&self) -> BTreeSet<AccountId> {
        self.states
            .iter()
            .filter_map(|state| match state {
                State::Public {
                    sk: None,
                    admission: Admission::Missing,
                    ..
                }
                | State::Private(_) => None,
                State::Public { account, .. } | State::PublicKeycard { account, .. } => {
                    Some(account.account_id)
                }
            })
            .collect()
    }

    pub fn public_account_nonces(&self) -> BTreeMap<AccountId, Nonce> {
        self.states
            .iter()
            .filter_map(|state| match state {
                State::Public {
                    account,
                    sk: Some(_),
                    ..
                }
                | State::PublicKeycard { account, .. } => {
                    Some((account.account_id, account.account.nonce))
                }
                State::Public { sk: None, .. } | State::Private(_) => None,
            })
            .collect()
    }

    pub fn shared_secrets(&self) -> Vec<SharedSecretKey> {
        self.private_states()
            .map(|pre| {
                let nonce = pre
                    .pre_state
                    .account
                    .nonce
                    .private_account_nonce_increment(&pre.kind.nsk());
                let esk = lee_core::EphemeralSecretKey::new(
                    &pre.pre_state.account_id,
                    &pre.random_seed,
                    &nonce,
                );
                SharedSecretKey::encapsulate_deterministic(&pre.vpk, &esk).0
            })
            .collect()
    }

    /// Given a count, generate that many dummy inputs with randomized seeds and notes.
    /// Uses the given commitment root from the account.
    pub fn dummy_inputs(&self, count: usize) -> Vec<DummyInput> {
        std::iter::repeat_with(|| DummyInput {
            nullifier_seed: random_bytes(),
            commitment_root: self.dummy_commitment_root,
            output: dummy_output(),
        })
        .take(count)
        .collect()
    }

    /// Generate the dummy inputs that pad this transaction's private-action count up to
    /// `PADDED_PRIVATE_ACTIONS`.
    pub fn dummy_inputs_default(&self) -> Vec<DummyInput> {
        let action_count = self
            .private_states()
            .count()
            .saturating_add(usize::from(self.message_path.is_some()));
        if action_count > Self::PADDED_PRIVATE_ACTIONS {
            log::warn!(
                "private action count {action_count} exceeds PADDED_PRIVATE_ACTIONS ({}); \
                 padding saturates and the private-action count is not hidden",
                Self::PADDED_PRIVATE_ACTIONS
            );
        }
        self.dummy_inputs(Self::PADDED_PRIVATE_ACTIONS.saturating_sub(action_count))
    }

    /// The membership path of the message this transaction receives, from the snapshot that
    /// proves its accounts.
    pub const fn message_path(&self) -> Option<&MembershipProof> {
        self.message_path.as_ref()
    }

    /// Private accounts whose note already outgrows [`CIPHERTEXT_PAD_SIZE`], and so ship at their
    /// own length among uniformly sized ones.
    pub(crate) fn accounts_outgrowing_pad(&self) -> Vec<AccountId> {
        let pad = usize::try_from(CIPHERTEXT_PAD_SIZE).expect("pad size fits in usize");
        self.private_states()
            .filter_map(|pre| {
                (note_plaintext_len(&pre.pre_state.account) > pad)
                    .then_some(pre.pre_state.account_id)
            })
            .collect()
    }

    fn private_states(&self) -> impl Iterator<Item = &AccountPreparedData> {
        self.states.iter().filter_map(|state| match state {
            State::Private(pre) => Some(pre.as_ref()),
            State::Public { .. } | State::PublicKeycard { .. } => None,
        })
    }

    /// Builds a witness for each private account, including all its actor states.
    pub fn private_witnesses(&self) -> Result<Vec<PrivateWitness>, ExecutionFailureKind> {
        self.private_states()
            .map(|pre| {
                Ok(PrivateWitness {
                    vpk: pre.vpk.clone(),
                    random_seed: pre.random_seed,
                    kind: pre.kind.clone(),
                    nullifier: match pre.proof.clone() {
                        Some(membership_proof) => NullifierWitness::Update {
                            account: pre.pre_state.account.clone(),
                            membership_proof,
                        },
                        None if pre.pre_state.account != Account::default() => {
                            return Err(ExecutionFailureKind::MissingMembershipProof(
                                pre.pre_state.account_id,
                            ));
                        }
                        None => NullifierWitness::Init {
                            commitment_root: self.dummy_commitment_root,
                        },
                    },
                    openings: pre.openings.clone(),
                })
            })
            .collect()
    }

    // A private account presents a fresh random alias for each message.
    pub fn presenter(&self) -> impl FnMut(Actor) -> SenderPresentation + Send + 'static {
        let private: HashSet<AccountId> = self
            .private_states()
            .map(|pre| pre.pre_state.account_id)
            .collect();
        move |sender| {
            if private.contains(&sender.account_id) {
                SenderPresentation::Blinded(random_bytes())
            } else {
                SenderPresentation::Canonical
            }
        }
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
    pub async fn fee_payer_account_id(
        &mut self,
        wallet: &WalletCore,
    ) -> Result<Option<AccountId>, ExecutionFailureKind> {
        self.fee_payer_account_id_with(|selector| async move {
            public_account_view(wallet, selector)
                .await
                .map(Option::unwrap_or_default)
        })
        .await
    }

    /// [`Self::fee_payer_account_id`] over an injected balance read, so the selection policy is
    /// exercisable without a wallet. A candidate whose native actor state is already materialised
    /// is never fetched, and the walk stops at the first funded signer.
    async fn fee_payer_account_id_with<F, Fut>(
        &mut self,
        mut fetch_view: F,
    ) -> Result<Option<AccountId>, ExecutionFailureKind>
    where
        F: FnMut(Actor) -> Fut,
        Fut: Future<Output = Result<Account, ExecutionFailureKind>>,
    {
        let mut first_signer = None;
        for index in 0..self.states.len() {
            let (State::Public {
                account,
                sk: Some(_),
                ..
            }
            | State::PublicKeycard { account, .. }) = &mut self.states[index]
            else {
                continue;
            };
            first_signer.get_or_insert(account.account_id);
            if !account
                .account
                .data
                .actor_states
                .contains_key(&NATIVE_TOKEN_PROGRAM_ID)
            {
                let view = fetch_view(Actor::native_balance(account.account_id)).await?;
                merge_public_view(account, &view)?;
            }
            if account
                .account
                .data
                .native_balance()
                .is_ok_and(|balance| balance > 0)
            {
                return Ok(Some(account.account_id));
            }
        }

        Ok(first_signer)
    }

    /// Whether `account_id` is a public account whose signature [`Self::sign_message`] produces.
    pub fn signs_for(&self, account_id: AccountId) -> bool {
        self.states.iter().any(|state| match state {
            State::Public {
                account,
                sk: Some(_),
                ..
            }
            | State::PublicKeycard { account, .. } => account.account_id == account_id,
            State::Public { sk: None, .. } | State::Private(_) => false,
        })
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
    kind: WitnessKind,
    vpk: ViewingPublicKey,
    pre_state: PreparedAccount,
    proof: Option<MembershipProof>,
    random_seed: [u8; 32],
    openings: BTreeSet<[u8; 32]>,
}

/// Builds a witness kind from the account kind and the key holding the account.
/// PDAs use their authority and seed instead of an authorization key, and hold only its `nsk`.
fn witness_kind(kind: &PrivateAccountKind, key: RegularKey) -> WitnessKind {
    match kind {
        PrivateAccountKind::Regular => WitnessKind::Regular(key),
        PrivateAccountKind::Pda {
            account_id, seed, ..
        } => WitnessKind::Pda {
            nsk: key.nsk(),
            binding: (*account_id, *seed),
        },
    }
}

async fn public_account_view(
    wallet: &WalletCore,
    actor_state_selector: Actor,
) -> Result<Option<Account>, ExecutionFailureKind> {
    wallet
        .get_account_view(actor_state_selector)
        .await
        .map_err(ExecutionFailureKind::SequencerError)
}

fn merge_public_view(
    prepared: &mut PreparedAccount,
    view: &Account,
) -> Result<(), ExecutionFailureKind> {
    if prepared.account.nonce != view.nonce {
        return Err(ExecutionFailureKind::SequencerError(anyhow::anyhow!(
            "Account views of {} disagree on the nonce",
            prepared.account_id,
        )));
    }
    prepared.account.data.update(&view.data);
    Ok(())
}

async fn prepare_public_account(
    wallet: &WalletCore,
    actor_state_selector: Actor,
) -> Result<(PreparedAccount, bool), ExecutionFailureKind> {
    let view = public_account_view(wallet, actor_state_selector).await?;
    let present = view.is_some();
    Ok((
        PreparedAccount {
            account_id: actor_state_selector.account_id,
            account: view.unwrap_or_default(),
        },
        present,
    ))
}

async fn prepare_account(
    wallet: &WalletCore,
    identity: AccountIdentity,
    actor_state_selector: Actor,
    authorizes: bool,
    pin: &mut Option<String>,
) -> Result<State, ExecutionFailureKind> {
    let account_id = actor_state_selector.account_id;
    let owned_key = wallet.get_account_public_signing_key(account_id);
    let (sk, evidence) = match identity {
        AccountIdentity::Public(_) => (
            owned_key.filter(|_| authorizes).cloned(),
            owned_key.map(key_evidence),
        ),
        AccountIdentity::PublicKeycard { key_path, .. } if authorizes => {
            let (account, _) = prepare_public_account(wallet, actor_state_selector).await?;
            if pin.is_none() {
                *pin = Some(
                    crate::helperfunctions::read_pin()
                        .map_err(ExecutionFailureKind::SignError)?
                        .as_str()
                        .to_owned(),
                );
            }
            return Ok(State::PublicKeycard { account, key_path });
        }
        AccountIdentity::PublicNoSign(_) | AccountIdentity::PublicKeycard { .. } => {
            (None, owned_key.map(key_evidence))
        }
        AccountIdentity::PublicForeign(pk) => (None, Some(PublicAccountEvidence::Key(pk))),
        AccountIdentity::PublicPda { program, seed } => {
            (None, Some(PublicAccountEvidence::Pda { program, seed }))
        }
        AccountIdentity::PrivateOwned(_) => {
            let managed = wallet
                .storage
                .key_chain()
                .managed_private_account(account_id)
                .ok_or(ExecutionFailureKind::KeyNotFoundError)?;
            return Ok(State::Private(Box::new(prepared_data(
                account_id,
                managed.account.clone(),
                witness_kind(
                    managed.kind,
                    regular_key(managed.keys.authorization_secret_key, authorizes),
                ),
                managed.vpk,
            ))));
        }
        AccountIdentity::PrivateForeign { .. } => {
            return Err(ExecutionFailureKind::ForeignPrivateAccount(account_id));
        }
        AccountIdentity::PrivateShared { ask, vpk } => {
            return Ok(State::Private(Box::new(private_shared_acc_preparation(
                wallet,
                account_id,
                vpk,
                WitnessKind::Regular(regular_key(ask, authorizes)),
            ))));
        }
        AccountIdentity::PrivatePdaShared {
            authority,
            seed,
            nsk,
            vpk,
        } => {
            let kind = PrivateAccountKind::Pda {
                account_id: authority,
                seed,
            };
            return Ok(State::Private(Box::new(private_shared_acc_preparation(
                wallet,
                account_id,
                vpk,
                witness_kind(&kind, RegularKey::Nullifying(nsk)),
            ))));
        }
    };
    let (account, present) = prepare_public_account(wallet, actor_state_selector).await?;
    Ok(State::Public {
        account,
        sk,
        admission: Admission::of(present, evidence),
    })
}

fn regular_key(ask: AuthorizationSecretKey, authorizes: bool) -> RegularKey {
    if authorizes {
        RegularKey::Authorized(ask)
    } else {
        RegularKey::Nullifying(NullifierSecretKey::from(&ask))
    }
}

fn key_evidence(key: &PrivateKey) -> PublicAccountEvidence {
    PublicAccountEvidence::Key(PublicKey::new_from_private_key(key))
}

fn private_shared_acc_preparation(
    wallet: &WalletCore,
    account_id: AccountId,
    vpk: ViewingPublicKey,
    kind: WitnessKind,
) -> AccountPreparedData {
    let account = wallet
        .private_account_state(account_id)
        .cloned()
        .unwrap_or_default();
    prepared_data(account_id, account, kind, vpk)
}

fn prepared_data(
    account_id: AccountId,
    account: Account,
    kind: WitnessKind,
    vpk: ViewingPublicKey,
) -> AccountPreparedData {
    AccountPreparedData {
        kind,
        vpk,
        pre_state: PreparedAccount {
            account_id,
            account,
        },
        proof: None,
        random_seed: random_bytes(),
        openings: BTreeSet::new(),
    }
}

async fn fetch_private_proofs_and_root(
    wallet: &WalletCore,
    states: &mut [State],
    message: Option<(u64, Commitment)>,
) -> Result<(CommitmentSetDigest, Option<MembershipProof>), ExecutionFailureKind> {
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

    let (proofs, message_path, root) = wallet
        .get_proofs_and_root(&commitments, message.map(|(position, _)| position))
        .await
        .map_err(ExecutionFailureKind::SequencerError)?;

    validate_proofs_against_root(&commitments, &proofs, root)?;
    let message_path = message
        .map(|message| message_path_at(message, message_path, root))
        .transpose()?;

    for (pre, proof) in private.iter_mut().zip(proofs) {
        pre.proof = proof;
    }

    Ok((root, message_path))
}

// The received message's path, if it sits at the requested position and reproduces `root`.
fn message_path_at(
    (position, commitment): (u64, Commitment),
    path: Option<MembershipProof>,
    root: CommitmentSetDigest,
) -> Result<MembershipProof, ExecutionFailureKind> {
    path.filter(|(path_position, path)| {
        *path_position == position
            && compute_digest_for_path(&commitment, position, path) == Ok(root)
    })
    .ok_or_else(|| {
        ExecutionFailureKind::SequencerError(anyhow::anyhow!(
            "No membership proof of the message at {position} reproduces the root {root:?}."
        ))
    })
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
        if let Some((position, path)) = proof
            && compute_digest_for_path(commitment, *position, path) != Ok(root)
        {
            return Err(ExecutionFailureKind::SequencerError(anyhow::anyhow!(
                "Membership proof for {commitment:?} does not reproduce the appropriate root {root:?}.",
            )));
        }
    }

    Ok(())
}

// The derivation a recovery binding proves for a private identity, at its canonical address.
pub fn recipient(wallet: &WalletCore, identity: &AccountIdentity) -> Option<Recipient> {
    let (npk, vpk, kind) = match identity {
        AccountIdentity::PrivateOwned(account_id) => {
            let managed = wallet
                .storage
                .key_chain()
                .managed_private_account(*account_id)?;
            (
                managed.keys.generate_nullifier_public_key(),
                managed.vpk,
                managed.kind.clone(),
            )
        }
        AccountIdentity::PrivateForeign { npk, vpk, kind } => (*npk, vpk.clone(), kind.clone()),
        AccountIdentity::PrivateShared { ask, vpk } => (
            NullifierPublicKey::from(&NullifierSecretKey::from(ask)),
            vpk.clone(),
            PrivateAccountKind::Regular,
        ),
        AccountIdentity::PrivatePdaShared {
            authority,
            seed,
            nsk,
            vpk,
        } => (
            NullifierPublicKey::from(nsk),
            vpk.clone(),
            PrivateAccountKind::Pda {
                account_id: *authority,
                seed: *seed,
            },
        ),
        AccountIdentity::Public(_)
        | AccountIdentity::PublicNoSign(_)
        | AccountIdentity::PublicForeign(_)
        | AccountIdentity::PublicPda { .. }
        | AccountIdentity::PublicKeycard { .. } => return None,
    };
    Some(Recipient {
        npk,
        vpk,
        kind,
        opening: None,
    })
}

pub fn random_bytes() -> [u8; 32] {
    let mut bytes = [0; 32];
    OsRng.fill_bytes(&mut bytes);
    bytes
}

/// Plaintext length of the note a private account encrypts to.
fn note_plaintext_len(account: &Account) -> usize {
    PrivateAccountKind::HEADER_LEN
        .checked_add(account.to_bytes().len())
        .expect("note plaintext length fits in usize")
}

fn random_vec(len: usize) -> Vec<u8> {
    let mut bytes = vec![0; len];
    OsRng.fill_bytes(&mut bytes);
    bytes
}

/// Generates the output of an action that creates no account state: a fresh commitment seed and
/// a dummy note.
pub fn dummy_output() -> DummyOutput {
    DummyOutput {
        commitment_seed: random_bytes(),
        note: random_dummy_note(),
    }
}

/// Generates a dummy note: random bytes sized to [`CIPHERTEXT_PAD_SIZE`] and a real ML-KEM
/// ciphertext epk toward a throwaway key.
fn random_dummy_note() -> EncryptedNote {
    let ciphertext_len = usize::try_from(CIPHERTEXT_PAD_SIZE).expect("pad size fits in usize");
    let throwaway_ek = MlKem768EncapsulationKey::from_seed(&random_bytes(), &random_bytes());
    let (_, epk) = SharedSecretKey::encapsulate(&throwaway_ek);
    EncryptedNote {
        ciphertext: Ciphertext::from_inner(random_vec(ciphertext_len)),
        epk,
    }
}

#[cfg(test)]
mod tests {

    use std::future::{Ready, ready};

    use futures::executor::block_on;

    use super::*;

    #[test]
    fn private_shared_is_private() {
        let acc = AccountIdentity::PrivateShared {
            ask: AuthorizationSecretKey([0; 32]),
            vpk: ViewingPublicKey::from_seed(&[2_u8; 32], &[3_u8; 32]),
        };
        assert!(acc.is_private());
        assert!(!acc.is_public());
    }

    fn private_state() -> State {
        let npk = NullifierPublicKey([0; 32]);
        let vpk = ViewingPublicKey::from_seed(&[0; 32], &[0; 32]);
        let account_id = lee::AccountId::from((&npk, &vpk));
        let pre_state = PreparedAccount {
            account_id,
            account: Account::default(),
        };
        State::Private(Box::new(AccountPreparedData {
            kind: WitnessKind::Regular(RegularKey::Nullifying([0; 32])),
            vpk,
            pre_state,
            proof: None,
            random_seed: [0; 32],
            openings: BTreeSet::new(),
        }))
    }

    fn public_state() -> State {
        let npk = NullifierPublicKey([0; 32]);
        let vpk = ViewingPublicKey::from_seed(&[0; 32], &[0; 32]);
        let account_id = lee::AccountId::from((&npk, &vpk));
        let account = PreparedAccount {
            account_id,
            account: Account::default(),
        };
        State::Public {
            account,
            sk: None,
            admission: Admission::Present,
        }
    }

    fn public_signing_state(seed: u8, balance: u128) -> State {
        public_signing_state_with(seed, Account::funded(balance))
    }

    fn public_signing_state_with(seed: u8, account: Account) -> State {
        let sk = lee::PrivateKey::try_new([seed; 32]).expect("valid key");
        let account_id = lee::AccountId::from(&lee::PublicKey::new_from_private_key(&sk));
        State::Public {
            account: PreparedAccount {
                account_id,
                account,
            },
            sk: Some(sk),
            admission: Admission::Present,
        }
    }

    /// A balance read that fails the test if the walk reaches it.
    fn never_fetches(selector: Actor) -> Ready<Result<Account, ExecutionFailureKind>> {
        panic!(
            "the payer walk must not read a balance it already holds, got {}",
            selector.account_id
        )
    }

    fn answers(
        account: &Account,
    ) -> impl FnMut(Actor) -> Ready<Result<Account, ExecutionFailureKind>> {
        let account = account.clone();
        move |_| ready(Ok(account.clone()))
    }

    fn payer(
        manager: &mut AccountManager,
        fetch: impl FnMut(Actor) -> Ready<Result<Account, ExecutionFailureKind>>,
    ) -> Option<AccountId> {
        block_on(manager.fee_payer_account_id_with(fetch)).expect("the walk succeeds")
    }

    fn manager(states: Vec<State>) -> AccountManager {
        let rows = (0..states.len())
            .map(|account| Row {
                account,
                program_account_id: NATIVE_TOKEN_PROGRAM_ID,
            })
            .collect();
        AccountManager {
            states,
            rows,
            pin: None,
            dummy_commitment_root: [0; 32],
            message_path: None,
        }
    }

    #[test]
    fn fee_payer_is_the_first_funded_public_signing_account() {
        let first_signing = public_signing_state(1, 1_000);
        let expected = first_signing.account().account_id;
        let mut manager = manager(vec![
            private_state(),
            first_signing,
            public_signing_state(2, 1_000),
        ]);
        assert_eq!(payer(&mut manager, never_fetches), Some(expected));
    }

    #[test]
    fn fee_payer_skips_a_non_signing_public_account() {
        // A tracked but unsignable public account (sk: None, e.g. an AMM pool
        // or definition PDA passed as a non-signing input) must not be
        // designated payer -- the first funded signing account is chosen instead.
        let signing = public_signing_state(3, 1_000);
        let signing_id = signing.account().account_id;
        let mut manager = manager(vec![public_state(), signing]);
        assert_eq!(payer(&mut manager, never_fetches), Some(signing_id));
    }

    #[test]
    fn fee_payer_skips_an_unfunded_signing_account_for_a_funded_one() {
        let funded = public_signing_state(5, 1_000);
        let funded_id = funded.account().account_id;
        let mut manager = manager(vec![public_signing_state(4, 0), funded]);
        // The unfunded candidate carries no native actor state, so it is read; the read
        // confirms it is empty and the walk moves on.
        assert_eq!(
            payer(&mut manager, answers(&Account::default())),
            Some(funded_id)
        );
    }

    #[test]
    fn no_public_account_means_no_fee_payer() {
        let mut manager = manager(vec![private_state()]);
        assert_eq!(payer(&mut manager, never_fetches), None);
    }

    #[test]
    fn an_all_unfunded_wallet_falls_back_to_the_first_signing_account() {
        // No signing account is funded, but a fee-exempt transaction still needs a
        // payer id to fill: fall back to the first signing account rather than
        // refuse to build.
        let first = public_signing_state(7, 0);
        let first_id = first.account().account_id;
        let mut manager = manager(vec![first, public_signing_state(8, 0)]);
        assert_eq!(
            payer(&mut manager, answers(&Account::default())),
            Some(first_id)
        );
    }

    #[test]
    fn a_non_signing_public_account_alone_has_no_fee_payer() {
        let mut manager = manager(vec![public_state()]);
        assert_eq!(payer(&mut manager, never_fetches), None);
    }

    #[test]
    fn an_application_scoped_candidate_is_funded_by_the_balance_read() {
        // Prepared for an application actor state alone, so its balance is absent until read.
        let program_id = AccountId::new([9; 32]);
        let scoped = Account::default().with_actor_state(program_id, vec![1_u8; 4].into());
        let candidate = public_signing_state_with(6, scoped);
        let candidate_id = candidate.account().account_id;
        let mut manager = manager(vec![candidate]);

        assert_eq!(
            payer(&mut manager, answers(&Account::funded(500))),
            Some(candidate_id)
        );
        let merged = &manager.states[0].account().account;
        assert_eq!(
            merged.data.native_balance(),
            Ok(500),
            "the read balance is merged in"
        );
        assert_eq!(
            merged.data.actor_state(program_id).as_ref(),
            vec![1_u8; 4],
            "merging a balance read must not drop the application actor state"
        );
    }

    #[test]
    fn a_failed_balance_read_fails_the_walk() {
        let mut manager = manager(vec![public_signing_state(11, 0)]);
        let result = block_on(manager.fee_payer_account_id_with(|_| {
            ready(Err(ExecutionFailureKind::SequencerError(anyhow::anyhow!(
                "sequencer unreachable"
            ))))
        }));
        assert!(
            matches!(result, Err(ExecutionFailureKind::SequencerError(_))),
            "a failed balance read must not be silently treated as unfunded, got {result:?}"
        );
    }

    #[test]
    fn a_balance_read_at_a_different_nonce_fails_the_walk() {
        let mut manager = manager(vec![public_signing_state(12, 0)]);
        let stale = Account {
            nonce: Nonce(7),
            ..Account::funded(1_000)
        };
        let result = block_on(manager.fee_payer_account_id_with(answers(&stale)));
        assert!(
            result.is_err_and(|error| error.to_string().contains("Failed to get data")),
            "a view from a different nonce must not be merged in"
        );
    }

    #[test]
    fn signs_for_only_signing_public_accounts() {
        let signing = public_signing_state(9, 0);
        let State::Public { account, .. } = &signing else {
            unreachable!("public_signing_state builds a public account");
        };
        let signing_id = account.account_id;
        let manager = manager(vec![public_state(), signing]);
        let non_signing_id = manager.public_account_ids()[0];
        assert!(manager.signs_for(signing_id));
        assert!(!manager.signs_for(non_signing_id));
    }

    #[test]
    fn an_owned_pdas_credential_never_becomes_a_regular_one() {
        let ask = AuthorizationSecretKey([5; 32]);
        let authority = AccountId::new([6; 32]);
        let seed = PdaSeed::new([7; 32]);

        let pda = witness_kind(
            &PrivateAccountKind::Pda {
                account_id: authority,
                seed,
            },
            RegularKey::Authorized(ask),
        );
        let regular = witness_kind(&PrivateAccountKind::Regular, RegularKey::Authorized(ask));

        assert!(matches!(
            pda,
            WitnessKind::Pda { nsk, binding }
                if nsk == NullifierSecretKey::from(&ask) && binding == (authority, seed)
        ));
        assert!(matches!(
            regular,
            WitnessKind::Regular(RegularKey::Authorized(_))
        ));
    }

    #[test]
    fn a_keyed_pda_is_derived_from_its_binding_and_stays_unauthorized() {
        let nsk = [1; 32];
        let npk = NullifierPublicKey::from(&nsk);
        let vpk = ViewingPublicKey::from_seed(&[2; 32], &[3; 32]);
        let authority = AccountId::new([4; 32]);
        let seed = PdaSeed::new([5; 32]);
        let kind = PrivateAccountKind::Pda {
            account_id: authority,
            seed,
        };

        let account_id = AccountId::for_private_account(&npk, &vpk, &kind);
        assert_ne!(
            account_id,
            AccountId::for_private_account(&npk, &vpk, &PrivateAccountKind::Regular),
            "the binding is part of the address, not decoration",
        );

        let pre = AccountPreparedData {
            kind: witness_kind(&kind, RegularKey::Nullifying(nsk)),
            vpk,
            pre_state: PreparedAccount {
                account_id,
                account: Account::default(),
            },
            proof: None,
            random_seed: [0; 32],
            openings: BTreeSet::new(),
        };

        let manager = manager(vec![State::Private(Box::new(pre))]);
        assert!(!manager.selected_actor_states()[0].is_authorized);
        let witnesses = manager.private_witnesses().unwrap();
        assert!(matches!(
            &witnesses[0].kind,
            WitnessKind::Pda { nsk: held, binding } if *held == nsk && *binding == (authority, seed)
        ));
        assert!(matches!(
            &witnesses[0].nullifier,
            NullifierWitness::Init { .. }
        ));
    }

    #[test]
    fn an_owned_account_without_authorization_keeps_only_its_nullifier_key() {
        let ask = AuthorizationSecretKey([5; 32]);
        let nsk = NullifierSecretKey::from(&ask);
        let npk = NullifierPublicKey::from(&nsk);
        let vpk = ViewingPublicKey::from_seed(&[2; 32], &[3; 32]);
        let account_id = lee::AccountId::from((&npk, &vpk));
        let owned = State::Private(Box::new(AccountPreparedData {
            kind: witness_kind(&PrivateAccountKind::Regular, regular_key(ask, false)),
            vpk,
            pre_state: PreparedAccount {
                account_id,
                account: Account::funded(5),
            },
            proof: Some((0, Vec::new())),
            random_seed: [0; 32],
            openings: BTreeSet::new(),
        }));

        let manager = manager(vec![owned]);
        assert!(!manager.selected_actor_states()[0].is_authorized);
        let witnesses = manager.private_witnesses().unwrap();
        assert!(matches!(
            witnesses[0].kind,
            WitnessKind::Regular(RegularKey::Nullifying(kept)) if kept == nsk
        ));
        assert!(matches!(
            &witnesses[0].nullifier,
            NullifierWitness::Update { .. }
        ));
    }

    #[test]
    fn a_keycard_account_without_authorization_neither_signs_nor_advances_its_nonce() {
        let account_id = lee::AccountId::new([7; 32]);
        let account = || PreparedAccount {
            account_id,
            account: Account {
                nonce: Nonce(3),
                ..Account::default()
            },
        };

        let signing = manager(vec![State::PublicKeycard {
            account: account(),
            key_path: "m/44'/60'/0'/0/0".to_owned(),
        }]);
        assert!(signing.selected_actor_states()[0].is_authorized);
        assert_eq!(signing.signers(), HashSet::from([account_id]));
        assert_eq!(
            signing.public_account_nonces(),
            BTreeMap::from([(account_id, Nonce(3))])
        );

        let unsigned = manager(vec![State::Public {
            account: account(),
            sk: None,
            admission: Admission::Present,
        }]);
        assert!(!unsigned.selected_actor_states()[0].is_authorized);
        assert!(unsigned.signers().is_empty());
        assert!(unsigned.public_account_nonces().is_empty());
    }

    #[test]
    fn only_an_absent_non_signing_public_account_carries_admission_evidence() {
        let key = lee::PrivateKey::try_new([9; 32]).expect("valid key");
        let key_evidence = PublicAccountEvidence::Key(lee::PublicKey::new_from_private_key(&key));
        assert_eq!(
            Admission::of(false, Some(key_evidence.clone())),
            Admission::Evidence(key_evidence.clone())
        );
        assert_eq!(
            Admission::of(true, Some(key_evidence.clone())),
            Admission::Present
        );
        assert_eq!(Admission::of(false, None), Admission::Missing);

        let signer = lee::PrivateKey::try_new([8; 32]).expect("valid key");
        let signer_evidence =
            PublicAccountEvidence::Key(lee::PublicKey::new_from_private_key(&signer));
        let pda = PublicAccountEvidence::Pda {
            program: AccountId::new([4; 32]),
            seed: PdaSeed::new([5; 32]),
        };
        let public = |sk, admission| State::Public {
            account: PreparedAccount {
                account_id: AccountId::new([1; 32]),
                account: Account::default(),
            },
            sk,
            admission,
        };
        let manager = manager(vec![
            public(None, Admission::Evidence(key_evidence.clone())),
            public(None, Admission::Evidence(pda.clone())),
            public(None, Admission::Present),
            public(Some(signer), Admission::Evidence(signer_evidence.clone())),
            public(None, Admission::Evidence(signer_evidence.clone())),
            private_state(),
        ]);

        assert_eq!(
            manager.admission_evidence(),
            vec![key_evidence, pda, signer_evidence]
        );
    }

    #[test]
    fn admitted_accounts_are_signers_and_accounts_present_or_carrying_evidence() {
        let signer = lee::PrivateKey::try_new([8; 32]).expect("valid key");
        let signer_evidence =
            PublicAccountEvidence::Key(lee::PublicKey::new_from_private_key(&signer));
        let public = |tag, sk, admission| State::Public {
            account: PreparedAccount {
                account_id: AccountId::new([tag; 32]),
                account: Account::default(),
            },
            sk,
            admission,
        };
        let pda = PublicAccountEvidence::Pda {
            program: AccountId::new([4; 32]),
            seed: PdaSeed::new([5; 32]),
        };

        let manager = manager(vec![
            public(1, Some(signer), Admission::Evidence(signer_evidence)),
            public(2, None, Admission::Present),
            public(3, None, Admission::Evidence(pda)),
            public(4, None, Admission::Missing),
            State::PublicKeycard {
                account: PreparedAccount {
                    account_id: AccountId::new([5; 32]),
                    account: Account::default(),
                },
                key_path: "m/44'/60'/0'/0/0".to_owned(),
            },
            public(6, None, Admission::Missing),
            public(7, None, Admission::Present),
            private_state(),
        ]);

        assert_eq!(
            manager.admitted_accounts(),
            BTreeSet::from([1, 2, 3, 5, 7].map(|tag| AccountId::new([tag; 32])))
        );
    }

    #[test]
    fn a_public_foreign_identity_names_its_keys_account_and_is_kept_without_signing() {
        let pk = lee::PublicKey::new_from_private_key(
            &lee::PrivateKey::try_new([9; 32]).expect("valid key"),
        );
        let foreign = AccountIdentity::PublicForeign(pk.clone());

        assert!(foreign.is_public());
        assert_eq!(foreign.account_id(), AccountId::from(&pk));
        assert_eq!(foreign.public_account_id(), Some(AccountId::from(&pk)));
        assert_eq!(
            foreign.without_signing(),
            AccountIdentity::PublicForeign(pk)
        );
    }

    #[test]
    fn an_unsigned_public_account_is_mentioned_alike_however_it_is_spelled() {
        let account_id = AccountId::new([7; 32]);
        for unsigned in [
            AccountIdentity::PublicNoSign(account_id).balance(),
            AccountIdentity::Public(account_id)
                .balance()
                .without_authorization(),
            AccountMention {
                identity: AccountIdentity::PublicNoSign(account_id),
                program_account_id: NATIVE_TOKEN_PROGRAM_ID,
                authorizes: true,
                openings: BTreeSet::new(),
            }
            .normalized(),
        ] {
            assert_eq!(unsigned.identity, AccountIdentity::Public(account_id));
            assert!(!unsigned.authorizes);
        }
    }

    #[test]
    fn an_account_holding_state_without_a_membership_proof_is_refused() {
        let nonce_only = Account {
            nonce: Nonce(1),
            ..Account::default()
        };
        for account in [Account::funded(5), nonce_only] {
            let State::Private(mut pre) = private_state() else {
                panic!("private_state builds a private account")
            };
            pre.pre_state.account = account;
            let account_id = pre.pre_state.account_id;

            assert!(matches!(
                manager(vec![State::Private(pre)]).private_witnesses(),
                Err(ExecutionFailureKind::MissingMembershipProof(refused)) if refused == account_id
            ));
        }
    }

    #[test]
    fn dummy_inputs_default_pads_private_count_to_max() {
        let max = AccountManager::PADDED_PRIVATE_ACTIONS;

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

        // A received message's spend takes a padding slot like an account's.
        let receiving = |states| AccountManager {
            message_path: Some((0, Vec::new())),
            ..manager(states)
        };
        assert_eq!(
            receiving(vec![private_state()])
                .dummy_inputs_default()
                .len(),
            max - 2
        );
        let full: Vec<State> = std::iter::repeat_with(private_state)
            .take(max - 1)
            .collect();
        assert_eq!(receiving(full).dummy_inputs_default().len(), 0);
        let over: Vec<State> = std::iter::repeat_with(private_state).take(max).collect();
        assert_eq!(receiving(over).dummy_inputs_default().len(), 0);
    }

    #[test]
    fn a_receipt_takes_only_the_message_path_at_its_position_that_reproduces_the_root() {
        let commitment = Commitment::new(&AccountId::new([0; 32]), &Account::default());
        let path = (3, vec![[1; 32], [2; 32]]);
        let root = compute_digest_for_path(&commitment, path.0, &path.1).unwrap();

        assert_eq!(
            message_path_at((3, commitment), Some(path.clone()), root).unwrap(),
            path
        );
        for (case, position, path, root) in [
            ("no path", 3, None, root),
            ("another position", 2, Some(path.clone()), root),
            ("another root", 3, Some(path), [4; 32]),
        ] {
            assert!(
                matches!(
                    message_path_at((position, commitment), path, root),
                    Err(ExecutionFailureKind::SequencerError(_))
                ),
                "{case}"
            );
        }
    }

    #[test]
    fn dummy_notes_are_padded_to_the_wallet_pad() {
        let expected = usize::try_from(CIPHERTEXT_PAD_SIZE).expect("pad size fits in usize");
        let lengths: Vec<usize> = manager(vec![])
            .dummy_inputs_default()
            .iter()
            .map(|dummy| dummy.output.note.ciphertext.as_bytes().len())
            .collect();

        assert_eq!(
            lengths,
            vec![expected; AccountManager::PADDED_PRIVATE_ACTIONS]
        );
    }

    #[test]
    fn oversized_private_accounts_are_reported() {
        let pad = usize::try_from(CIPHERTEXT_PAD_SIZE).expect("pad size fits in usize");
        let mut state = private_state();
        let State::Private(pre) = &mut state else {
            panic!("private_state builds a private account")
        };
        pre.pre_state
            .account
            .data
            .set_actor_state(AccountId::new([9_u8; 32]), vec![0_u8; pad].into());
        let account_id = pre.pre_state.account_id;

        assert_eq!(
            manager(vec![state]).accounts_outgrowing_pad(),
            vec![account_id]
        );
        assert!(
            manager(vec![private_state()])
                .accounts_outgrowing_pad()
                .is_empty()
        );
    }

    #[test]
    fn the_presenter_draws_a_fresh_alias_per_message_of_a_private_account() {
        let (private, public) = (AccountId::new([1; 32]), AccountId::new([2; 32]));
        let mut present = manager(vec![State::Private(Box::new(AccountPreparedData {
            kind: WitnessKind::Regular(RegularKey::Nullifying([4; 32])),
            vpk: ViewingPublicKey::from_seed(&[0; 32], &[0; 32]),
            pre_state: PreparedAccount {
                account_id: private,
                account: Account::default(),
            },
            proof: None,
            random_seed: [0; 32],
            openings: BTreeSet::from([[9; 32]]),
        }))])
        .presenter();

        let factors: HashSet<[u8; 32]> =
            std::iter::repeat_with(|| present(Actor::native_balance(private)))
                .take(3)
                .map(|presentation| {
                    let SenderPresentation::Blinded(factor) = presentation else {
                        panic!("a private account presents an alias");
                    };
                    factor
                })
                .collect();

        assert_eq!(factors.len(), 3);
        assert!(!factors.contains(&[9; 32]));
        assert_eq!(
            present(Actor::native_balance(public)),
            SenderPresentation::Canonical
        );
    }
}
