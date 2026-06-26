use lee_core::{
    Commitment, CommitmentSetDigest, DUMMY_COMMITMENT_HASH, EncryptedAccountData, EncryptionScheme,
    EphemeralPublicKey, InputAccountIdentity, MembershipProof, Nullifier, NullifierPublicKey,
    NullifierSecretKey, PrivacyPreservingCircuitOutput, PrivateAccountKind, SharedSecretKey,
    account::{Account, AccountId, Nonce},
    compute_digest_for_path,
};

use crate::execution_state::ExecutionState;

struct PrivateOutputHandler<'ctx> {
    output: &'ctx mut PrivacyPreservingCircuitOutput,
    output_index: &'ctx mut u32,
    pre_state: &'ctx lee_core::account::AccountWithMetadata,
    post_state: Account,
    epk: &'ctx EphemeralPublicKey,
    view_tag: u8,
    ssk: &'ctx SharedSecretKey,
    identifier: u128,
}

impl PrivateOutputHandler<'_> {
    fn authorized_init(self, nsk: &NullifierSecretKey) {
        let npk = NullifierPublicKey::from(nsk);
        let account_id =
            derive_and_verify_account_id(&npk, self.identifier, self.pre_state.account_id);

        assert!(
            self.pre_state.is_authorized,
            "Pre-state not authorized for authenticated private account"
        );
        assert_eq!(
            self.pre_state.account,
            Account::default(),
            "Found new private account with non default values"
        );

        let (new_nullifier, new_nonce) = init_nullifier_and_nonce(&account_id);
        let kind = PrivateAccountKind::Regular(self.identifier);

        self.emit_private_output(&account_id, &kind, new_nullifier, new_nonce);
    }

    fn authorized_update(self, nsk: &NullifierSecretKey, membership_proof: &MembershipProof) {
        let npk = NullifierPublicKey::from(nsk);
        let account_id =
            derive_and_verify_account_id(&npk, self.identifier, self.pre_state.account_id);

        assert!(
            self.pre_state.is_authorized,
            "Pre-state not authorized for authenticated private account"
        );

        let new_nullifier = compute_update_nullifier_and_set_digest(
            membership_proof,
            &self.pre_state.account,
            &account_id,
            nsk,
        );
        let new_nonce = self
            .pre_state
            .account
            .nonce
            .private_account_nonce_increment(nsk);
        let kind = PrivateAccountKind::Regular(self.identifier);

        self.emit_private_output(&account_id, &kind, new_nullifier, new_nonce);
    }

    fn unauthorized(self, npk: &NullifierPublicKey) {
        let account_id =
            derive_and_verify_account_id(npk, self.identifier, self.pre_state.account_id);

        assert_eq!(
            self.pre_state.account,
            Account::default(),
            "Found new private account with non default values",
        );
        assert!(
            !self.pre_state.is_authorized,
            "Found new private account marked as authorized."
        );

        let (new_nullifier, new_nonce) = init_nullifier_and_nonce(&account_id);
        let kind = PrivateAccountKind::Regular(self.identifier);

        self.emit_private_output(&account_id, &kind, new_nullifier, new_nonce);
    }

    fn pda_init(
        self,
        pos: usize,
        pda_seed_by_position: &std::collections::HashMap<
            usize,
            (lee_core::program::ProgramId, lee_core::program::PdaSeed),
        >,
    ) {
        // The npk-to-account_id binding is established upstream in
        // `validate_and_sync_states` via `Claim::Pda(seed)` or a caller `pda_seeds`
        // match. Here we only enforce the init pre-conditions.
        assert!(
            !self.pre_state.is_authorized,
            "PrivatePdaInit requires unauthorized pre_state"
        );
        assert_eq!(
            self.pre_state.account,
            Account::default(),
            "New private PDA must be default"
        );

        let (new_nullifier, new_nonce) = init_nullifier_and_nonce(&self.pre_state.account_id);

        let account_id = self.pre_state.account_id;
        let (authority_program_id, seed) = pda_seed_by_position
            .get(&pos)
            .expect("PrivatePdaInit position must be in pda_seed_by_position");
        let kind = PrivateAccountKind::Pda {
            program_id: *authority_program_id,
            seed: *seed,
            identifier: self.identifier,
        };

        self.emit_private_output(&account_id, &kind, new_nullifier, new_nonce);
    }

    fn pda_update(
        self,
        nsk: &NullifierSecretKey,
        membership_proof: &MembershipProof,
        external_seed: Option<&(lee_core::program::PdaSeed, lee_core::program::ProgramId)>,
        pos: usize,
        pda_seed_by_position: &std::collections::HashMap<
            usize,
            (lee_core::program::ProgramId, lee_core::program::PdaSeed),
        >,
    ) {
        // With an external seed the binding comes from the circuit input and the
        // pre_state is intentionally unauthorized; without one the binding comes from
        // a Claim or caller pda_seeds, so the pre_state must already be authorized.
        assert!(
            self.pre_state.is_authorized ^ external_seed.is_some(),
            "PrivatePdaUpdate requires authorized pre_state or external seed"
        );

        let new_nullifier = compute_update_nullifier_and_set_digest(
            membership_proof,
            &self.pre_state.account,
            &self.pre_state.account_id,
            nsk,
        );
        let new_nonce = self
            .pre_state
            .account
            .nonce
            .private_account_nonce_increment(nsk);

        let account_id = self.pre_state.account_id;
        let (authority_program_id, seed) = pda_seed_by_position
            .get(&pos)
            .expect("PrivatePdaUpdate position must be in pda_seed_by_position");
        let kind = PrivateAccountKind::Pda {
            program_id: *authority_program_id,
            seed: *seed,
            identifier: self.identifier,
        };

        self.emit_private_output(&account_id, &kind, new_nullifier, new_nonce);
    }

    fn emit_private_output(
        self,
        account_id: &AccountId,
        kind: &PrivateAccountKind,
        new_nullifier: (Nullifier, CommitmentSetDigest),
        new_nonce: Nonce,
    ) {
        self.output.new_nullifiers.push(new_nullifier);

        let mut post_with_updated_nonce = self.post_state;
        post_with_updated_nonce.nonce = new_nonce;

        let commitment_post = Commitment::new(account_id, &post_with_updated_nonce);
        let encrypted_account = EncryptionScheme::encrypt(
            &post_with_updated_nonce,
            kind,
            self.ssk,
            &commitment_post,
            *self.output_index,
        );

        self.output.new_commitments.push(commitment_post);
        self.output
            .encrypted_private_post_states
            .push(EncryptedAccountData {
                ciphertext: encrypted_account,
                epk: self.epk.clone(),
                view_tag: self.view_tag,
            });
        *self.output_index = self
            .output_index
            .checked_add(1)
            .unwrap_or_else(|| panic!("Too many private accounts, output index overflow"));
    }
}

fn init_nullifier_and_nonce(account_id: &AccountId) -> ((Nullifier, CommitmentSetDigest), Nonce) {
    let nullifier = (
        Nullifier::for_account_initialization(account_id),
        DUMMY_COMMITMENT_HASH,
    );
    let nonce = Nonce::private_account_nonce_init(account_id);
    (nullifier, nonce)
}

fn derive_and_verify_account_id(
    npk: &NullifierPublicKey,
    identifier: u128,
    pre_state_account_id: AccountId,
) -> AccountId {
    let account_id = AccountId::for_regular_private_account(npk, identifier);
    assert_eq!(account_id, pre_state_account_id, "AccountId mismatch");
    account_id
}

fn compute_update_nullifier_and_set_digest(
    membership_proof: &MembershipProof,
    pre_account: &Account,
    account_id: &AccountId,
    nsk: &NullifierSecretKey,
) -> (Nullifier, CommitmentSetDigest) {
    let commitment_pre = Commitment::new(account_id, pre_account);
    let set_digest = compute_digest_for_path(&commitment_pre, membership_proof);
    let nullifier = Nullifier::for_account_update(&commitment_pre, nsk);
    (nullifier, set_digest)
}

pub fn compute_circuit_output(
    execution_state: ExecutionState,
    account_identities: &[InputAccountIdentity],
) -> PrivacyPreservingCircuitOutput {
    let (block_validity_window, timestamp_validity_window, pda_seed_by_position, states_iter) =
        execution_state.into_parts();
    let mut output = PrivacyPreservingCircuitOutput {
        public_pre_states: Vec::new(),
        public_post_states: Vec::new(),
        encrypted_private_post_states: Vec::new(),
        new_commitments: Vec::new(),
        new_nullifiers: Vec::new(),
        block_validity_window,
        timestamp_validity_window,
    };

    assert_eq!(
        account_identities.len(),
        states_iter.len(),
        "Invalid account_identities length"
    );

    let mut output_index = 0;
    for (pos, (account_identity, (pre_state, post_state))) in
        account_identities.iter().zip(states_iter).enumerate()
    {
        match account_identity {
            InputAccountIdentity::Public => {
                output.public_pre_states.push(pre_state);
                output.public_post_states.push(post_state);
            }
            InputAccountIdentity::PrivateAuthorizedInit {
                epk,
                view_tag,
                ssk,
                nsk,
                identifier,
            } => PrivateOutputHandler {
                output: &mut output,
                output_index: &mut output_index,
                pre_state: &pre_state,
                post_state,
                epk,
                view_tag: *view_tag,
                ssk,
                identifier: *identifier,
            }
            .authorized_init(nsk),
            InputAccountIdentity::PrivateAuthorizedUpdate {
                epk,
                view_tag,
                ssk,
                nsk,
                membership_proof,
                identifier,
            } => PrivateOutputHandler {
                output: &mut output,
                output_index: &mut output_index,
                pre_state: &pre_state,
                post_state,
                epk,
                view_tag: *view_tag,
                ssk,
                identifier: *identifier,
            }
            .authorized_update(nsk, membership_proof),
            InputAccountIdentity::PrivateUnauthorized {
                epk,
                view_tag,
                npk,
                ssk,
                identifier,
            } => PrivateOutputHandler {
                output: &mut output,
                output_index: &mut output_index,
                pre_state: &pre_state,
                post_state,
                epk,
                view_tag: *view_tag,
                ssk,
                identifier: *identifier,
            }
            .unauthorized(npk),
            InputAccountIdentity::PrivatePdaInit {
                epk,
                view_tag,
                npk: _,
                ssk,
                identifier,
                seed: _,
            } => PrivateOutputHandler {
                output: &mut output,
                output_index: &mut output_index,
                pre_state: &pre_state,
                post_state,
                epk,
                view_tag: *view_tag,
                ssk,
                identifier: *identifier,
            }
            .pda_init(pos, &pda_seed_by_position),
            InputAccountIdentity::PrivatePdaUpdate {
                epk,
                view_tag,
                ssk,
                nsk,
                membership_proof,
                identifier,
                seed: external_seed,
            } => PrivateOutputHandler {
                output: &mut output,
                output_index: &mut output_index,
                pre_state: &pre_state,
                post_state,
                epk,
                view_tag: *view_tag,
                ssk,
                identifier: *identifier,
            }
            .pda_update(
                nsk,
                membership_proof,
                external_seed.as_ref(),
                pos,
                &pda_seed_by_position,
            ),
        }
    }

    output
}
