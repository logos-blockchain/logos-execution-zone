use lee_core::{
    AuthWitness, Commitment, CommitmentSetDigest, EncryptedAccountData, EncryptionScheme,
    EphemeralSecretKey, InputAccountIdentity, MembershipProof, Nullifier, NullifierPublicKey,
    NullifierSecretKey, NullifierWitness, PrivacyPreservingCircuitOutput, PrivateAccountKind,
    PrivateKind, PrivateWitness, SharedSecretKey, ThreadedDiff,
    account::{Account, AccountId, Nonce},
    compute_digest_for_path,
    encryption::ViewingPublicKey,
};

use crate::private_env::PrivateEnv;

pub fn compute_circuit_output(
    env: PrivateEnv,
    threaded: ThreadedDiff,
    account_identities: &[InputAccountIdentity],
) -> PrivacyPreservingCircuitOutput {
    let pda_seed_by_position = env.into_bound_pda_seeds();
    let mut output = PrivacyPreservingCircuitOutput {
        public_pre_states: Vec::new(),
        public_post_states: Vec::new(),
        encrypted_private_post_states: Vec::new(),
        new_commitments: Vec::new(),
        new_nullifiers: Vec::new(),
        block_validity_window: threaded.block_validity_window,
        timestamp_validity_window: threaded.timestamp_validity_window,
    };

    assert_eq!(
        account_identities.len(),
        threaded.accounts.len(),
        "Invalid account_identities length"
    );

    let mut output_index = 0;
    for (pos, (account_identity, (pre_state, post_state))) in
        account_identities.iter().zip(threaded.accounts).enumerate()
    {
        match account_identity {
            InputAccountIdentity::Public => {
                output.public_pre_states.push(pre_state);
                output.public_post_states.push(post_state);
            }
            InputAccountIdentity::Private(witness) => {
                let PrivateWitness {
                    vpk,
                    random_seed,
                    identifier,
                    kind,
                    auth,
                    nullifier,
                } = witness;
                let npk = nullifier.npk();

                let (account_id, account_kind) = match kind {
                    PrivateKind::Regular => {
                        let account_id = account_identity
                            .regular_account_id()
                            .expect("regular private account id");
                        assert_eq!(account_id, pre_state.account_id, "AccountId mismatch");
                        assert_eq!(
                            pre_state.is_authorized,
                            matches!(auth, AuthWitness::Held(_)),
                            "Regular private account authorization must match its held auth key"
                        );
                        (account_id, PrivateAccountKind::Regular(*identifier))
                    }
                    PrivateKind::Pda {
                        seed: external_seed,
                    } => {
                        match nullifier {
                            NullifierWitness::Init { .. } => assert!(
                                !pre_state.is_authorized,
                                "Private PDA init requires an unauthorized pre-state"
                            ),
                            NullifierWitness::Update { .. } => assert!(
                                pre_state.is_authorized ^ external_seed.is_some(),
                                "Private PDA update requires an authorized pre-state or an external seed"
                            ),
                        }
                        let (authority_program_id, seed) = pda_seed_by_position
                            .get(&pos)
                            .expect("private PDA position must be in pda_seed_by_position");
                        (
                            pre_state.account_id,
                            PrivateAccountKind::Pda {
                                program_id: *authority_program_id,
                                seed: *seed,
                                identifier: *identifier,
                            },
                        )
                    }
                };

                let (new_nullifier, new_nonce) = match nullifier {
                    NullifierWitness::Init {
                        commitment_root, ..
                    } => {
                        assert_eq!(
                            pre_state.account,
                            Account::default(),
                            "Found new private account with non default values"
                        );
                        (
                            (
                                Nullifier::for_account_initialization(&account_id),
                                *commitment_root,
                            ),
                            Nonce::private_account_nonce_init(&account_id),
                        )
                    }
                    NullifierWitness::Update {
                        nsk,
                        membership_proof,
                    } => (
                        compute_update_nullifier_and_set_digest(
                            membership_proof,
                            &pre_state.account,
                            &account_id,
                            nsk,
                        ),
                        pre_state.account.nonce.private_account_nonce_increment(nsk),
                    ),
                };

                emit_private_output(
                    &mut output,
                    &mut output_index,
                    post_state,
                    &account_id,
                    &account_kind,
                    &npk,
                    vpk,
                    random_seed,
                    new_nullifier,
                    new_nonce,
                );
            }
        }
    }

    output
}

#[expect(
    clippy::too_many_arguments,
    reason = "Inputs are distinct concerns from the variant arms; bundling would be artificial"
)]
fn emit_private_output(
    output: &mut PrivacyPreservingCircuitOutput,
    output_index: &mut u32,
    post_state: Account,
    account_id: &AccountId,
    kind: &PrivateAccountKind,
    npk: &NullifierPublicKey,
    vpk: &ViewingPublicKey,
    random_seed: &[u8; 32],
    new_nullifier: (Nullifier, CommitmentSetDigest),
    new_nonce: Nonce,
) {
    output.new_nullifiers.push(new_nullifier);

    let mut post_with_updated_nonce = post_state;
    post_with_updated_nonce.nonce = new_nonce;

    let commitment_post = Commitment::new(account_id, &post_with_updated_nonce);

    let esk = EphemeralSecretKey::new(account_id, random_seed, &new_nonce);
    let (shared_secret, epk) = SharedSecretKey::encapsulate_deterministic(vpk, &esk);

    // Currently the view tag is properlty generated for all accounts.
    // To increase privacy, this will be changed in the later version
    // to only be generated explicitly for initialized accounts and
    // fed by the prover directly for updated accounts.
    //
    // See issue 573:
    // https://github.com/logos-blockchain/logos-execution-zone/issues/573
    let view_tag = EncryptedAccountData::compute_view_tag(npk, vpk);

    let encrypted_account = EncryptionScheme::encrypt(
        &post_with_updated_nonce,
        kind,
        &shared_secret,
        &commitment_post,
        *output_index,
    );

    output.new_commitments.push(commitment_post);
    output
        .encrypted_private_post_states
        .push(EncryptedAccountData {
            ciphertext: encrypted_account,
            epk,
            view_tag,
        });
    *output_index = output_index
        .checked_add(1)
        .unwrap_or_else(|| panic!("Too many private accounts, output index overflow"));
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
