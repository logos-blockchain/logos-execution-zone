use lee_core::{
    Commitment, EncryptedAccountData, EncryptionScheme, EphemeralSecretKey,
    PrivacyPreservingCircuitOutput, PrivateAccountKind, PrivateKind, SharedSecretKey, ThreadedDiff,
    account::{Account, AccountId},
};

use crate::private_env::{PrivateEnv, Row};

pub fn compute_circuit_output(
    env: PrivateEnv,
    threaded: ThreadedDiff,
) -> PrivacyPreservingCircuitOutput {
    let mut registry = env.into_registry();
    let mut output = PrivacyPreservingCircuitOutput {
        public_pre_states: Vec::new(),
        public_post_states: Vec::new(),
        encrypted_private_post_states: Vec::new(),
        new_commitments: Vec::new(),
        new_nullifiers: Vec::new(),
        block_validity_window: threaded.block_validity_window,
        timestamp_validity_window: threaded.timestamp_validity_window,
    };

    let mut output_index = 0;
    for (pre_state, post_state) in threaded.accounts {
        if let Some(row) = registry.remove(&pre_state.account_id) {
            emit_private_output(
                &mut output,
                &mut output_index,
                post_state,
                &pre_state.account_id,
                row,
            );
        } else {
            output.public_pre_states.push(pre_state);
            output.public_post_states.push(post_state);
        }
    }

    assert!(registry.is_empty(), "Unused private witness row");

    output
}

fn emit_private_output(
    output: &mut PrivacyPreservingCircuitOutput,
    output_index: &mut u32,
    post_state: Account,
    account_id: &AccountId,
    row: Row,
) {
    let Row {
        kind,
        vpk,
        random_seed,
        identifier,
        npk,
        pre: _,
        nullifier,
        new_nonce,
    } = row;
    let account_kind = match kind {
        PrivateKind::Regular { .. } => PrivateAccountKind::Regular(identifier),
        PrivateKind::Pda {
            seed: (seed, program_id),
        } => PrivateAccountKind::Pda {
            program_id,
            seed,
            identifier,
        },
    };

    output.new_nullifiers.push(nullifier);

    let mut post_with_updated_nonce = post_state;
    post_with_updated_nonce.nonce = new_nonce;

    let commitment_post = Commitment::new(account_id, &post_with_updated_nonce);

    let esk = EphemeralSecretKey::new(account_id, &random_seed, &new_nonce);
    let (shared_secret, epk) = SharedSecretKey::encapsulate_deterministic(&vpk, &esk);

    // Currently the view tag is properlty generated for all accounts.
    // To increase privacy, this will be changed in the later version
    // to only be generated explicitly for initialized accounts and
    // fed by the prover directly for updated accounts.
    //
    // See issue 573:
    // https://github.com/logos-blockchain/logos-execution-zone/issues/573
    let view_tag = EncryptedAccountData::compute_view_tag(&npk, &vpk);

    let encrypted_account = EncryptionScheme::encrypt(
        &post_with_updated_nonce,
        &account_kind,
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
