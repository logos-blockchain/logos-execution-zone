use std::{
    collections::{HashMap, HashSet, VecDeque},
    convert::Infallible,
};

use lee_core::{
    Attestation, Authorization, AuthorizationSecretKey, Backend, Commitment, CommitmentSetDigest,
    Identifier, Nullifier, NullifierPublicKey, NullifierWitness, PrivateKind, PrivateWitness,
    ValidationError,
    account::{Account, AccountId, AccountWithMetadata, Nonce},
    compute_digest_for_path, derive_nullifier_secret_key,
    encryption::ViewingPublicKey,
    program::{ChainedCall, PdaSeed, ProgramId, ProgramOutput},
};
use risc0_zkvm::{guest::env, serde::to_vec};

pub struct Row {
    pub kind: PrivateKind,
    pub vpk: ViewingPublicKey,
    pub random_seed: [u8; 32],
    pub identifier: Identifier,
    pub npk: NullifierPublicKey,
    pub pre: Account,
    pub nullifier: (Nullifier, CommitmentSetDigest),
    pub new_nonce: Nonce,
}

pub struct PrivateEnv {
    registry: HashMap<AccountId, Row>,
    remaining_outputs: VecDeque<ProgramOutput>,
}

impl PrivateEnv {
    #[must_use]
    pub fn new(private_rows: Vec<PrivateWitness>, program_outputs: Vec<ProgramOutput>) -> Self {
        let mut registry: HashMap<AccountId, Row> = HashMap::new();
        let mut families: HashSet<(ProgramId, PdaSeed)> = HashSet::new();

        for witness in private_rows {
            let account_id = witness.self_id();
            let PrivateWitness {
                vpk,
                random_seed,
                identifier,
                kind,
                nullifier,
            } = witness;

            match &kind {
                PrivateKind::Regular { ask: Some(ask) } => {
                    assert_authorization_chain(ask, &nullifier, &account_id);
                }
                PrivateKind::Pda {
                    seed: (seed, program_id),
                } => assert!(
                    families.insert((*program_id, *seed)),
                    "Two witness rows share the same (program, seed) in one transaction: {account_id}"
                ),
                PrivateKind::Regular { ask: None } => {}
            }

            let npk = nullifier.npk();
            let (pre, new_nullifier, new_nonce) = match nullifier {
                NullifierWitness::Init {
                    commitment_root, ..
                } => (
                    Account::default(),
                    (
                        Nullifier::for_account_initialization(&account_id),
                        commitment_root,
                    ),
                    Nonce::private_account_nonce_init(&account_id),
                ),
                NullifierWitness::Update {
                    nsk,
                    membership_proof,
                    pre_account,
                } => {
                    let new_nonce = pre_account.nonce.private_account_nonce_increment(&nsk);
                    let commitment_pre = Commitment::new(&account_id, &pre_account);
                    let set_digest = compute_digest_for_path(&commitment_pre, &membership_proof);
                    (
                        pre_account,
                        (
                            Nullifier::for_account_update(&commitment_pre, &nsk),
                            set_digest,
                        ),
                        new_nonce,
                    )
                }
            };

            assert!(
                registry
                    .insert(
                        account_id,
                        Row {
                            kind,
                            vpk,
                            random_seed,
                            identifier,
                            npk,
                            pre,
                            nullifier: new_nullifier,
                            new_nonce,
                        }
                    )
                    .is_none(),
                "Duplicate witness row for {account_id}"
            );
        }

        Self {
            registry,
            remaining_outputs: program_outputs.into(),
        }
    }

    #[must_use]
    pub fn into_registry(self) -> HashMap<AccountId, Row> {
        assert!(
            self.remaining_outputs.is_empty(),
            "Inner call without a chained call found"
        );
        self.registry
    }
}

impl Backend for PrivateEnv {
    type Error = ValidationError;

    fn output_for_call(
        &mut self,
        call: &ChainedCall,
        _caller: Option<ProgramId>,
    ) -> Result<ProgramOutput, ValidationError> {
        let output = self
            .remaining_outputs
            .pop_front()
            .expect("Insufficient program outputs for chained calls");
        assert_eq!(
            call.instruction_data, output.instruction_data,
            "Mismatched instruction data between chained call and program output"
        );
        let words = to_vec(&output).expect("program_output must be serializable");
        env::verify(call.program_id, &words)
            .unwrap_or_else(|_: Infallible| unreachable!("Infallible error is never constructed"));
        Ok(output)
    }

    fn attest(&self, pre: &AccountWithMetadata) -> Attestation {
        self.registry.get(&pre.account_id).map_or_else(
            // A public account is root-authorized iff it signed; the circuit's only signal is the
            // verifier-bound `is_authorized`. Trusted here and enforced by the verifier — this
            // just feeds the cross-call scoping set.
            || Attestation {
                account: pre.account.clone(),
                authorization: if pre.is_authorized {
                    Authorization::Holder
                } else {
                    Authorization::None
                },
                exhibits_preimage: false,
            },
            |row| Attestation {
                account: row.pre.clone(),
                authorization: if matches!(row.kind, PrivateKind::Regular { ask: Some(_) }) {
                    Authorization::Holder
                } else {
                    Authorization::None
                },
                exhibits_preimage: true,
            },
        )
    }

    fn seed_derives(&self, program_id: ProgramId, seed: PdaSeed, account_id: AccountId) -> bool {
        match self.registry.get(&account_id) {
            Some(Row {
                kind: PrivateKind::Pda { seed: bound },
                ..
            }) => *bound == (seed, program_id),
            Some(_) => false,
            None => account_id.matches_public_pda(&program_id, &seed),
        }
    }
}

fn assert_authorization_chain(
    ask: &AuthorizationSecretKey,
    nullifier: &NullifierWitness,
    account_id: &AccountId,
) {
    let nsk = derive_nullifier_secret_key(ask);
    match nullifier {
        NullifierWitness::Update {
            nsk: witness_nsk, ..
        } => assert_eq!(
            nsk, *witness_nsk,
            "Authorization key does not derive the nullifier secret key for {account_id}"
        ),
        NullifierWitness::Init { npk, .. } => assert_eq!(
            NullifierPublicKey::from(&nsk),
            *npk,
            "Authorization key does not derive the nullifier public key for {account_id}"
        ),
    }
}
