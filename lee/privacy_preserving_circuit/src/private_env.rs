use std::{
    collections::{HashMap, VecDeque, hash_map::Entry},
    convert::Infallible,
};

use lee_core::{
    AuthWitness, Authorization, Backend, InputAccountIdentity, PrivateKind, PrivateWitness,
    Resolved, ValidationError,
    account::{AccountId, AccountWithMetadata},
    program::{ChainedCall, PdaSeed, ProgramId, ProgramOutput},
};
use risc0_zkvm::{guest::env, serde::to_vec};

pub struct PrivateEnv<'ids> {
    account_identities: &'ids [InputAccountIdentity],
    remaining_outputs: VecDeque<ProgramOutput>,
    private_pda_bound_positions: HashMap<usize, (ProgramId, PdaSeed)>,
    pda_family_binding: HashMap<(ProgramId, PdaSeed), AccountId>,
    next_position: usize,
    position_by_id: HashMap<AccountId, usize>,
}

impl<'ids> PrivateEnv<'ids> {
    #[must_use]
    pub fn new(
        account_identities: &'ids [InputAccountIdentity],
        program_outputs: Vec<ProgramOutput>,
    ) -> Self {
        Self {
            account_identities,
            remaining_outputs: program_outputs.into(),
            private_pda_bound_positions: HashMap::new(),
            pda_family_binding: HashMap::new(),
            next_position: 0,
            position_by_id: HashMap::new(),
        }
    }

    #[must_use]
    pub fn into_bound_pda_seeds(self) -> HashMap<usize, (ProgramId, PdaSeed)> {
        self.private_pda_bound_positions
    }
}

impl Backend for PrivateEnv<'_> {
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

    fn resolve_pre_state(
        &mut self,
        pre: &AccountWithMetadata,
    ) -> Result<Resolved, ValidationError> {
        let position = self.next_position;
        self.next_position = position.checked_add(1).expect("position counter overflow");
        self.position_by_id.insert(pre.account_id, position);

        let ids = self.account_identities;
        let external_seed = match ids.get(position) {
            Some(InputAccountIdentity::Private(PrivateWitness {
                kind:
                    PrivateKind::Pda {
                        seed: Some((seed, authority_program_id)),
                    },
                ..
            })) => Some((*seed, *authority_program_id)),
            _ => None,
        };
        if let Some((seed, authority_program_id)) = external_seed {
            assert_eq!(
                ids[position].pda_account_id(&authority_program_id, &seed),
                Some(pre.account_id),
                "External seed mismatch at position {position}"
            );
            assert!(
                !pre.is_authorized,
                "Private PDA with externally-provided seed must not be authorized at position {position}"
            );
            bind_private_pda_position(
                &mut self.private_pda_bound_positions,
                position,
                authority_program_id,
                seed,
            );
            assert_family_binding(
                &mut self.pda_family_binding,
                authority_program_id,
                seed,
                pre.account_id,
            );
        }
        let authorization = match ids.get(position) {
            // A public account is root-authorized iff it signed; the circuit's only signal is the
            // verifier-bound `is_authorized`. Trusted here (first-sight check is skipped) and
            // enforced by the verifier — this just feeds the cross-call scoping set.
            Some(InputAccountIdentity::Public) if pre.is_authorized => Authorization::Holder,
            Some(InputAccountIdentity::Private(PrivateWitness {
                kind: PrivateKind::Regular,
                auth: AuthWitness::Held(_),
                ..
            })) => Authorization::Holder,
            _ => Authorization::None,
        };
        Ok(Resolved {
            account: pre.account.clone(),
            authorization,
        })
    }

    fn try_bind_pda(
        &mut self,
        program_id: ProgramId,
        seed: PdaSeed,
        account_id: AccountId,
    ) -> Result<bool, ValidationError> {
        let position = self.position_by_id[&account_id];
        let ids = self.account_identities;
        if ids[position].pda_account_id(&program_id, &seed) != Some(account_id) {
            return Ok(false);
        }
        assert_family_binding(&mut self.pda_family_binding, program_id, seed, account_id);
        if ids[position].is_private_pda() {
            bind_private_pda_position(
                &mut self.private_pda_bound_positions,
                position,
                program_id,
                seed,
            );
        }
        Ok(true)
    }

    fn finalize(&self) -> Result<(), ValidationError> {
        assert!(
            self.remaining_outputs.is_empty(),
            "Inner call without a chained call found"
        );
        for (position, account_identity) in self.account_identities.iter().enumerate() {
            if account_identity.is_private_pda() {
                assert!(
                    self.private_pda_bound_positions.contains_key(&position),
                    "private PDA pre_state at position {position} has no proven (seed, npk) binding via Claim::Pda or caller pda_seeds"
                );
            }
        }
        Ok(())
    }

    fn authorization_bound_elsewhere(&self) -> bool {
        true
    }
}

fn assert_family_binding(
    bindings: &mut HashMap<(ProgramId, PdaSeed), AccountId>,
    program_id: ProgramId,
    seed: PdaSeed,
    account_id: AccountId,
) {
    match bindings.entry((program_id, seed)) {
        Entry::Vacant(e) => {
            e.insert(account_id);
        }
        Entry::Occupied(e) => {
            assert_eq!(
                *e.get(),
                account_id,
                "Two different accounts resolved under the same (program, seed) in one transaction: existing {}, new {account_id}",
                e.get()
            );
        }
    }
}

fn bind_private_pda_position(
    map: &mut HashMap<usize, (ProgramId, PdaSeed)>,
    position: usize,
    program_id: ProgramId,
    seed: PdaSeed,
) {
    match map.entry(position) {
        Entry::Occupied(e) => assert_eq!(
            *e.get(),
            (program_id, seed),
            "Duplicate binding at position {position}: conflicting (program_id, seed)"
        ),
        Entry::Vacant(e) => {
            e.insert((program_id, seed));
        }
    }
}
