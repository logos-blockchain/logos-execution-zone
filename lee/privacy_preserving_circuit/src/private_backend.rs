//! The privacy preserving circuit's half of the shared traversal: it verifies a proof of
//! each call, and its only independent view of an account is that account's witness.

use std::{
    collections::{HashMap, HashSet, VecDeque, hash_map::Entry},
    convert::Infallible,
};

use lee_core::{
    BlockId, NullifierPublicKey, NullifierSecretKey, NullifierWitness, PrivateWitness,
    ProgramImageClaim, Timestamp, WitnessKind,
    account::{AccountData, AccountId, ProgramShardSelector},
    native_token::{self, NATIVE_TOKEN_PROGRAM_ID},
    program::{
        AccountInput, BlockValidityWindow, ChainedCall, PdaSeed, ProgramId, ProgramOutput,
        TimestampValidityWindow, pre_states_match_shard_selectors,
    },
    validation::{Backend, CallContext, ValidationError},
};
use risc0_zkvm::guest::env;

/// SAFETY-CRITICAL, deliberately uninhabited: no `Err` can be constructed, so every `?` is a
/// dead branch and a rejection can only be the panic below. Never make this inhabited.
pub enum Fatal {}

#[expect(
    clippy::fallible_impl_from,
    reason = "panicking is the point: `Fatal` is uninhabited, so this conversion is the only way a rejection can be expressed in-guest"
)]
impl From<ValidationError> for Fatal {
    fn from(error: ValidationError) -> Self {
        panic!("{error}")
    }
}

pub struct PrivateBackend<'input> {
    witnesses: &'input [PrivateWitness],
    /// An account without a witness is public in-circuit: no note, so the journal exposes it.
    witness_by_account: HashMap<AccountId, usize>,
    remaining_outputs: VecDeque<ProgramOutput>,
    initial_shard_selectors: &'input [ProgramShardSelector],
    /// Untrusted, prover-supplied; the sequencer checks these against chain state, not us.
    image_id_by_account_id: HashMap<AccountId, ProgramId>,
    /// One `(program, seed)` per account per transaction, else one seed authorizes a family.
    pda_family_binding: HashMap<(AccountId, PdaSeed), AccountId>,
    /// Masked journal authorization, so a later sighting is judged as the verifier will.
    public_authorization: HashMap<AccountId, bool>,
    block_bounds: (Option<BlockId>, Option<BlockId>),
    timestamp_bounds: (Option<Timestamp>, Option<Timestamp>),
}

impl<'input> PrivateBackend<'input> {
    /// Index the witnesses and check each binds the account it claims, before any call runs.
    pub fn new(
        witnesses: &'input [PrivateWitness],
        program_outputs: Vec<ProgramOutput>,
        program_image_claims: &[ProgramImageClaim],
        initial_shard_selectors: &'input [ProgramShardSelector],
    ) -> Self {
        assert!(
            !program_image_claims
                .iter()
                .any(|claim| claim.account_id == NATIVE_TOKEN_PROGRAM_ID),
            "The native token program has no deployable bytecode to claim"
        );
        assert_eq!(
            initial_shard_selectors.iter().collect::<HashSet<_>>().len(),
            initial_shard_selectors.len(),
            "An account may select several shards, but never the same one twice"
        );
        let mut backend = Self {
            witnesses,
            witness_by_account: HashMap::new(),
            remaining_outputs: program_outputs.into(),
            initial_shard_selectors,
            image_id_by_account_id: program_image_claims
                .iter()
                .map(|claim| (claim.account_id, claim.image_id))
                .collect(),
            pda_family_binding: HashMap::new(),
            public_authorization: HashMap::new(),
            block_bounds: (None, None),
            timestamp_bounds: (None, None),
        };

        for (index, witness) in witnesses.iter().enumerate() {
            let account_id = witness.account_id();
            assert!(
                backend
                    .witness_by_account
                    .insert(account_id, index)
                    .is_none(),
                "Two witnesses derive the same private account {account_id}"
            );
            match &witness.kind {
                WitnessKind::Pda {
                    binding: (program, seed),
                } => backend.assert_family_binding(*program, *seed, account_id),
                WitnessKind::Regular { ask } => {
                    if let Some(ask) = ask {
                        let derived = NullifierSecretKey::from(ask);
                        match &witness.nullifier {
                            // The authorization key must actually bind the account id.
                            NullifierWitness::Update { nsk, .. } => assert_eq!(
                                derived, *nsk,
                                "Authorization secret key does not derive the nullifier secret key of {account_id}"
                            ),
                            NullifierWitness::Init { npk, .. } => assert_eq!(
                                NullifierPublicKey::from(&derived),
                                *npk,
                                "Authorization secret key does not derive the nullifier public key of {account_id}"
                            ),
                        }
                    }
                }
            }
        }

        backend
    }

    #[must_use]
    pub fn into_windows(self) -> (BlockValidityWindow, TimestampValidityWindow) {
        let block: BlockValidityWindow = self.block_bounds.try_into().expect(
            "There should be non empty intersection in the program output block validity windows",
        );
        let timestamp: TimestampValidityWindow = self.timestamp_bounds.try_into().expect(
            "There should be non empty intersection in the program output timestamp validity windows",
        );
        (block, timestamp)
    }

    #[must_use]
    pub fn witness_for(&self, account_id: AccountId) -> Option<&'input PrivateWitness> {
        self.witness_by_account
            .get(&account_id)
            .map(|&index| &self.witnesses[index])
    }

    fn native_output(
        &self,
        call: &ChainedCall,
        ctx: &CallContext<'_>,
        reported: ProgramOutput,
    ) -> ProgramOutput {
        // If the call is top-level, it was handed the transaction's selectors, since the
        // protocol itself runs it.
        let scheduled = if ctx.caller_account_id.is_some() {
            call.shard_selectors.as_slice()
        } else {
            self.initial_shard_selectors
        };
        assert!(
            pre_states_match_shard_selectors(scheduled, &reported.state_diffs),
            "Call ran on shard selectors it was not handed"
        );
        let pre_states: Vec<AccountInput> = reported
            .state_diffs
            .into_iter()
            .map(|diff| diff.pre_state)
            .collect();
        native_token::execute(ctx.caller_account_id, &pre_states, &call.instruction_data)
            .unwrap_or_else(|err| panic!("Invalid native transfer: {err}"))
    }

    fn assert_family_binding(
        &mut self,
        program_account_id: AccountId,
        seed: PdaSeed,
        account_id: AccountId,
    ) {
        match self.pda_family_binding.entry((program_account_id, seed)) {
            Entry::Vacant(entry) => {
                entry.insert(account_id);
            }
            Entry::Occupied(entry) => assert_eq!(
                *entry.get(),
                account_id,
                "Two different accounts resolved under the same (program, seed) in one transaction: existing {}, new {account_id}",
                entry.get()
            ),
        }
    }

    fn seed_granted(
        ctx: &CallContext<'_>,
        witness: Option<&PrivateWitness>,
        account_id: AccountId,
    ) -> Option<(AccountId, PdaSeed)> {
        witness.map_or_else(
            || {
                let caller_account_id = ctx.caller_account_id?;
                ctx.pda_seeds.iter().find_map(|seed| {
                    (AccountId::for_public_pda(&caller_account_id, seed) == account_id)
                        .then_some((caller_account_id, *seed))
                })
            },
            |witness| {
                witness.pda_binding().filter(|&(program, seed)| {
                    Some(program) == ctx.caller_account_id && ctx.pda_seeds.contains(&seed)
                })
            },
        )
    }

    /// Authorized by its own credential or a grant inherited from an ancestor call.
    fn is_already_authorized(
        &self,
        ctx: &CallContext<'_>,
        account_id: AccountId,
        witness: Option<&PrivateWitness>,
    ) -> bool {
        ctx.authorized_accounts.contains(&account_id)
            || witness.map_or_else(
                || {
                    self.public_authorization
                        .get(&account_id)
                        .copied()
                        .unwrap_or(false)
                },
                |witness| matches!(witness.kind, WitnessKind::Regular { ask: Some(_) }),
            )
    }
}

impl Backend for PrivateBackend<'_> {
    type Error = Fatal;

    fn output_for_call(
        &mut self,
        call: &ChainedCall,
        ctx: &CallContext<'_>,
    ) -> Result<ProgramOutput, Fatal> {
        let Some(program_output) = self.remaining_outputs.pop_front() else {
            panic!("Insufficient program outputs for chained calls");
        };
        if call.program_account_id == NATIVE_TOKEN_PROGRAM_ID {
            return Ok(self.native_output(call, ctx, program_output));
        }
        // `env::verify` needs the invoked program's real image id, not its dispatch address.
        let image_id = self
            .image_id_by_account_id
            .get(&call.program_account_id)
            .copied()
            .expect("no image_id claim supplied for invoked program account");
        let frame = lee_core::to_borsh_frame(&program_output);
        env::verify(image_id, &frame)
            .unwrap_or_else(|_: Infallible| unreachable!("Infallible error is never constructed"));
        Ok(program_output)
    }

    fn has_independent_view(&mut self, account_id: AccountId) -> bool {
        // A witness binds its note's content; a public account has none, so its claim is
        // adopted and the verifier checks it against real state.
        self.witness_for(account_id).is_some()
    }

    fn value_at_first_sight(
        &mut self,
        account_id: AccountId,
        _ctx: &CallContext<'_>,
    ) -> Result<Option<AccountData>, Fatal> {
        Ok(self
            .witness_for(account_id)
            .map(|witness| witness.account.data.clone()))
    }

    fn judge_authorization(
        &mut self,
        pre: &AccountInput,
        first_sight: bool,
        ctx: &CallContext<'_>,
    ) -> Result<bool, Fatal> {
        let account_id = pre.account_id;
        let witness = self.witness_for(account_id);
        let granted = Self::seed_granted(ctx, witness, account_id);

        if let Some((program, seed)) = granted {
            self.assert_family_binding(program, seed, account_id);
        }

        if let Some(witness) = witness {
            match &witness.kind {
                WitnessKind::Regular { ask } if first_sight => assert_eq!(
                    pre.is_authorized,
                    ask.is_some(),
                    "Regular private account {account_id} must be authorized exactly by its supplied credential"
                ),
                WitnessKind::Regular { .. } | WitnessKind::Pda { .. } => assert_eq!(
                    pre.is_authorized,
                    granted.is_some() || self.is_already_authorized(ctx, account_id, Some(witness)),
                    "Inconsistent authorization for account {account_id}"
                ),
            }
            return Ok(pre.is_authorized);
        }

        // At first sight a public account's claim stands, the verifier re-derives it from the
        // signer set; afterwards it must stay consistent with this traversal.
        if !first_sight {
            assert_eq!(
                pre.is_authorized,
                granted.is_some() || self.is_already_authorized(ctx, account_id, None),
                "Inconsistent authorization for account {account_id}"
            );
            return Ok(self
                .public_authorization
                .get(&account_id)
                .copied()
                .unwrap_or(false));
        }

        if granted.is_some() {
            assert!(
                pre.is_authorized,
                "Caller-seeded public PDA must be declared authorized at first sight: {account_id}"
            );
        }
        // Public PDAs cannot sign, so export false and remember it for later sightings.
        let exported = granted.is_none() && pre.is_authorized;
        self.public_authorization.insert(account_id, exported);
        Ok(exported)
    }

    fn observe_windows(
        &mut self,
        block: BlockValidityWindow,
        timestamp: TimestampValidityWindow,
    ) -> Result<(), Fatal> {
        self.block_bounds = intersect(self.block_bounds, block.start(), block.end());
        self.timestamp_bounds =
            intersect(self.timestamp_bounds, timestamp.start(), timestamp.end());
        Ok(())
    }

    fn finish(&mut self) -> Result<(), Fatal> {
        assert!(
            self.remaining_outputs.is_empty(),
            "Inner call without a chained call found"
        );
        Ok(())
    }
}

fn intersect<T: Copy + Ord>(
    bounds: (Option<T>, Option<T>),
    start: Option<T>,
    end: Option<T>,
) -> (Option<T>, Option<T>) {
    let lower = match (bounds.0, start) {
        (Some(current), Some(new)) => Some(current.max(new)),
        (only, None) | (None, only) => only,
    };
    let upper = match (bounds.1, end) {
        (Some(current), Some(new)) => Some(current.min(new)),
        (only, None) | (None, only) => only,
    };
    (lower, upper)
}

#[cfg(test)]
mod tests {
    use lee_core::{
        account::Account,
        encryption::ViewingPublicKey,
        program::{CallKind, ProgramEvent, ShardStateDiff},
        validation::{ThreadedDiff, validate_state_diff},
    };

    use super::*;

    const PROGRAM: AccountId = AccountId::new([0xA0; 32]);
    const OTHER_PROGRAM: AccountId = AccountId::new([0xA1; 32]);
    const SEED: PdaSeed = PdaSeed::new([2; 32]);
    const OTHER_SEED: PdaSeed = PdaSeed::new([3; 32]);

    fn witness_with(kind: WitnessKind) -> PrivateWitness {
        PrivateWitness {
            account: Account::default(),
            vpk: ViewingPublicKey::from_seed(&[4; 32], &[5; 32]),
            random_seed: [6; 32],
            identifier: 0,
            kind,
            nullifier: NullifierWitness::Init {
                npk: NullifierPublicKey([7; 32]),
                commitment_root: [8; 32],
            },
        }
    }

    fn granted(
        caller: Option<AccountId>,
        seeds: &[PdaSeed],
        witness: Option<&PrivateWitness>,
        account_id: AccountId,
    ) -> Option<(AccountId, PdaSeed)> {
        let ctx = CallContext {
            caller_account_id: caller,
            program_account_id: AccountId::new([0xD0; 32]),
            pda_seeds: seeds,
            authorized_accounts: &HashSet::new(),
            touched: &HashMap::new(),
        };
        PrivateBackend::seed_granted(&ctx, witness, account_id)
    }

    fn native_row(seed: u8, is_authorized: bool, balance: u128) -> AccountInput {
        AccountInput::balance(AccountId::new([seed; 32]), is_authorized, balance)
    }

    fn native_selectors() -> Vec<ProgramShardSelector> {
        vec![
            ProgramShardSelector::balance(AccountId::new([1; 32])),
            ProgramShardSelector::balance(AccountId::new([2; 32])),
        ]
    }

    fn tampered_native_report(amount: u128) -> ProgramOutput {
        let instruction = borsh::to_vec(&native_token::Instruction::Transfer { amount })
            .expect("the instruction serializes");
        let forged_credit = native_token::encode_balance(9_999);
        ProgramOutput {
            self_account_id: AccountId::new([0xAA; 32]),
            caller_account_id: Some(AccountId::new([0xBB; 32])),
            call_kind: CallKind::Unknown(7),
            instruction_data: instruction,
            state_diffs: vec![
                ShardStateDiff::new(native_row(1, true, 100), forged_credit.clone()),
                ShardStateDiff::new(native_row(2, false, 0), forged_credit),
            ],
            chained_calls: vec![ChainedCall {
                program_account_id: AccountId::new([0xCC; 32]),
                shard_selectors: Vec::new(),
                instruction_data: Vec::new(),
                pda_seeds: Vec::new(),
            }],
            block_validity_window: (Some(1), Some(2)).try_into().expect("a valid window"),
            timestamp_validity_window: (Some(3), Some(4)).try_into().expect("a valid window"),
            events: vec![ProgramEvent {
                selector: [1; 8],
                data: vec![2; 4],
            }],
        }
    }

    fn derive(
        witnesses: &[PrivateWitness],
        program_account_id: AccountId,
        report: ProgramOutput,
        selectors: &[ProgramShardSelector],
        claims: &[ProgramImageClaim],
    ) -> (ThreadedDiff, (BlockValidityWindow, TimestampValidityWindow)) {
        let initial_call = ChainedCall {
            program_account_id,
            instruction_data: report.instruction_data.clone(),
            shard_selectors: Vec::new(),
            pda_seeds: Vec::new(),
        };
        let mut backend = PrivateBackend::new(witnesses, vec![report], claims, selectors);
        let threaded = match validate_state_diff(&mut backend, initial_call, selectors) {
            Ok(threaded) => threaded,
            Err(fatal) => match fatal {},
        };
        (threaded, backend.into_windows())
    }

    fn derive_native_root(
        report: ProgramOutput,
        selectors: &[ProgramShardSelector],
    ) -> (ThreadedDiff, (BlockValidityWindow, TimestampValidityWindow)) {
        derive(&[], NATIVE_TOKEN_PROGRAM_ID, report, selectors, &[])
    }

    #[test]
    fn a_native_call_takes_only_its_rows_from_the_report() {
        let (threaded, (block_window, timestamp_window)) =
            derive_native_root(tampered_native_report(30), &native_selectors());

        let balances: Vec<_> = threaded
            .first_sight
            .iter()
            .map(|(account_id, _)| threaded.touched[account_id].balance())
            .collect();
        assert_eq!(balances, vec![Ok(70), Ok(30)]);
        assert_eq!(block_window.start(), None);
        assert_eq!(block_window.end(), None);
        assert_eq!(timestamp_window.start(), None);
        assert_eq!(timestamp_window.end(), None);
    }

    #[test]
    #[should_panic(expected = "Call ran on shard selectors it was not handed")]
    fn a_native_root_must_report_the_scheduled_selectors_in_order() {
        let mut selectors = native_selectors();
        selectors.reverse();

        drop(derive_native_root(tampered_native_report(30), &selectors));
    }

    #[test]
    #[should_panic(expected = "must be authorized exactly by its supplied credential")]
    fn a_native_call_refuses_authorization_the_witness_does_not_carry() {
        let mut witness = witness_with(WitnessKind::Regular { ask: None });
        witness.account = Account::funded(100);
        let sender = witness.account_id();
        let recipient = AccountId::new([2; 32]);
        let mut report = tampered_native_report(30);
        report.state_diffs[0].pre_state = AccountInput::balance(sender, true, 100);
        report.state_diffs[1].pre_state = AccountInput::balance(recipient, false, 0);

        drop(derive(
            &[witness],
            NATIVE_TOKEN_PROGRAM_ID,
            report,
            &[
                ProgramShardSelector::balance(sender),
                ProgramShardSelector::balance(recipient),
            ],
            &[],
        ));
    }

    #[test]
    #[should_panic(expected = "never the same one twice")]
    fn a_root_may_not_be_handed_the_same_shard_twice() {
        let selector = ProgramShardSelector::balance(AccountId::new([1; 32]));

        drop(derive(
            &[],
            AccountId::new([0xD0; 32]),
            tampered_native_report(30),
            &[selector, selector],
            &[],
        ));
    }

    #[test]
    #[should_panic(expected = "The native token program has no deployable bytecode to claim")]
    fn a_guest_image_claim_for_the_reserved_id_is_refused() {
        drop(derive(
            &[],
            NATIVE_TOKEN_PROGRAM_ID,
            tampered_native_report(30),
            &native_selectors(),
            &[ProgramImageClaim {
                account_id: NATIVE_TOKEN_PROGRAM_ID,
                image_id: [7; 8],
            }],
        ));
    }

    #[test]
    fn a_delegated_seed_grants_a_private_pda_only_to_its_bound_program() {
        let pda = witness_with(WitnessKind::Pda {
            binding: (PROGRAM, SEED),
        });
        let regular = witness_with(WitnessKind::Regular { ask: None });
        let (pda_id, regular_id) = (pda.account_id(), regular.account_id());

        assert_eq!(
            granted(Some(PROGRAM), &[OTHER_SEED, SEED], Some(&pda), pda_id),
            Some((PROGRAM, SEED))
        );
        assert_eq!(
            granted(Some(OTHER_PROGRAM), &[SEED], Some(&pda), pda_id),
            None
        );
        assert_eq!(
            granted(Some(PROGRAM), &[OTHER_SEED], Some(&pda), pda_id),
            None
        );
        assert_eq!(
            granted(Some(PROGRAM), &[SEED], Some(&regular), regular_id),
            None
        );
    }

    #[test]
    fn a_delegated_seed_grants_a_public_pda_only_the_account_it_derives() {
        let pda = AccountId::for_public_pda(&PROGRAM, &SEED);

        assert_eq!(
            granted(Some(PROGRAM), &[OTHER_SEED, SEED], None, pda),
            Some((PROGRAM, SEED))
        );
        assert_eq!(granted(Some(OTHER_PROGRAM), &[SEED], None, pda), None);
        assert_eq!(granted(Some(PROGRAM), &[OTHER_SEED], None, pda), None);
        assert_eq!(granted(None, &[SEED], None, pda), None);
    }
}
