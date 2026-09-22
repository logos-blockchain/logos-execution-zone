//! The privacy preserving circuit's half of the shared traversal.
//!
//! What makes this environment private is concentrated here: it verifies a proof of each call
//! rather than executing it, its only independent view of an account is the witness supplied for
//! it, and a PDA seed proves authorization through that witness rather than through a public
//! derivation alone. The traversal in [`lee_core::validation`] owns everything else.

use std::{
    collections::{HashMap, VecDeque, hash_map::Entry},
    convert::Infallible,
};

use lee_core::{
    BlockId, NullifierPublicKey, NullifierSecretKey, NullifierWitness, PrivateWitness,
    ProgramImageClaim, Timestamp, WitnessKind,
    account::{AccountData, AccountId},
    program::{
        AccountInput, BlockValidityWindow, ChainedCall, PdaSeed, ProgramId, ProgramOutput,
        TimestampValidityWindow,
    },
    validation::{Backend, CallContext, ValidationError},
};
use risc0_zkvm::guest::env;

/// The circuit's error type, deliberately uninhabited.
///
/// SAFETY-CRITICAL: an invalid execution must never become a value a caller can inspect, ignore
/// or recover from. Because `Fatal` has no variants, no `Err` can be constructed, every `?` in
/// the traversal is a statically dead branch, and the only way a rejection can be expressed is
/// the panic in the conversion below, which aborts the guest at the exact failure site and
/// produces no receipt. Replacing this with an inhabited error type would turn every one of
/// those dead branches into a live one, and a single `.ok()` or `unwrap_or_default()` downstream
/// would then prove an invalid execution. Do not.
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
    /// Which witness, if any, derives each account. An account without one is public inside the
    /// circuit: it has no note, so the journal must expose it for the verifier to check.
    witness_by_account: HashMap<AccountId, usize>,
    remaining_outputs: VecDeque<ProgramOutput>,
    /// Untrusted, prover-supplied. `env::verify` needs a real image id, not a dispatch address.
    /// The circuit does not check these against chain state; the sequencer does that
    /// independently before accepting the proof. See [`ProgramImageClaim`].
    image_id_by_account_id: HashMap<AccountId, ProgramId>,
    /// Each `(program, seed)` resolves to at most one account per transaction. Without this a
    /// single delegated seed could authorize several members of a PDA family at once.
    pda_family_binding: HashMap<(AccountId, PdaSeed), AccountId>,
    /// Public accounts whose journal authorization was masked to false, so a later sighting
    /// judges them the way the verifier will.
    public_authorization: HashMap<AccountId, bool>,
    block_bounds: (Option<BlockId>, Option<BlockId>),
    timestamp_bounds: (Option<Timestamp>, Option<Timestamp>),
}

impl<'input> PrivateBackend<'input> {
    /// Index the witnesses and check each one binds the account it claims, before any call runs.
    pub fn new(
        witnesses: &'input [PrivateWitness],
        program_outputs: Vec<ProgramOutput>,
        program_image_claims: &[ProgramImageClaim],
    ) -> Self {
        let mut backend = Self {
            witnesses,
            witness_by_account: HashMap::new(),
            remaining_outputs: program_outputs.into(),
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

    /// The accumulated validity windows, once every call has declared its own.
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

    /// The account's PDA binding, if the caller delegated the seed that derives it.
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

    /// Whether the account is authorized by its own credential or a grant inherited from an
    /// ancestor call.
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
        _ctx: &CallContext<'_>,
    ) -> Result<ProgramOutput, Fatal> {
        let Some(program_output) = self.remaining_outputs.pop_front() else {
            panic!("Insufficient program outputs for chained calls");
        };
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

    fn authoritative_value(
        &mut self,
        account_id: AccountId,
        _ctx: &CallContext<'_>,
    ) -> Result<Option<AccountData>, Fatal> {
        // A witnessed account's value comes from its note, which the commitment and nullifier
        // bind. A public account inside the circuit has no note, so its claim is adopted the
        // first time each shard is named and the verifier checks it against real state.
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

        // A note carries its own authorization, so the journal states it as-is.
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

        // A public account inside the circuit has no note. At first sight its claim stands,
        // because the verifier re-derives authorization from the real signer set; afterwards it
        // must stay consistent with what this traversal has established.
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
        // Public PDAs cannot sign, so the verifier would re-derive their authorization as false.
        // Export false rather than the program's claim, and remember it so a later sighting is
        // judged the way the verifier will judge it.
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
