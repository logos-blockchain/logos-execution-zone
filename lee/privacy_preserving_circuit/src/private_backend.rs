//! The privacy preserving circuit's half of the shared traversal.
//!
//! What makes this environment private is concentrated here: it verifies a proof of each call
//! rather than executing it, it has no chain state to resolve an account's value against, and a
//! PDA seed proves authorization through a supplied witness rather than through a public
//! derivation alone. The traversal in [`lee_core::validation`] owns everything else.

use std::{
    collections::{HashMap, HashSet, VecDeque, hash_map::Entry},
    convert::Infallible,
};

use lee_core::{
    BlockId, Identifier, InputAccountIdentity, NullifierPublicKey, PrivateWitness,
    ProgramImageClaim, Timestamp, WitnessKind,
    account::{Account, AccountId, AccountWithMetadata},
    encryption::ViewingPublicKey,
    program::{
        BlockValidityWindow, ChainedCall, PdaSeed, ProgramId, ProgramOutput,
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

/// What the traversal derived that only the output stage needs: the intersected validity
/// windows, and the `(program, seed)` each private-PDA position was bound under.
pub struct DerivedOutputs {
    pub block_validity_window: BlockValidityWindow,
    pub timestamp_validity_window: TimestampValidityWindow,
    pub pda_seed_by_position: HashMap<usize, (AccountId, PdaSeed)>,
}

pub struct PrivateBackend<'input> {
    /// One entry per account in first-sight order; the traversal's `position` indexes it.
    account_identities: &'input [InputAccountIdentity],
    remaining_outputs: VecDeque<ProgramOutput>,
    /// Untrusted, prover-supplied. `env::verify` needs a real image id, not a dispatch address.
    /// The circuit does not check these against chain state; the sequencer does that
    /// independently before accepting the proof. See [`ProgramImageClaim`].
    image_id_by_account_id: HashMap<AccountId, ProgramId>,
    /// The `(npk, vpk, identifier)` supplied for each private-PDA position, used by both binding
    /// paths to verify `AccountId::for_private_pda(...) == pre_state.account_id`.
    private_pda_by_position: HashMap<usize, (NullifierPublicKey, ViewingPublicKey, Identifier)>,
    /// Positions whose supplied npk has been bound to their `AccountId` by a proven derivation,
    /// via the position's own witness `binding` or via a caller's `pda_seeds`. Binding is an
    /// idempotent property, not an event: the same position may legitimately be bound through
    /// both paths in one transaction. Every private-PDA position must appear here by the end.
    private_pda_bound_positions: HashMap<usize, (AccountId, PdaSeed)>,
    /// Each `(program, seed)` resolves to at most one account per transaction. A seed under a
    /// program derives a family, one member per distinct npk; without this a single `pda_seeds`
    /// entry could authorize several members at once and let a callee mix balances across them.
    pda_family_binding: HashMap<(AccountId, PdaSeed), AccountId>,
    /// Non-PDA accounts authorized at first sight anywhere in the tree stay authorized
    /// throughout. The public environment gets the same effect from its signer set.
    globally_authorized: HashSet<AccountId>,
    block_bounds: (Option<BlockId>, Option<BlockId>),
    timestamp_bounds: (Option<Timestamp>, Option<Timestamp>),
}

impl<'input> PrivateBackend<'input> {
    pub fn new(
        account_identities: &'input [InputAccountIdentity],
        program_outputs: Vec<ProgramOutput>,
        program_image_claims: &[ProgramImageClaim],
    ) -> Self {
        let mut private_pda_by_position = HashMap::new();
        for (position, account_identity) in account_identities.iter().enumerate() {
            if let Some(witness) = account_identity.npk_vpk_if_private_pda() {
                private_pda_by_position.insert(position, witness);
            }
        }

        Self {
            account_identities,
            remaining_outputs: program_outputs.into(),
            image_id_by_account_id: program_image_claims
                .iter()
                .map(|claim| (claim.account_id, claim.image_id))
                .collect(),
            private_pda_by_position,
            private_pda_bound_positions: HashMap::new(),
            pda_family_binding: HashMap::new(),
            globally_authorized: HashSet::new(),
            block_bounds: (None, None),
            timestamp_bounds: (None, None),
        }
    }

    /// The accumulated windows and the per-position `(program, seed)` map the output stage needs
    /// to rebuild each private PDA's ciphertext header.
    #[must_use]
    pub fn into_parts(self) -> DerivedOutputs {
        let block_validity_window: BlockValidityWindow = self.block_bounds.try_into().expect(
            "There should be non empty intersection in the program output block validity windows",
        );
        let timestamp_validity_window: TimestampValidityWindow = self
            .timestamp_bounds
            .try_into()
            .expect(
            "There should be non empty intersection in the program output timestamp validity windows",
        );
        DerivedOutputs {
            block_validity_window,
            timestamp_validity_window,
            pda_seed_by_position: self.private_pda_bound_positions,
        }
    }

    /// Match `account_id` against the caller's seeds under the public-PDA derivation.
    fn match_caller_seed_as_public_pda(
        ctx: &CallContext<'_>,
        account_id: AccountId,
    ) -> Option<(PdaSeed, AccountId)> {
        let caller_account_id = ctx.caller_account_id?;
        // Costy for calls with multiple seeds in one call.
        ctx.pda_seeds.iter().find_map(|seed| {
            (AccountId::for_public_pda(&caller_account_id, seed) == account_id)
                .then_some((*seed, caller_account_id))
        })
    }

    /// Match `account_id` against the caller's seeds under the private-PDA derivation, using the
    /// `(npk, vpk, identifier)` supplied for this position. `None` when the position carries no
    /// private-PDA witness.
    fn match_caller_seed_as_private_pda(
        &self,
        ctx: &CallContext<'_>,
        account_id: AccountId,
        position: usize,
    ) -> Option<(PdaSeed, AccountId)> {
        let (npk, vpk, identifier) = self.private_pda_by_position.get(&position)?;
        let caller_account_id = ctx.caller_account_id?;
        // Costy for calls with multiple seeds in one call.
        ctx.pda_seeds.iter().find_map(|seed| {
            (AccountId::for_private_pda(&caller_account_id, seed, npk, vpk, *identifier)
                == account_id)
                .then_some((*seed, caller_account_id))
        })
    }

    /// Record or re-verify the `(program, seed) -> account_id` family binding.
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

    fn bind_private_pda_position(
        &mut self,
        position: usize,
        program_account_id: AccountId,
        seed: PdaSeed,
    ) {
        match self.private_pda_bound_positions.entry(position) {
            Entry::Occupied(entry) => assert_eq!(
                *entry.get(),
                (program_account_id, seed),
                "Duplicate binding at position {position}: conflicting (program_id, seed)"
            ),
            Entry::Vacant(entry) => {
                entry.insert((program_account_id, seed));
            }
        }
    }

    /// Check the position's own witness-declared `(authority, seed)` binding, once, at first
    /// sight. The alternative path is a caller's `pda_seeds` matching the same derivation.
    fn bind_from_witness(&mut self, account_id: AccountId, position: usize) {
        let Some(InputAccountIdentity::Private(PrivateWitness {
            kind:
                WitnessKind::Pda {
                    binding: Some((authority_account_id, seed)),
                },
            ..
        })) = self.account_identities.get(position)
        else {
            return;
        };
        let (authority_account_id, seed) = (*authority_account_id, *seed);
        let (npk, vpk, identifier) = self
            .private_pda_by_position
            .get(&position)
            .expect("a Pda witness always yields npk, vpk and identifier for its position");
        let expected =
            AccountId::for_private_pda(&authority_account_id, &seed, npk, vpk, *identifier);
        assert_eq!(
            account_id, expected,
            "External seed mismatch for private PDA at position {position}"
        );
        self.bind_private_pda_position(position, authority_account_id, seed);
        self.assert_family_binding(authority_account_id, seed, account_id);
    }

    /// The bidirectional authorization check for a position that carries a private-PDA witness,
    /// or for any account seen before. Records the bindings a caller-seed match establishes.
    fn assert_authorization(
        &mut self,
        ctx: &CallContext<'_>,
        account_id: AccountId,
        position: usize,
        journalled: bool,
    ) {
        let matched = Self::match_caller_seed_as_public_pda(ctx, account_id)
            .map(|(seed, caller)| (seed, false, caller))
            .or_else(|| {
                self.match_caller_seed_as_private_pda(ctx, account_id, position)
                    .map(|(seed, caller)| (seed, true, caller))
            });

        if let Some((seed, is_private_form, caller_account_id)) = matched {
            self.assert_family_binding(caller_account_id, seed, account_id);
            if is_private_form {
                self.bind_private_pda_position(position, caller_account_id, seed);
            }
        }

        let is_authorized = matched.is_some()
            || self.globally_authorized.contains(&account_id)
            || ctx.authorized_accounts.contains(&account_id);

        assert_eq!(
            journalled, is_authorized,
            "Inconsistent authorization for account {account_id}"
        );
    }

    /// Judge a first sight that carries no private-PDA witness. Returns whether the account is a
    /// caller-seeded public PDA, whose authorization must be masked out of the journal.
    fn authorize_first_sight_without_pda_witness(
        &mut self,
        ctx: &CallContext<'_>,
        account_id: AccountId,
        journalled: bool,
    ) -> bool {
        if let Some((seed, caller_account_id)) =
            Self::match_caller_seed_as_public_pda(ctx, account_id)
        {
            assert!(
                journalled,
                "Caller-seeded public PDA must be declared authorized at first sight: {account_id}"
            );
            self.assert_family_binding(caller_account_id, seed, account_id);
            true
        } else {
            // A non-PDA account authorized at first sight is authorized for the whole tree.
            if journalled {
                self.globally_authorized.insert(account_id);
            }
            false
        }
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

    fn expected_first_sight(
        &mut self,
        _account_id: AccountId,
        _ctx: &CallContext<'_>,
    ) -> Result<Option<Account>, Fatal> {
        // The circuit has no chain state to resolve against. A note's content is bound by its
        // commitment and nullifier, checked in the output stage, not by this traversal.
        Ok(None)
    }

    fn judge_authorization(
        &mut self,
        pre: &AccountWithMetadata,
        position: usize,
        first_sight: bool,
        ctx: &CallContext<'_>,
    ) -> Result<bool, Fatal> {
        let account_id = pre.account_id;
        let journalled = pre.is_authorized;

        if !first_sight {
            self.assert_authorization(ctx, account_id, position, journalled);
            return Ok(journalled);
        }

        self.bind_from_witness(account_id, position);

        if self.private_pda_by_position.contains_key(&position) {
            self.assert_authorization(ctx, account_id, position, journalled);
            return Ok(journalled);
        }

        if self.authorize_first_sight_without_pda_witness(ctx, account_id, journalled) {
            // The verifier cannot replay the transaction to see which public PDAs a caller
            // seeded, and it checks regular accounts against the real signer set instead. So a
            // caller-seeded public PDA is exported unauthorized, and the program's own claim
            // stays out of the journal.
            return Ok(false);
        }

        Ok(journalled)
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

        // Every private-PDA pre_state must have had its npk bound to its account_id, via its own
        // witness binding or a caller's pda_seeds. An unbound one has no cryptographic link
        // between the supplied npk and the account_id.
        for (position, account_identity) in self.account_identities.iter().enumerate() {
            assert!(
                !account_identity.is_private_pda()
                    || self.private_pda_bound_positions.contains_key(&position),
                "private PDA pre_state at position {position} has no proven (seed, npk) binding via witness binding or caller pda_seeds"
            );
        }
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
