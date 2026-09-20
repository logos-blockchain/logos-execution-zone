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
    BlockId, DeferredResolution, Identifier, InputAccountIdentity, NullifierPublicKey,
    PrivateWitness, ProgramImageClaim, Timestamp, WitnessKind,
    account::{Account, AccountId, AccountWithMetadata},
    encryption::ViewingPublicKey,
    program::{
        AccountStateDiff, BlockValidityWindow, CallKind, ChainedCall, DeferReads, IncrementalCall,
        PdaSeed, ProgramId, ProgramOutput, TimestampValidityWindow, UnsupportedCallKind,
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
/// windows, the `(program, seed)` each private-PDA position was bound under, and each public
/// account's final `Bound`/`Deferred` classification.
pub struct DerivedOutputs {
    pub block_validity_window: BlockValidityWindow,
    pub timestamp_validity_window: TimestampValidityWindow,
    pub pda_seed_by_position: HashMap<usize, (AccountId, PdaSeed)>,
    pub classification: HashMap<AccountId, WriteFate>,
}

/// A public account's classification, decided across every call that touches it. Absence from
/// the map means the same as `Bound` at output time - nothing was written, nothing to defer.
///
/// `Bound` is permanent: a later touch, even a covered one, can't move an account back to
/// `Deferred` - see `classify_touch`.
#[derive(Clone)]
pub enum WriteFate {
    Bound,
    /// Unresolved deltas, in touch order. A read never appears here - covered reads are no-ops,
    /// uncovered ones force `Bound`.
    Deferred(Vec<DeferredResolution>),
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
    /// Mirrors the traversal's own first-sight position assignment, one call ahead of it -
    /// `output_for_call` needs positions before the traversal assigns them for this call's
    /// diffs. Grown in the same order the traversal grows its own, so a lookup here always
    /// agrees with what `judge_authorization` is later called with for the same account.
    position_by_account: HashMap<AccountId, usize>,
    next_position: usize,
    /// This call's `Probe` claim, if any - `None` covers both "never asked" (no public account
    /// touched) and "asked but declined". Reset every `output_for_call`; read by `resolve_write`
    /// before the next call's `output_for_call` runs (the traversal always processes them in
    /// that order).
    current_call_defer_reads: Option<DeferReads>,
    /// Each public account's classification, across every call that's touched it. See
    /// [`WriteFate`].
    classification: HashMap<AccountId, WriteFate>,
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
            position_by_account: HashMap::new(),
            next_position: 0,
            current_call_defer_reads: None,
            classification: HashMap::new(),
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
            classification: self.classification,
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

    /// Verifies `output` as a genuine receipt from `self_account_id`'s real guest ELF, via
    /// recursive proof composition rather than live re-execution.
    fn verify_receipt(&self, self_account_id: AccountId, output: &ProgramOutput) {
        let image_id = self
            .image_id_by_account_id
            .get(&self_account_id)
            .copied()
            .expect("no image_id claim supplied for invoked program account");
        let frame = lee_core::to_borsh_frame(output);
        env::verify(image_id, &frame)
            .unwrap_or_else(|_: Infallible| unreachable!("Infallible error is never constructed"));
    }

    /// Whether `program_output`'s diffs touch a public account - real position assignment,
    /// moments later, just reuses what's mirrored here (`entry` is idempotent). See
    /// `position_by_account`'s doc for why the mirror has to persist across calls.
    fn touches_public(&mut self, program_output: &ProgramOutput) -> bool {
        let account_identities = self.account_identities;
        let position_by_account = &mut self.position_by_account;
        let next_position = &mut self.next_position;
        program_output.state_diffs.iter().any(|diff| {
            let account_id = diff.pre_state.account_id;
            let position = *position_by_account.entry(account_id).or_insert_with(|| {
                let pos = *next_position;
                *next_position = next_position
                    .checked_add(1)
                    .expect("account position count cannot overflow usize");
                pos
            });
            matches!(
                account_identities.get(position),
                Some(InputAccountIdentity::Public)
            )
        })
    }

    /// Pops the next `CallKind::Incremental` receipt and verifies it (see
    /// [`Self::verify_receipt`]) as this call's single `Probe` response - one per program
    /// invocation, covering every public account it touches, reads and writes alike (see
    /// `DeferReads`'s doc).
    ///
    /// Binds the claim to the real `Execute` call it answers for by checking its
    /// `instruction_data` matches `program_output.instruction_data` - without this a malicious
    /// prover could answer `Probe` for a different instruction than the one it actually
    /// executed, making a claim that was never really evaluated against this call.
    ///
    /// Returns `None` for both a genuine `UnsupportedCallKind` response and a claim this program
    /// simply declined to make - either way there's nothing to check `covers()` against, and the
    /// caller treats both the same: force every touch `Bound`.
    fn verify_probe_receipt(
        &mut self,
        call: &ChainedCall,
        ctx: &CallContext<'_>,
        program_output: &ProgramOutput,
    ) -> Option<DeferReads> {
        let Some(probe_output) = self.remaining_outputs.pop_front() else {
            panic!("prover must supply a Probe receipt for this call");
        };
        assert_eq!(
            probe_output.call_kind,
            CallKind::Incremental,
            "expected a Probe output for program {:?}",
            call.program_account_id
        );
        assert_eq!(
            probe_output.self_account_id, call.program_account_id,
            "Probe output for program {:?} was produced by the wrong program",
            call.program_account_id
        );
        assert_eq!(
            probe_output.caller_account_id, ctx.caller_account_id,
            "Probe output for program {:?} has the wrong caller",
            call.program_account_id
        );
        let Ok(IncrementalCall::Probe(probed_instruction_data)) =
            borsh::from_slice::<IncrementalCall>(&probe_output.instruction_data)
        else {
            panic!(
                "Probe output for program {:?} is not a Probe envelope",
                call.program_account_id
            );
        };
        assert_eq!(
            probed_instruction_data, program_output.instruction_data,
            "Probe output for program {:?} was answered for a different instruction than its \
             Execute call received",
            call.program_account_id
        );

        self.verify_receipt(call.program_account_id, &probe_output);

        probe_output
            .events
            .iter()
            .find(|event| event.selector == DeferReads::SELECTOR)
            .and_then(|event| borsh::from_slice::<DeferReads>(&event.data).ok())
    }

    /// Classifies one touch of `account_id` as `Bound` or `Deferred`, using this call's `Probe`
    /// claim (`current_call_defer_reads`). A no-op for a private account, or once already
    /// permanently `Bound`. See [`WriteFate`]'s doc.
    ///
    /// `diff` is the *unresolved* diff `output_for_call` produced - a `Deferred` write is
    /// recorded as this raw delta, never the value `resolve_write` computed, since settlement
    /// replays it against live state later.
    fn classify_touch(
        &mut self,
        account_id: AccountId,
        is_write: bool,
        diff: &AccountStateDiff,
        ctx: &CallContext<'_>,
    ) {
        let position = *self
            .position_by_account
            .entry(account_id)
            .or_insert_with(|| {
                let pos = self.next_position;
                self.next_position = self
                    .next_position
                    .checked_add(1)
                    .expect("account position count cannot overflow usize");
                pos
            });
        let is_public = matches!(
            self.account_identities.get(position),
            Some(InputAccountIdentity::Public)
        );
        if !is_public {
            return;
        }

        let covered = self
            .current_call_defer_reads
            .is_some_and(|claim| claim.covers(is_write));
        // Lazy: only reached (twice, once per branch below) when `covered && is_write`, so a
        // read or an uncovered touch never pays for `post_data`'s clone.
        let resolution = || DeferredResolution {
            executing_account_id: ctx.program_account_id,
            post_balance_diff: diff.post_balance_diff,
            post_data: diff.post_data.clone(),
        };

        match self.classification.entry(account_id) {
            Entry::Occupied(mut entry) => {
                if matches!(entry.get(), WriteFate::Bound) {
                    // Permanent - a later touch, even a covered one, changes nothing.
                    return;
                }
                if !covered {
                    entry.insert(WriteFate::Bound);
                } else if is_write {
                    let WriteFate::Deferred(resolutions) = entry.get_mut() else {
                        unreachable!("the Bound case already returned above")
                    };
                    resolutions.push(resolution());
                } else {
                    // A covered read is a no-op, exactly as if this touch never happened.
                }
            }
            Entry::Vacant(entry) => {
                if !covered {
                    entry.insert(WriteFate::Bound);
                } else if is_write {
                    entry.insert(WriteFate::Deferred(vec![resolution()]));
                } else {
                    // A covered read on a not-yet-classified account stays unclassified - the
                    // same as `Bound` at output time, since nothing was ever written.
                }
            }
        }
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
        self.verify_receipt(call.program_account_id, &program_output);

        // One `Probe` per call, covering every public account it touches - popped here, right
        // after `Execute`, so it lands before any `Update` receipts this call's own writes
        // produce (see `execute_and_prove_probe`'s call site on the prover side).
        self.current_call_defer_reads = if self.touches_public(&program_output) {
            self.verify_probe_receipt(call, ctx, &program_output)
        } else {
            None
        };

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

    /// For a write, pops the next `CallKind::Incremental` receipt and verifies it (see
    /// [`Self::verify_receipt`]) as the `Update` resolution - the in-circuit analog of
    /// `PublicBackend::resolve_write`. Every write is resolved unconditionally, regardless of its
    /// eventual `Bound`/`Deferred` classification: the account's real, resolved value is always
    /// needed for chain continuity, and if it ends up `Bound`, it's the literal final value.
    /// Falls back to `diff` verbatim if the program declines (`UnsupportedCallKind`). A read has
    /// nothing to resolve and gets no receipt, so none is popped for one.
    ///
    /// Every touch, write or read, is then classified `Bound`/`Deferred` - see `classify_touch`.
    /// `Update`'s outcome never affects that classification, only what `resolved` is.
    fn resolve_write(
        &mut self,
        diff: &AccountStateDiff,
        ctx: &CallContext<'_>,
    ) -> Result<AccountStateDiff, Fatal> {
        let account_id = diff.pre_state.account_id;
        let is_write = diff.post_data.is_some();

        let resolved = if is_write {
            let Some(update_output) = self.remaining_outputs.pop_front() else {
                panic!("Insufficient program outputs for chained calls");
            };

            assert_eq!(
                update_output.call_kind,
                CallKind::Incremental,
                "expected an Update resolution output for account {account_id}"
            );
            assert_eq!(
                update_output.self_account_id, ctx.program_account_id,
                "Update resolution output for account {account_id} was produced by the wrong \
                 program"
            );
            // `Update` is never caller-gated (whitelisting belongs at `Execute` time), and is
            // proven with no caller for exactly that reason - see
            // `execute_and_prove_incremental`.
            assert_eq!(
                update_output.caller_account_id, None,
                "Update resolution output for account {account_id} has the wrong caller"
            );

            self.verify_receipt(ctx.program_account_id, &update_output);

            let unsupported = update_output
                .events
                .iter()
                .any(|event| event.selector == UnsupportedCallKind::SELECTOR);
            if unsupported {
                diff.clone()
            } else {
                let expected_pre_account = diff.pre_state.account.clone();
                let [resolved]: [AccountStateDiff; 1] = update_output
                    .state_diffs
                    .try_into()
                    .unwrap_or_else(|diffs: Vec<AccountStateDiff>| {
                        panic!(
                            "Incremental resolution for account {account_id} returned {} \
                                 diffs, expected 1",
                            diffs.len()
                        )
                    });
                assert_eq!(
                    resolved.pre_state.account_id, account_id,
                    "Incremental resolution returned a diff for the wrong account"
                );
                assert_eq!(
                    resolved.pre_state.account, expected_pre_account,
                    "Incremental resolution for account {account_id} was run against the wrong \
                     pre_state"
                );
                resolved
            }
        } else {
            diff.clone()
        };

        self.classify_touch(account_id, is_write, diff, ctx);

        Ok(resolved)
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
