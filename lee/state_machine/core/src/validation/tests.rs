use std::collections::{HashMap, VecDeque};

use super::{Backend, CallContext, ThreadedDiff, ValidationError, validate_state_diff};
use crate::{
    account::{AccountData, AccountId, ProgramShardSelector, ShardData},
    error::InvalidProgramBehaviorError,
    program::{
        AccountInput, BlockValidityWindow, ChainedCall, ProgramOutput, ShardStateDiff,
        TimestampValidityWindow,
    },
};

const ROOT_PROGRAM: u8 = 1;
const CALLEE_PROGRAM: u8 = 2;
const GRANDCHILD: u8 = 3;
const SIBLING: u8 = 4;
const ACCOUNT_A: u8 = 10;
const ACCOUNT_B: u8 = 11;
const ACCOUNT_C: u8 = 12;

struct Recorder {
    outputs: VecDeque<ProgramOutput>,
    /// Exports every first sight as unauthorized, as an environment whose journal must not
    /// reveal an authorization its verifier cannot reproduce.
    mask_first_sight: bool,
    inherited: Vec<Vec<u8>>,
    /// Accounts this environment has its own view of, as a witness gives the circuit.
    known: HashMap<AccountId, AccountData>,
}

impl Recorder {
    fn new(outputs: Vec<ProgramOutput>) -> Self {
        Self {
            outputs: outputs.into(),
            mask_first_sight: false,
            inherited: Vec::new(),
            known: HashMap::new(),
        }
    }

    fn knowing(mut self, account: u8, data: AccountData) -> Self {
        self.known.insert(id(account), data);
        self
    }

    fn masking_first_sight(mut self) -> Self {
        self.mask_first_sight = true;
        self
    }
}

impl Backend for Recorder {
    type Error = ValidationError;

    fn output_for_call(
        &mut self,
        _call: &ChainedCall,
        ctx: &CallContext<'_>,
    ) -> Result<ProgramOutput, ValidationError> {
        let mut inherited: Vec<u8> = ctx
            .authorized_accounts
            .iter()
            .map(|account_id| account_id.value()[0])
            .collect();
        inherited.sort_unstable();
        self.inherited.push(inherited);
        Ok(self
            .outputs
            .pop_front()
            .expect("the test supplies one output per call"))
    }

    fn has_independent_view(&mut self, account_id: AccountId) -> bool {
        self.known.contains_key(&account_id)
    }

    fn value_at_first_sight(
        &mut self,
        account_id: AccountId,
        _ctx: &CallContext<'_>,
    ) -> Result<Option<AccountData>, ValidationError> {
        Ok(self.known.get(&account_id).cloned())
    }

    fn judge_authorization(
        &mut self,
        pre: &AccountInput,
        first_sight: bool,
        _ctx: &CallContext<'_>,
    ) -> Result<bool, ValidationError> {
        Ok(pre.is_authorized && !(first_sight && self.mask_first_sight))
    }

    fn observe_windows(
        &mut self,
        _block: BlockValidityWindow,
        _timestamp: TimestampValidityWindow,
    ) -> Result<(), ValidationError> {
        Ok(())
    }
}

fn id(tag: u8) -> AccountId {
    AccountId::new([tag; 32])
}

fn shard(bytes: &[u8]) -> ShardData {
    bytes.to_vec().try_into().expect("test shard data is small")
}

fn shard_of(account: u8, program: u8) -> ProgramShardSelector {
    ProgramShardSelector::new(id(account), id(program))
}

/// A row claiming `data` for `selector` and leaving it unchanged.
fn read(selector: ProgramShardSelector, data: &[u8], is_authorized: bool) -> ShardStateDiff {
    ShardStateDiff::unchanged(AccountInput::with_shard(
        selector.account_id,
        is_authorized,
        selector.program_account_id,
        shard(data),
    ))
}

fn call(program: u8, selectors: &[ProgramShardSelector]) -> ChainedCall {
    ChainedCall {
        program_account_id: id(program),
        shard_selectors: selectors.to_vec(),
        instruction_data: Vec::new(),
        pda_seeds: Vec::new(),
    }
}

fn output(program: u8, caller: Option<u8>, rows: Vec<ShardStateDiff>) -> ProgramOutput {
    ProgramOutput::new(id(program), caller.map(id), Vec::new(), rows)
}

fn first_sights(diff: &ThreadedDiff) -> Vec<(u8, bool)> {
    diff.first_sight
        .iter()
        .map(|&(account_id, exported)| (account_id.value()[0], exported))
        .collect()
}

fn initial(diff: &ThreadedDiff, account: u8) -> &AccountData {
    &diff.at_first_sight[&id(account)]
}

fn running(diff: &ThreadedDiff, account: u8) -> &AccountData {
    &diff.touched[&id(account)]
}

#[test]
fn first_sight_order_survives_an_account_introduced_by_a_callee() {
    // A is first seen inside the chained call, so it takes position 1 although its id sorts first
    // and the transaction declares it first. Positions index per-account witness data downstream,
    // so the ordering is contract.
    let (shard_a, shard_b) = (
        shard_of(ACCOUNT_A, ROOT_PROGRAM),
        shard_of(ACCOUNT_B, ROOT_PROGRAM),
    );
    let root = output(ROOT_PROGRAM, None, vec![read(shard_b, b"", false)])
        .with_chained_calls(vec![call(CALLEE_PROGRAM, &[shard_a, shard_b])]);
    let callee = output(
        CALLEE_PROGRAM,
        Some(ROOT_PROGRAM),
        vec![read(shard_a, b"", false), read(shard_b, b"", false)],
    );

    let diff = validate_state_diff(
        &mut Recorder::new(vec![root, callee]),
        call(ROOT_PROGRAM, &[shard_b]),
        &[shard_a, shard_b],
    )
    .expect("a callee may be the first to touch an account the transaction declared");

    assert_eq!(
        first_sights(&diff),
        vec![(ACCOUNT_B, false), (ACCOUNT_A, false)]
    );
}

#[test]
fn journalled_grants_flow_down_a_branch_while_masked_exports_stay_masked() {
    // The root grants A and its first callee additionally B, so the grandchild inherits both and
    // the root's other callee only A. The first callee is also named C without authorizing it:
    // naming alone grants nothing. Every first sight is exported as unauthorized; the grants
    // must still follow the journalled flags.
    let (shard_a, shard_b, shard_c) = (
        shard_of(ACCOUNT_A, ROOT_PROGRAM),
        shard_of(ACCOUNT_B, ROOT_PROGRAM),
        shard_of(ACCOUNT_C, ROOT_PROGRAM),
    );
    let both = vec![read(shard_a, b"", true), read(shard_b, b"", true)];
    let root = output(ROOT_PROGRAM, None, vec![read(shard_a, b"", true)]).with_chained_calls(vec![
        call(CALLEE_PROGRAM, &[shard_a, shard_b, shard_c]),
        call(SIBLING, &[shard_a]),
    ]);
    let mut callee_rows = both.clone();
    callee_rows.push(read(shard_c, b"", false));
    let callee = output(CALLEE_PROGRAM, Some(ROOT_PROGRAM), callee_rows)
        .with_chained_calls(vec![call(GRANDCHILD, &[shard_a, shard_b])]);
    let grandchild = output(GRANDCHILD, Some(CALLEE_PROGRAM), both);
    let sibling = output(SIBLING, Some(ROOT_PROGRAM), vec![read(shard_a, b"", true)]);

    let mut backend = Recorder::new(vec![root, callee, grandchild, sibling]).masking_first_sight();
    let diff = validate_state_diff(&mut backend, call(ROOT_PROGRAM, &[shard_a]), &[shard_a])
        .expect("the scripted tree is well behaved");

    assert_eq!(
        backend.inherited,
        vec![
            vec![],
            vec![ACCOUNT_A],
            vec![ACCOUNT_A, ACCOUNT_B],
            vec![ACCOUNT_A]
        ]
    );
    assert_eq!(
        first_sights(&diff),
        vec![(ACCOUNT_A, false), (ACCOUNT_B, false), (ACCOUNT_C, false)]
    );
}

#[test]
fn a_callee_must_run_the_instruction_its_caller_sent() {
    let shard_a = shard_of(ACCOUNT_A, ROOT_PROGRAM);
    let root =
        output(ROOT_PROGRAM, None, vec![read(shard_a, b"", false)]).with_chained_calls(vec![
            ChainedCall {
                instruction_data: vec![1, 2, 3],
                ..call(CALLEE_PROGRAM, &[shard_a])
            },
        ]);
    let mut callee = output(
        CALLEE_PROGRAM,
        Some(ROOT_PROGRAM),
        vec![read(shard_a, b"", false)],
    );
    callee.instruction_data = vec![9, 9, 9];

    let result = validate_state_diff(
        &mut Recorder::new(vec![root, callee]),
        call(ROOT_PROGRAM, &[shard_a]),
        &[shard_a],
    );
    assert!(matches!(
        result,
        Err(ValidationError::ProgramBehavior(
            InvalidProgramBehaviorError::MismatchedInstructionData { program_account_id }
        )) if program_account_id == id(CALLEE_PROGRAM)
    ));
}

#[test]
fn an_unseen_shard_is_adopted_where_the_environment_has_no_view_of_it() {
    // Two calls name two different shards of one account. Both are adopted, and the second must
    // not be rejected against the first call's result, nor lost to a later call that reads it.
    // The root also rewrites the first shard: the adopted claims keep what was claimed, and the
    // later adoption must not revert the write.
    let (first, second) = (
        shard_of(ACCOUNT_A, ROOT_PROGRAM),
        shard_of(ACCOUNT_A, CALLEE_PROGRAM),
    );
    let rewrite = ShardStateDiff {
        post_data: Some(shard(b"rewritten")),
        ..read(first, b"first", false)
    };
    let root = output(ROOT_PROGRAM, None, vec![rewrite]).with_chained_calls(vec![
        call(CALLEE_PROGRAM, &[second]),
        call(SIBLING, &[first, second]),
    ]);
    let callee = output(
        CALLEE_PROGRAM,
        Some(ROOT_PROGRAM),
        vec![read(second, b"second", false)],
    );
    let later = output(
        SIBLING,
        Some(ROOT_PROGRAM),
        vec![
            read(first, b"rewritten", false),
            read(second, b"second", false),
        ],
    );

    let diff = validate_state_diff(
        &mut Recorder::new(vec![root, callee, later]),
        call(ROOT_PROGRAM, &[first]),
        &[first, second],
    )
    .expect("a shard the environment has no view of is adopted the first time it is named");

    for (account, root_shard) in [
        (initial(&diff, ACCOUNT_A), b"first".as_slice()),
        (running(&diff, ACCOUNT_A), b"rewritten".as_slice()),
    ] {
        assert_eq!(account.shard(id(ROOT_PROGRAM)), &shard(root_shard));
        assert_eq!(account.shard(id(CALLEE_PROGRAM)), &shard(b"second"));
    }
}

#[test]
fn an_adopted_empty_shard_still_counts_as_named() {
    // A resolver may legitimately answer with an empty shard. `set_shard` would delete the key;
    // the pre view must keep it, or the journal drops a shard the transaction did name.
    let named = shard_of(ACCOUNT_A, CALLEE_PROGRAM);
    let diff = validate_state_diff(
        &mut Recorder::new(vec![output(
            ROOT_PROGRAM,
            None,
            vec![read(named, b"", false)],
        )]),
        call(ROOT_PROGRAM, &[named]),
        &[named],
    )
    .expect("an empty adopted shard is legitimate");

    assert!(
        initial(&diff, ACCOUNT_A)
            .shards
            .contains_key(&id(CALLEE_PROGRAM)),
        "an empty adopted shard must still be recorded as named"
    );
}

#[test]
fn an_environment_with_its_own_view_checks_the_claim_rather_than_adopting_it() {
    // Where the environment knows the account, a claim is checked rather than adopted, even when
    // what it knows is empty.
    let named = shard_of(ACCOUNT_A, ROOT_PROGRAM);
    for known in [
        AccountData::default().with_shard(id(ROOT_PROGRAM), shard(b"real")),
        AccountData::default(),
    ] {
        let result = validate_state_diff(
            &mut Recorder::new(vec![output(
                ROOT_PROGRAM,
                None,
                vec![read(named, b"forged", false)],
            )])
            .knowing(ACCOUNT_A, known),
            call(ROOT_PROGRAM, &[named]),
            &[named],
        );
        assert!(matches!(
            result,
            Err(ValidationError::ProgramBehavior(
                InvalidProgramBehaviorError::InconsistentAccountPreState { account_id, .. }
            )) if account_id == id(ACCOUNT_A)
        ));
    }
}

#[test]
fn a_later_sighting_is_checked_against_the_running_value_not_the_first_one() {
    // A second call is judged on what the first left behind: the root's write is current, and
    // the shard data the environment started from is stale.
    let named = shard_of(ACCOUNT_A, ROOT_PROGRAM);
    let known = AccountData::default().with_shard(id(ROOT_PROGRAM), shard(b"old"));
    let run = |seen: &[u8]| {
        let write = ShardStateDiff::new(AccountInput::at(named, true, &known), shard(b"new"));
        let root = output(ROOT_PROGRAM, None, vec![write])
            .with_chained_calls(vec![call(CALLEE_PROGRAM, &[named])]);
        let callee = output(
            CALLEE_PROGRAM,
            Some(ROOT_PROGRAM),
            vec![read(named, seen, false)],
        );
        validate_state_diff(
            &mut Recorder::new(vec![root, callee]).knowing(ACCOUNT_A, known.clone()),
            call(ROOT_PROGRAM, &[named]),
            &[named],
        )
    };

    let diff = run(b"new").expect("a later sighting is checked against the running value");
    assert_eq!(
        running(&diff, ACCOUNT_A).shard(id(ROOT_PROGRAM)),
        &shard(b"new")
    );
    assert!(matches!(
        run(b"old"),
        Err(ValidationError::ProgramBehavior(
            InvalidProgramBehaviorError::InconsistentAccountPreState { account_id, .. }
        )) if account_id == id(ACCOUNT_A)
    ));
}

#[test]
fn a_declared_shard_selector_may_not_go_unreported() {
    // Reporting one shard of an account does not account for another shard of it.
    let (reported, omitted) = (
        shard_of(ACCOUNT_A, ROOT_PROGRAM),
        shard_of(ACCOUNT_A, CALLEE_PROGRAM),
    );
    let result = validate_state_diff(
        &mut Recorder::new(vec![output(
            ROOT_PROGRAM,
            None,
            vec![read(reported, b"", false)],
        )]),
        call(ROOT_PROGRAM, &[reported]),
        &[reported, omitted],
    );
    assert!(matches!(
        result,
        Err(ValidationError::ProgramBehavior(
            InvalidProgramBehaviorError::DeclaredAccountMissingFromOutput { account_id }
        )) if account_id == id(ACCOUNT_A)
    ));
}
