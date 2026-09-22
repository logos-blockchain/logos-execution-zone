use std::collections::{HashMap, VecDeque};

use super::{Backend, CallContext, ThreadedDiff, ValidationError, validate_state_diff};
use crate::{
    account::{AccountData, AccountId, BalanceDiff, ProgramShardSelector, ShardData},
    error::InvalidProgramBehaviorError,
    program::{
        AccountInput, AccountStateDiff, BlockValidityWindow, ChainedCall, ProgramOutput,
        TimestampValidityWindow,
    },
};

const ROOT_PROGRAM: u8 = 1;
const CALLEE_PROGRAM: u8 = 2;
const GRANDCHILD: u8 = 3;
const SIBLING: u8 = 4;
const ACCOUNT_A: u8 = 10;
const ACCOUNT_B: u8 = 11;

struct Recorder {
    outputs: VecDeque<ProgramOutput>,
    /// Exports every first sight as unauthorized, as an environment whose journal must not
    /// reveal an authorization its verifier cannot reproduce.
    mask_first_sight: bool,
    inherited: Vec<Vec<u8>>,
    judged: Vec<String>,
    /// Accounts this environment has its own view of, as a witness gives the circuit.
    known: HashMap<AccountId, AccountData>,
}

impl Recorder {
    fn new(outputs: Vec<ProgramOutput>) -> Self {
        Self {
            outputs: outputs.into(),
            mask_first_sight: false,
            inherited: Vec::new(),
            judged: Vec::new(),
            known: HashMap::new(),
        }
    }

    fn knowing(mut self, account_id: AccountId, data: AccountData) -> Self {
        self.known.insert(account_id, data);
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
        self.judged.push(format!(
            "judge({}, first={first_sight})",
            pre.account_id.value()[0]
        ));
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

/// The selector a program names when it only touches the balance.
fn selector(tag: u8) -> ProgramShardSelector {
    ProgramShardSelector::balance(id(tag))
}

fn input(tag: u8, is_authorized: bool) -> AccountInput {
    AccountInput::at(selector(tag), is_authorized, &AccountData::default())
}

fn unchanged(tag: u8) -> AccountStateDiff {
    AccountStateDiff::unchanged(input(tag, false))
}

fn root_call(accounts: &[u8]) -> ChainedCall {
    ChainedCall {
        program_account_id: id(ROOT_PROGRAM),
        shard_selectors: accounts.iter().copied().map(selector).collect(),
        instruction_data: Vec::new(),
        pda_seeds: Vec::new(),
    }
}

fn run(
    backend: &mut Recorder,
    call: ChainedCall,
    declared: &[ProgramShardSelector],
) -> Result<ThreadedDiff, ValidationError> {
    validate_state_diff(backend, call, declared)
}

#[test]
fn first_sight_order_survives_an_account_introduced_by_a_callee() {
    // B is first seen inside the chained call, so it takes position 1. Positions index
    // per-account witness data downstream, so the ordering is contract.
    let root = ProgramOutput::new(
        id(ROOT_PROGRAM),
        None,
        Vec::new(),
        vec![unchanged(ACCOUNT_A)],
    )
    .with_chained_calls(vec![ChainedCall {
        program_account_id: id(CALLEE_PROGRAM),
        shard_selectors: vec![selector(ACCOUNT_B), selector(ACCOUNT_A)],
        instruction_data: Vec::new(),
        pda_seeds: Vec::new(),
    }]);
    let callee = ProgramOutput::new(
        id(CALLEE_PROGRAM),
        Some(id(ROOT_PROGRAM)),
        Vec::new(),
        vec![unchanged(ACCOUNT_B), unchanged(ACCOUNT_A)],
    );

    let mut backend = Recorder::new(vec![root, callee]);
    let declared = [selector(ACCOUNT_A), selector(ACCOUNT_B)];
    let diff = run(&mut backend, root_call(&[ACCOUNT_A]), &declared)
        .expect("a callee may be the first to touch an account the transaction declared");

    assert_eq!(
        diff.first_sight
            .iter()
            .map(|(account_id, _)| account_id.value()[0])
            .collect::<Vec<_>>(),
        vec![ACCOUNT_A, ACCOUNT_B]
    );
    assert!(backend.judged.contains(&"judge(11, first=true)".to_owned()));
}

#[test]
fn a_masked_export_does_not_weaken_what_the_program_was_judged_on() {
    // The call legitimately debits an authorized account while every first sight is exported as
    // unauthorized. Judging the exported flag would break every masked authorized spend.
    let funded = AccountData {
        balance: 5,
        ..AccountData::default()
    };
    let output = ProgramOutput::new(
        id(ROOT_PROGRAM),
        None,
        Vec::new(),
        vec![
            AccountStateDiff {
                pre_state: AccountInput::at(selector(ACCOUNT_A), true, &funded),
                post_balance_diff: BalanceDiff::Sub(5),
                post_data: None,
            },
            AccountStateDiff {
                pre_state: input(ACCOUNT_B, false),
                post_balance_diff: BalanceDiff::Add(5),
                post_data: None,
            },
        ],
    );
    let declared = [selector(ACCOUNT_A), selector(ACCOUNT_B)];

    let diff = run(
        &mut Recorder::new(vec![output]).masking_first_sight(),
        root_call(&[ACCOUNT_A, ACCOUNT_B]),
        &declared,
    )
    .expect("masking the exported flag must not retract the authorization the program relied on");

    // What reaches the caller is the masked view.
    assert!(
        diff.first_sight
            .iter()
            .all(|(_, is_authorized)| !is_authorized)
    );
}

#[test]
fn authorization_propagates_down_a_branch_but_not_across_siblings() {
    // The root journals A as authorized, so both callees inherit A. The exported flag disagrees
    // here, and propagation must follow the journalled one.
    let chained = |program: u8, accounts: &[u8]| ChainedCall {
        program_account_id: id(program),
        shard_selectors: accounts.iter().copied().map(selector).collect(),
        instruction_data: Vec::new(),
        pda_seeds: Vec::new(),
    };
    let authorized = |tag: u8| AccountStateDiff::unchanged(input(tag, true));

    let root = ProgramOutput::new(
        id(ROOT_PROGRAM),
        None,
        Vec::new(),
        vec![authorized(ACCOUNT_A)],
    )
    .with_chained_calls(vec![
        chained(CALLEE_PROGRAM, &[ACCOUNT_A]),
        chained(SIBLING, &[ACCOUNT_A]),
    ]);
    let first_callee = ProgramOutput::new(
        id(CALLEE_PROGRAM),
        Some(id(ROOT_PROGRAM)),
        Vec::new(),
        vec![authorized(ACCOUNT_A)],
    )
    .with_chained_calls(vec![chained(GRANDCHILD, &[ACCOUNT_A])]);
    let grandchild = ProgramOutput::new(
        id(GRANDCHILD),
        Some(id(CALLEE_PROGRAM)),
        Vec::new(),
        vec![authorized(ACCOUNT_A)],
    );
    let sibling = ProgramOutput::new(
        id(SIBLING),
        Some(id(ROOT_PROGRAM)),
        Vec::new(),
        vec![authorized(ACCOUNT_A)],
    );

    let mut backend =
        Recorder::new(vec![root, first_callee, grandchild, sibling]).masking_first_sight();
    let declared = [selector(ACCOUNT_A)];
    run(&mut backend, root_call(&[ACCOUNT_A]), &declared)
        .expect("the scripted tree is well behaved");

    assert_eq!(
        backend.inherited,
        vec![
            Vec::<u8>::new(),
            vec![ACCOUNT_A],
            vec![ACCOUNT_A],
            vec![ACCOUNT_A],
        ]
    );
}

#[test]
fn a_callee_must_run_the_instruction_its_caller_sent() {
    let root = ProgramOutput::new(
        id(ROOT_PROGRAM),
        None,
        Vec::new(),
        vec![unchanged(ACCOUNT_A)],
    )
    .with_chained_calls(vec![ChainedCall {
        program_account_id: id(CALLEE_PROGRAM),
        shard_selectors: vec![selector(ACCOUNT_A)],
        instruction_data: vec![1, 2, 3],
        pda_seeds: Vec::new(),
    }]);
    let callee = ProgramOutput::new(
        id(CALLEE_PROGRAM),
        Some(id(ROOT_PROGRAM)),
        vec![9, 9, 9],
        vec![unchanged(ACCOUNT_A)],
    );
    let declared = [selector(ACCOUNT_A)];

    let result = run(
        &mut Recorder::new(vec![root, callee]),
        root_call(&[ACCOUNT_A]),
        &declared,
    );
    assert!(matches!(
        result,
        Err(ValidationError::ProgramBehavior(
            InvalidProgramBehaviorError::MismatchedInstructionData { program_account_id }
        )) if program_account_id == id(CALLEE_PROGRAM)
    ));
}

/// A selector naming one program's shard of an account, rather than its balance.
fn shard_of(tag: u8, program: u8) -> ProgramShardSelector {
    ProgramShardSelector::new(id(tag), id(program))
}

fn shard(bytes: &[u8]) -> ShardData {
    bytes.to_vec().try_into().expect("test shard data is small")
}

fn with_shard(
    selector: ProgramShardSelector,
    data: ShardData,
    is_authorized: bool,
) -> AccountInput {
    let mut account = AccountData::default();
    if let Some(program) = selector.program_account_id {
        account.shards.insert(program, data);
    }
    AccountInput::at(selector, is_authorized, &account)
}

#[test]
fn an_unseen_shard_is_adopted_where_the_environment_has_no_view_of_it() {
    // Two calls name two different shards of one account. Both are adopted, and the second must
    // not be rejected against the first call's result.
    let root = ProgramOutput::new(
        id(ROOT_PROGRAM),
        None,
        Vec::new(),
        vec![AccountStateDiff::unchanged(with_shard(
            shard_of(ACCOUNT_A, ROOT_PROGRAM),
            shard(b"first"),
            false,
        ))],
    )
    .with_chained_calls(vec![ChainedCall {
        program_account_id: id(CALLEE_PROGRAM),
        shard_selectors: vec![shard_of(ACCOUNT_A, CALLEE_PROGRAM)],
        instruction_data: Vec::new(),
        pda_seeds: Vec::new(),
    }]);
    let callee = ProgramOutput::new(
        id(CALLEE_PROGRAM),
        Some(id(ROOT_PROGRAM)),
        Vec::new(),
        vec![AccountStateDiff::unchanged(with_shard(
            shard_of(ACCOUNT_A, CALLEE_PROGRAM),
            shard(b"second"),
            false,
        ))],
    );
    let declared = [
        shard_of(ACCOUNT_A, ROOT_PROGRAM),
        shard_of(ACCOUNT_A, CALLEE_PROGRAM),
    ];

    let diff = run(
        &mut Recorder::new(vec![root, callee]),
        ChainedCall {
            program_account_id: id(ROOT_PROGRAM),
            shard_selectors: vec![shard_of(ACCOUNT_A, ROOT_PROGRAM)],
            instruction_data: Vec::new(),
            pda_seeds: Vec::new(),
        },
        &declared,
    )
    .expect("a shard the environment has no view of is adopted the first time it is named");

    let pre = &diff.at_first_sight[&id(ACCOUNT_A)];
    assert_eq!(pre.shard(id(ROOT_PROGRAM)), &shard(b"first"));
    assert_eq!(pre.shard(id(CALLEE_PROGRAM)), &shard(b"second"));
}

#[test]
fn an_adopted_empty_shard_still_counts_as_named() {
    // A resolver may legitimately answer with an empty shard. `set_shard` would delete the key;
    // the pre view must keep it, or the journal drops a shard the transaction did name.
    let output = ProgramOutput::new(
        id(ROOT_PROGRAM),
        None,
        Vec::new(),
        vec![AccountStateDiff::unchanged(with_shard(
            shard_of(ACCOUNT_A, CALLEE_PROGRAM),
            ShardData::empty(),
            false,
        ))],
    );
    let declared = [shard_of(ACCOUNT_A, CALLEE_PROGRAM)];

    let diff = run(
        &mut Recorder::new(vec![output]),
        ChainedCall {
            program_account_id: id(ROOT_PROGRAM),
            shard_selectors: vec![shard_of(ACCOUNT_A, CALLEE_PROGRAM)],
            instruction_data: Vec::new(),
            pda_seeds: Vec::new(),
        },
        &declared,
    )
    .expect("an empty adopted shard is legitimate");

    assert!(
        diff.at_first_sight[&id(ACCOUNT_A)]
            .shards
            .contains_key(&id(CALLEE_PROGRAM)),
        "an empty adopted shard must still be recorded as named"
    );
}

#[test]
fn an_environment_with_its_own_view_checks_the_claim_rather_than_adopting_it() {
    // Where the environment knows the account, a claim is checked rather than adopted. The
    // balances agree, so only the adoption branch can decide this.
    let known = AccountData::default().with_shard(id(ROOT_PROGRAM), shard(b"real"));
    let output = ProgramOutput::new(
        id(ROOT_PROGRAM),
        None,
        Vec::new(),
        vec![AccountStateDiff::unchanged(with_shard(
            shard_of(ACCOUNT_A, ROOT_PROGRAM),
            shard(b"forged"),
            false,
        ))],
    );
    let declared = [shard_of(ACCOUNT_A, ROOT_PROGRAM)];

    let result = run(
        &mut Recorder::new(vec![output]).knowing(id(ACCOUNT_A), known),
        ChainedCall {
            program_account_id: id(ROOT_PROGRAM),
            shard_selectors: vec![shard_of(ACCOUNT_A, ROOT_PROGRAM)],
            instruction_data: Vec::new(),
            pda_seeds: Vec::new(),
        },
        &declared,
    );
    assert!(matches!(
        result,
        Err(ValidationError::ProgramBehavior(
            InvalidProgramBehaviorError::InconsistentAccountPreState { account_id, .. }
        )) if account_id == id(ACCOUNT_A)
    ));
}

#[test]
fn a_later_sighting_is_checked_against_the_running_value_not_the_first_one() {
    // A second call is judged on what the first left behind. Comparing against the environment's
    // original view would reject every legitimate chained spend.
    let known = AccountData {
        balance: 100,
        ..AccountData::default()
    };
    let spend = AccountStateDiff::balance(
        AccountInput::at(selector(ACCOUNT_A), true, &known),
        BalanceDiff::Sub(40),
    );
    let credit = AccountStateDiff::balance(input(ACCOUNT_B, false), BalanceDiff::Add(40));
    let root = ProgramOutput::new(id(ROOT_PROGRAM), None, Vec::new(), vec![spend, credit])
        .with_chained_calls(vec![ChainedCall {
            program_account_id: id(CALLEE_PROGRAM),
            shard_selectors: vec![selector(ACCOUNT_A)],
            instruction_data: Vec::new(),
            pda_seeds: Vec::new(),
        }]);
    // The callee sees 60, the balance the root call left, not the 100 the environment knows.
    let after = AccountData {
        balance: 60,
        ..AccountData::default()
    };
    let callee = ProgramOutput::new(
        id(CALLEE_PROGRAM),
        Some(id(ROOT_PROGRAM)),
        Vec::new(),
        vec![AccountStateDiff::unchanged(AccountInput::at(
            selector(ACCOUNT_A),
            false,
            &after,
        ))],
    );

    let diff = run(
        &mut Recorder::new(vec![root, callee]).knowing(id(ACCOUNT_A), known),
        root_call(&[ACCOUNT_A, ACCOUNT_B]),
        &[selector(ACCOUNT_A), selector(ACCOUNT_B)],
    )
    .expect("a later sighting is checked against the running value");

    assert_eq!(diff.touched[&id(ACCOUNT_A)].balance, 60);
}

#[test]
fn a_declared_shard_selector_may_not_go_unreported() {
    let output = ProgramOutput::new(
        id(ROOT_PROGRAM),
        None,
        Vec::new(),
        vec![unchanged(ACCOUNT_A)],
    );
    let declared = [selector(ACCOUNT_A), selector(ACCOUNT_B)];

    let result = run(
        &mut Recorder::new(vec![output]),
        root_call(&[ACCOUNT_A]),
        &declared,
    );
    assert!(matches!(
        result,
        Err(ValidationError::ProgramBehavior(
            InvalidProgramBehaviorError::DeclaredAccountMissingFromOutput { account_id }
        )) if account_id == id(ACCOUNT_B)
    ));
}
