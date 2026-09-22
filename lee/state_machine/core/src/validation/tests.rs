use std::collections::VecDeque;

use super::{Backend, CallContext, ThreadedDiff, ValidationError, validate_state_diff};
use crate::{
    account::{AccountData, AccountId, BalanceDiff, ProgramShardSelector},
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

/// A scripted backend: replays prepared outputs and records what the traversal asked of it.
struct Recorder {
    outputs: VecDeque<ProgramOutput>,
    /// When set, every first sight is exported as unauthorized, mimicking an environment whose
    /// journal must not reveal an authorization its verifier cannot reproduce.
    mask_first_sight: bool,
    /// The inherited authorized set seen at each call, in traversal order.
    inherited: Vec<Vec<u8>>,
    /// One entry per `judge_authorization`, recording the position and first-sight flag.
    judged: Vec<String>,
}

impl Recorder {
    fn new(outputs: Vec<ProgramOutput>) -> Self {
        Self {
            outputs: outputs.into(),
            mask_first_sight: false,
            inherited: Vec::new(),
            judged: Vec::new(),
        }
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

    fn authoritative_value(
        &mut self,
        _account_id: AccountId,
        _ctx: &CallContext<'_>,
    ) -> Result<Option<AccountData>, ValidationError> {
        // No independent view: the journalled claim stands, as in the circuit.
        Ok(None)
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

/// The balance shard of `tag`: the selector a program names when it only touches the balance.
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
    // B is first seen inside the chained call, so it takes position 1 even though the root's own
    // output named only A. Positions index per-account witness data downstream, so this ordering
    // is part of the contract.
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
    // The backend exports every first sight as unauthorized, but the call legitimately debits an
    // authorized account. `validate_execution` must judge the journalled flag, not the exported
    // one, or an environment that masks its journal could no longer prove an authorized spend.
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
    // The root journals A as authorized, so both of its callees inherit A. Masking matters here:
    // the backend exports every first sight as unauthorized, so the exported flag and the
    // journalled one disagree, and propagation must follow the journalled one.
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

    // Depth-first: root, first callee, its grandchild, then the sibling. The root inherits
    // nothing; everything below it inherits A.
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
    // The callee answers with a proof of the same program on a different instruction.
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
