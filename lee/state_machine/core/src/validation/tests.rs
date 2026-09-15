use std::collections::VecDeque;

use super::{
    Backend, CallContext, Declarations, ThreadedDiff, ValidationError, validate_state_diff,
};
use crate::{
    account::{Account, AccountId, AccountWithMetadata, BalanceDiff, Data},
    error::InvalidProgramBehaviorError,
    program::{
        AccountStateDiff, BlockValidityWindow, ChainedCall, ProgramEvent, ProgramOutput,
        TimestampValidityWindow,
    },
};

const ROOT_PROGRAM: u8 = 1;
const CALLEE_PROGRAM: u8 = 2;
const ACCOUNT_A: u8 = 10;
const ACCOUNT_B: u8 = 11;
const ACCOUNT_C: u8 = 12;
const FIRST_CALLEE: u8 = 2;
const GRANDCHILD: u8 = 3;
const SIBLING: u8 = 4;

/// Records every hook the traversal fires, in order, so the check sequence itself is asserted
/// rather than only its outcomes.
struct Recorder {
    outputs: VecDeque<ProgramOutput>,
    /// What `expected_first_sight` answers: `Some` mimics an environment with authoritative
    /// state, `None` one that adopts the journalled claim.
    first_sight: Option<Account>,
    /// When set, every first sight is exported as unauthorized, mimicking an environment whose
    /// journal must not reveal an authorization its verifier cannot reproduce.
    mask_first_sight: bool,
    /// The inherited authorized set seen at each call, in traversal order.
    inherited: Vec<Vec<u8>>,
    log: Vec<String>,
}

impl Recorder {
    fn new(outputs: Vec<ProgramOutput>) -> Self {
        Self {
            outputs: outputs.into(),
            first_sight: None,
            mask_first_sight: false,
            inherited: Vec::new(),
            log: Vec::new(),
        }
    }

    fn masking_first_sight(mut self) -> Self {
        self.mask_first_sight = true;
        self
    }

    fn answering_first_sight(mut self, account: Account) -> Self {
        self.first_sight = Some(account);
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
        self.log.push(format!(
            "output_for_call({})",
            ctx.program_account_id.value()[0]
        ));
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

    fn expected_first_sight(
        &mut self,
        account_id: AccountId,
        _ctx: &CallContext<'_>,
    ) -> Result<Option<Account>, ValidationError> {
        self.log
            .push(format!("expected_first_sight({})", account_id.value()[0]));
        Ok(self.first_sight.clone())
    }

    fn judge_authorization(
        &mut self,
        pre: &AccountWithMetadata,
        position: usize,
        first_sight: bool,
        _ctx: &CallContext<'_>,
    ) -> Result<bool, ValidationError> {
        self.log.push(format!(
            "judge({}, pos={position}, first={first_sight})",
            pre.account_id.value()[0]
        ));
        Ok(pre.is_authorized && !(first_sight && self.mask_first_sight))
    }

    fn observe_windows(
        &mut self,
        _block: BlockValidityWindow,
        _timestamp: TimestampValidityWindow,
    ) -> Result<(), ValidationError> {
        self.log.push("observe_windows".to_owned());
        Ok(())
    }

    fn observe_events(&mut self, emitter: AccountId, events: Vec<ProgramEvent>) {
        self.log.push(format!(
            "observe_events({}, {})",
            emitter.value()[0],
            events.len()
        ));
    }

    fn finish(&mut self) -> Result<(), ValidationError> {
        self.log.push("finish".to_owned());
        Ok(())
    }
}

fn id(tag: u8) -> AccountId {
    AccountId::new([tag; 32])
}

fn pre_state(tag: u8, account: Account, is_authorized: bool) -> AccountWithMetadata {
    AccountWithMetadata::new(account, is_authorized, id(tag))
}

fn unchanged(tag: u8) -> AccountStateDiff {
    AccountStateDiff::unchanged(pre_state(tag, Account::default(), false))
}

fn root_call(accounts: &[u8]) -> ChainedCall {
    ChainedCall {
        program_account_id: id(ROOT_PROGRAM),
        pre_state_ids: accounts.iter().copied().map(id).collect(),
        instruction_data: Vec::new(),
        pda_seeds: Vec::new(),
    }
}

fn declarations(must_be_touched: &[AccountId], root_output_is_confined: bool) -> Declarations<'_> {
    Declarations {
        must_be_touched,
        root_output_is_confined,
    }
}

fn run(
    backend: &mut Recorder,
    call: ChainedCall,
    declarations: &Declarations<'_>,
) -> Result<ThreadedDiff, ValidationError> {
    validate_state_diff(backend, call, declarations)
}

#[test]
fn hooks_fire_in_the_documented_order() {
    // Root touches A and B, then chains to a callee that touches A again. The repeat sighting
    // must reuse A's original position and skip the first-sight lookup.
    let root = ProgramOutput::new(
        id(ROOT_PROGRAM),
        None,
        Vec::new(),
        vec![unchanged(ACCOUNT_A), unchanged(ACCOUNT_B)],
    )
    .with_chained_calls(vec![ChainedCall {
        program_account_id: id(CALLEE_PROGRAM),
        pre_state_ids: vec![id(ACCOUNT_A)],
        instruction_data: Vec::new(),
        pda_seeds: Vec::new(),
    }]);
    let callee = ProgramOutput::new(
        id(CALLEE_PROGRAM),
        Some(id(ROOT_PROGRAM)),
        Vec::new(),
        vec![unchanged(ACCOUNT_A)],
    );

    let mut backend = Recorder::new(vec![root, callee]);
    let must_be_touched = [id(ACCOUNT_A), id(ACCOUNT_B)];
    run(
        &mut backend,
        root_call(&[ACCOUNT_A, ACCOUNT_B]),
        &declarations(&must_be_touched, true),
    )
    .expect("the scripted tree is well behaved");

    assert_eq!(
        backend.log,
        vec![
            "output_for_call(1)",
            "expected_first_sight(10)",
            "judge(10, pos=0, first=true)",
            "expected_first_sight(11)",
            "judge(11, pos=1, first=true)",
            "observe_windows",
            "observe_events(1, 0)",
            "output_for_call(2)",
            "judge(10, pos=0, first=false)",
            "observe_windows",
            "observe_events(2, 0)",
            "finish",
        ]
    );
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
        pre_state_ids: vec![id(ACCOUNT_B), id(ACCOUNT_A)],
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
    let must_be_touched = [id(ACCOUNT_A)];
    let diff = run(
        &mut backend,
        root_call(&[ACCOUNT_A]),
        &declarations(&must_be_touched, true),
    )
    .expect("a callee may introduce an account the root did not name");

    assert_eq!(
        diff.accounts
            .iter()
            .map(|(pre, _)| pre.account_id.value()[0])
            .collect::<Vec<_>>(),
        vec![ACCOUNT_A, ACCOUNT_B]
    );
    assert!(
        backend
            .log
            .contains(&"judge(11, pos=1, first=true)".to_owned())
    );
}

#[test]
fn root_output_confinement_is_declared_per_environment() {
    let output = || {
        ProgramOutput::new(
            id(ROOT_PROGRAM),
            None,
            Vec::new(),
            vec![unchanged(ACCOUNT_A), unchanged(ACCOUNT_C)],
        )
    };
    let must_be_touched = [id(ACCOUNT_A)];

    let confined = run(
        &mut Recorder::new(vec![output()]),
        root_call(&[ACCOUNT_A]),
        &declarations(&must_be_touched, true),
    );
    assert!(matches!(
        confined,
        Err(ValidationError::ProgramBehavior(
            InvalidProgramBehaviorError::UndeclaredAccountInProgramOutput { account_id, .. }
        )) if account_id == id(ACCOUNT_C)
    ));

    run(
        &mut Recorder::new(vec![output()]),
        root_call(&[ACCOUNT_A]),
        &declarations(&must_be_touched, false),
    )
    .expect("an unconfined root may report an account its call did not name");
}

#[test]
fn a_callee_is_confined_regardless_of_the_root_declaration() {
    // The ordered `pre_states_match_accounts` check covers chained calls, so an unconfined root
    // does not loosen anything below it.
    let root = ProgramOutput::new(
        id(ROOT_PROGRAM),
        None,
        Vec::new(),
        vec![unchanged(ACCOUNT_A)],
    )
    .with_chained_calls(vec![ChainedCall {
        program_account_id: id(CALLEE_PROGRAM),
        pre_state_ids: vec![id(ACCOUNT_A)],
        instruction_data: Vec::new(),
        pda_seeds: Vec::new(),
    }]);
    let callee = ProgramOutput::new(
        id(CALLEE_PROGRAM),
        Some(id(ROOT_PROGRAM)),
        Vec::new(),
        vec![unchanged(ACCOUNT_A), unchanged(ACCOUNT_C)],
    );
    let must_be_touched = [id(ACCOUNT_A)];

    let result = run(
        &mut Recorder::new(vec![root, callee]),
        root_call(&[ACCOUNT_A]),
        &declarations(&must_be_touched, false),
    );
    assert!(matches!(
        result,
        Err(ValidationError::ProgramBehavior(
            InvalidProgramBehaviorError::ChainedCallAccountsMismatch { .. }
        ))
    ));
}

#[test]
fn an_authoritative_first_sight_value_is_enforced() {
    let funded = Account {
        balance: 42,
        ..Account::default()
    };
    let output = || {
        ProgramOutput::new(
            id(ROOT_PROGRAM),
            None,
            Vec::new(),
            vec![unchanged(ACCOUNT_A)],
        )
    };
    let must_be_touched = [id(ACCOUNT_A)];

    // The journalled pre-state is `Account::default()`, so an environment that knows the account
    // actually holds 42 rejects it.
    let result = run(
        &mut Recorder::new(vec![output()]).answering_first_sight(funded),
        root_call(&[ACCOUNT_A]),
        &declarations(&must_be_touched, true),
    );
    assert!(matches!(
        result,
        Err(ValidationError::ProgramBehavior(
            InvalidProgramBehaviorError::InconsistentAccountPreState { account_id, .. }
        )) if account_id == id(ACCOUNT_A)
    ));

    // An environment with no independently known value adopts the claim.
    run(
        &mut Recorder::new(vec![output()]),
        root_call(&[ACCOUNT_A]),
        &declarations(&must_be_touched, true),
    )
    .expect("a backend answering None adopts the journalled pre-state");
}

#[test]
fn an_unowned_account_that_changed_must_not_carry_data() {
    // A is unowned and already carries data; the call only moves balance into it, so nothing
    // claims it and it ends the transaction unowned with data.
    let unowned_with_data = Account {
        data: Data::try_from(vec![1, 2, 3]).expect("small data fits"),
        ..Account::default()
    };
    let funded = Account {
        balance: 5,
        ..Account::default()
    };

    let output = ProgramOutput::new(
        id(ROOT_PROGRAM),
        None,
        Vec::new(),
        vec![
            AccountStateDiff {
                pre_state: pre_state(ACCOUNT_A, unowned_with_data, false),
                post_balance_diff: BalanceDiff::Add(5),
                post_data: None,
            },
            AccountStateDiff {
                pre_state: pre_state(ACCOUNT_B, funded, true),
                post_balance_diff: BalanceDiff::Sub(5),
                post_data: None,
            },
        ],
    );
    let must_be_touched = [id(ACCOUNT_A), id(ACCOUNT_B)];

    let result = run(
        &mut Recorder::new(vec![output]),
        root_call(&[ACCOUNT_A, ACCOUNT_B]),
        &declarations(&must_be_touched, true),
    );
    assert!(matches!(
        result,
        Err(ValidationError::ProgramBehavior(
            InvalidProgramBehaviorError::DataBearingUnownedAccount { account_id }
        )) if account_id == id(ACCOUNT_A)
    ));
}

#[test]
fn a_declared_account_may_not_vanish_from_the_output() {
    let output = ProgramOutput::new(
        id(ROOT_PROGRAM),
        None,
        Vec::new(),
        vec![unchanged(ACCOUNT_A)],
    );
    let must_be_touched = [id(ACCOUNT_A), id(ACCOUNT_B)];

    let result = run(
        &mut Recorder::new(vec![output]),
        root_call(&[ACCOUNT_A, ACCOUNT_B]),
        &declarations(&must_be_touched, true),
    );
    assert!(matches!(
        result,
        Err(ValidationError::ProgramBehavior(
            InvalidProgramBehaviorError::DeclaredAccountMissingFromOutput { account_id }
        )) if account_id == id(ACCOUNT_B)
    ));
}

#[test]
fn the_call_budget_counts_calls_not_depth() {
    // A fan of sibling calls exhausts the same budget a chain would.
    let callees = super::MAX_NUMBER_CHAINED_CALLS + 1;
    let fan: Vec<ChainedCall> = std::iter::repeat_with(|| ChainedCall {
        program_account_id: id(CALLEE_PROGRAM),
        pre_state_ids: vec![id(ACCOUNT_A)],
        instruction_data: Vec::new(),
        pda_seeds: Vec::new(),
    })
    .take(callees)
    .collect();
    let root = ProgramOutput::new(
        id(ROOT_PROGRAM),
        None,
        Vec::new(),
        vec![unchanged(ACCOUNT_A)],
    )
    .with_chained_calls(fan);
    let mut outputs = vec![root];
    outputs.extend(
        std::iter::repeat_with(|| {
            ProgramOutput::new(
                id(CALLEE_PROGRAM),
                Some(id(ROOT_PROGRAM)),
                Vec::new(),
                vec![unchanged(ACCOUNT_A)],
            )
        })
        .take(callees),
    );
    let must_be_touched = [id(ACCOUNT_A)];

    let result = run(
        &mut Recorder::new(outputs),
        root_call(&[ACCOUNT_A]),
        &declarations(&must_be_touched, true),
    );
    assert!(matches!(
        result,
        Err(ValidationError::MaxChainedCallsDepthExceeded)
    ));
}

#[test]
fn a_masked_export_does_not_weaken_what_the_program_was_judged_on() {
    // The backend exports every first sight as unauthorized, but the call legitimately debits an
    // authorized account. `validate_execution` must judge the journalled flag, not the exported
    // one, or an environment that masks its journal could no longer prove an authorized spend.
    let funded = Account {
        balance: 5,
        ..Account::default()
    };
    let output = ProgramOutput::new(
        id(ROOT_PROGRAM),
        None,
        Vec::new(),
        vec![
            AccountStateDiff {
                pre_state: pre_state(ACCOUNT_A, funded, true),
                post_balance_diff: BalanceDiff::Sub(5),
                post_data: None,
            },
            AccountStateDiff {
                pre_state: pre_state(ACCOUNT_B, Account::default(), false),
                post_balance_diff: BalanceDiff::Add(5),
                post_data: None,
            },
        ],
    );
    let must_be_touched = [id(ACCOUNT_A), id(ACCOUNT_B)];

    let diff = run(
        &mut Recorder::new(vec![output]).masking_first_sight(),
        root_call(&[ACCOUNT_A, ACCOUNT_B]),
        &declarations(&must_be_touched, true),
    )
    .expect("masking the exported flag must not retract the authorization the program relied on");

    // What reaches the caller is the masked view.
    assert!(diff.accounts.iter().all(|(pre, _)| !pre.is_authorized));
}

#[test]
fn authorization_propagates_down_a_branch_but_not_across_siblings() {
    // The root journals A as authorized, so both of its callees inherit A. The first callee
    // journals B as authorized; that grant must reach the first callee's own child and must not
    // reach its sibling.
    let chained = |program: u8, accounts: &[u8]| ChainedCall {
        program_account_id: id(program),
        pre_state_ids: accounts.iter().copied().map(id).collect(),
        instruction_data: Vec::new(),
        pda_seeds: Vec::new(),
    };
    let authorized =
        |tag: u8| AccountStateDiff::unchanged(pre_state(tag, Account::default(), true));

    let root = ProgramOutput::new(
        id(ROOT_PROGRAM),
        None,
        Vec::new(),
        vec![authorized(ACCOUNT_A)],
    )
    .with_chained_calls(vec![
        chained(FIRST_CALLEE, &[ACCOUNT_A]),
        chained(SIBLING, &[ACCOUNT_A]),
    ]);
    let first_callee = ProgramOutput::new(
        id(FIRST_CALLEE),
        Some(id(ROOT_PROGRAM)),
        Vec::new(),
        vec![authorized(ACCOUNT_A)],
    )
    .with_chained_calls(vec![chained(GRANDCHILD, &[ACCOUNT_A])]);
    let grandchild = ProgramOutput::new(
        id(GRANDCHILD),
        Some(id(FIRST_CALLEE)),
        Vec::new(),
        vec![authorized(ACCOUNT_A)],
    );
    let sibling = ProgramOutput::new(
        id(SIBLING),
        Some(id(ROOT_PROGRAM)),
        Vec::new(),
        vec![authorized(ACCOUNT_A)],
    );

    let mut backend = Recorder::new(vec![root, first_callee, grandchild, sibling]);
    let must_be_touched = [id(ACCOUNT_A)];
    run(
        &mut backend,
        root_call(&[ACCOUNT_A]),
        &declarations(&must_be_touched, true),
    )
    .expect("the scripted tree is well behaved");

    // Depth-first: root, first callee, its grandchild, then the sibling. The root inherits
    // nothing; everything below it inherits A; the sibling inherits A from the root and nothing
    // from its sibling's subtree.
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
        pre_state_ids: vec![id(ACCOUNT_A)],
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
    let must_be_touched = [id(ACCOUNT_A)];

    let result = run(
        &mut Recorder::new(vec![root, callee]),
        root_call(&[ACCOUNT_A]),
        &declarations(&must_be_touched, true),
    );
    assert!(matches!(
        result,
        Err(ValidationError::ProgramBehavior(
            InvalidProgramBehaviorError::MismatchedInstructionData { program_account_id }
        )) if program_account_id == id(CALLEE_PROGRAM)
    ));
}
