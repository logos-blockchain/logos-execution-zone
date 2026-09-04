use cross_zone_inbox_core::{
    CrossZoneMessage, InboxConfig, Instruction, SeenShard, inbox_config_account_id,
    inbox_seen_shard_account_id,
};
use cross_zone_marker_core::inbox_source_marker_account_id;
use lee_core::{
    account::{AccountWithMetadata, BalanceDiff},
    program::{
        AccountStateDiff, ChainedCall, ProgramCall, ProgramInput, ProgramOutput, read_lee_call,
        respond_unsupported_call,
    },
};

fn unchanged(pre: &AccountWithMetadata) -> AccountStateDiff {
    AccountStateDiff::unchanged(pre.clone())
}

fn main() {
    let call = read_lee_call::<Instruction>();
    let ProgramCall::Execute(
        ProgramInput {
            self_account_id,
            caller_account_id,
            pre_states,
            instruction,
        },
        instruction_data,
    ) = call
    else {
        respond_unsupported_call(call);
    };

    assert!(
        caller_account_id.is_none(),
        "Inbox is only invoked as a top-level sequencer-origin transaction"
    );

    match instruction {
        Instruction::Dispatch(msg) => dispatch(
            self_account_id,
            caller_account_id,
            pre_states,
            instruction_data,
            &msg,
        ),
        Instruction::InitConfig(config) => init_config(
            self_account_id,
            caller_account_id,
            pre_states,
            instruction_data,
            &config,
        ),
    }
}

/// Delivers a finalized peer message to its target program, no-op on replay.
///
/// The inbox does not decide who may deliver what. It authenticates transport
/// and nothing else: any program this zone hosts can be named as a target, with
/// instruction bytes and account ids the peer chose. So a program meant to be
/// reachable across zones MUST check the marker at position 0 against sources it
/// authorized itself, the way `wrapped_token` and `ping_receiver` do. A program
/// not meant to be reachable has only whatever its own code happens to do. Some
/// refuse: four assert `caller_account_id` is none, several chain into the
/// marker's zero program id and are stopped by the host, and the rest are saved
/// by an address assert on a PDA. Others no longer do — a target that used to be
/// stopped only because it claimed the marker without its authorization now runs,
/// since ownership follows a data write and needs no claim. What such a target
/// can be made to do is write state at addresses the peer names, which is the
/// squatting any locally deployed program can already do, at no local fee. None
/// of that was written with cross-zone delivery in mind. User-deployed programs
/// are reachable too, and were written with no expectation of an inbox caller at
/// all.
fn dispatch(
    self_account_id: lee_core::account::AccountId,
    caller_account_id: Option<lee_core::account::AccountId>,
    pre_states: Vec<AccountWithMetadata>,
    instruction_data: Vec<u8>,
    msg: &CrossZoneMessage,
) {
    assert!(
        msg.l1_inclusion_witness.is_none(),
        "l1_inclusion_witness must be None in v1"
    );

    // pre_states layout: [config, seen_shard, source marker, then the target accounts].
    let mut accounts = pre_states.into_iter();
    let config = accounts.next().expect("config account required");
    let seen = accounts.next().expect("seen shard account required");
    let marker = accounts.next().expect("source marker account required");
    let target_accounts: Vec<AccountWithMetadata> = accounts.collect();

    assert_eq!(
        config.account_id,
        inbox_config_account_id(self_account_id),
        "First account must be the inbox config PDA"
    );
    assert_eq!(
        seen.account_id,
        inbox_seen_shard_account_id(self_account_id, &msg.src_zone, msg.src_block_id),
        "Second account must be the seen-shard PDA"
    );
    // The one value the chained call carries about where the message came from.
    // The target re-derives this address from the source it accepts, so binding it
    // here is what makes a target's own check meaningful.
    assert_eq!(
        marker.account_id,
        inbox_source_marker_account_id(self_account_id, &msg.src_zone, msg.src_account_id),
        "Third account must be the source marker PDA for this message"
    );

    let cfg = InboxConfig::from_bytes(&config.account.data).expect("inbox config decodes");

    assert!(
        msg.src_zone != cfg.self_zone,
        "Source zone must not be this zone"
    );
    // Mirrors the bridge receipt.
    let mut shard = if seen.account.program_owner == self_account_id {
        SeenShard::from_bytes(&seen.account.data).expect("seen shard decodes")
    } else {
        SeenShard::default()
    };

    // One block id, one delivering block. The address binds the zone and block
    // id but not which block claimed them, so an equivocating peer's two blocks
    // at one id land here; the first binds the shard and the second aborts.
    //
    // Before the replay check, not after: reaching the replay branch first would
    // turn a wrong-block delivery into a silent no-op, which the indexer's
    // already-seen short circuit would then wave through.
    assert!(
        shard.binds(&msg.src_block_hash),
        "Seen shard is bound to a different peer block at this block id"
    );

    let already_seen = shard.contains(msg.src_tx_index);

    // On replay this is a no-op: the seen shard is untouched and no call is made.
    let (seen_post, chained_calls) = if already_seen {
        (unchanged(&seen), vec![])
    } else {
        shard.insert(msg.src_block_hash, msg.src_tx_index);
        let seen_post = AccountStateDiff::new(
            seen,
            BalanceDiff::Add(0),
            shard
                .to_bytes()
                .try_into()
                .expect("seen shard fits in account data"),
        );

        // The payload carries the target instruction as borsh bytes: its instruction_data verbatim.
        let call_instruction_data = msg.payload.clone();

        // The marker leads, so a target reads its source at a fixed position
        // without knowing anything about the accounts that follow it.
        let mut call_accounts = vec![marker.account_id];
        call_accounts.extend(target_accounts.iter().map(|a| a.account_id));
        let call = ChainedCall {
            program_account_id: msg.target_account_id,
            pre_state_ids: call_accounts,
            instruction_data: call_instruction_data,
            pda_seeds: vec![],
        };
        (seen_post, vec![call])
    };

    let mut post_diffs = vec![unchanged(&config), seen_post, unchanged(&marker)];
    post_diffs.extend(target_accounts.iter().map(unchanged));

    ProgramOutput::new(
        self_account_id,
        caller_account_id,
        instruction_data,
        post_diffs,
    )
    .with_chained_calls(chained_calls)
    .write();
}

/// Writes the inbox config into the config PDA exactly once at genesis.
fn init_config(
    self_account_id: lee_core::account::AccountId,
    caller_account_id: Option<lee_core::account::AccountId>,
    pre_states: Vec<AccountWithMetadata>,
    instruction_data: Vec<u8>,
    config: &InboxConfig,
) {
    // pre_states: [config PDA].
    let [config_meta] = <[AccountWithMetadata; 1]>::try_from(pre_states)
        .expect("InitConfig requires the config account");
    assert_eq!(
        config_meta.account_id,
        inbox_config_account_id(self_account_id),
        "account must be the inbox config PDA"
    );
    // Init-once, idempotent under genesis replay: an empty config is a first init;
    // a written config must already hold exactly this, since genesis is replayed
    // onto seeded state during multi-sequencer reconstruction. Implicit ownership
    // alone would not stop the owning program from rewriting its own config data
    // on a later call.
    if !config_meta.account.data.is_empty() {
        assert_eq!(
            config_meta.account.program_owner, self_account_id,
            "inbox config PDA is owned by another program"
        );
        assert_eq!(
            *config_meta.account.data,
            config.to_bytes(),
            "inbox config already initialized differently"
        );
    }

    let config_post = AccountStateDiff::new(
        config_meta,
        BalanceDiff::Add(0),
        config
            .to_bytes()
            .try_into()
            .expect("inbox config fits in account data"),
    );

    ProgramOutput::new(
        self_account_id,
        caller_account_id,
        instruction_data,
        vec![config_post],
    )
    .write();
}
