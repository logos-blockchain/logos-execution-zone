use cross_zone_inbox_core::{
    CrossZoneMessage, InboxConfig, Instruction, SeenShard, inbox_config_account_id,
    inbox_config_seed, inbox_seen_shard_account_id, inbox_seen_shard_seed,
};
use cross_zone_marker_core::inbox_source_marker_account_id;
use lee_core::{
    account::{Account, AccountDiff, BalanceDiff},
    program::{AccountDiffOutput, ChainedCall, Claim, ProgramCall, ProgramInput, read_lee_call},
};

fn main() {
    let ProgramCall::Execute { input, instruction } = read_lee_call::<Instruction>();

    assert!(
        input.call.caller_program_id.is_none(),
        "Inbox is only invoked as a top-level sequencer-origin transaction"
    );

    match instruction {
        Instruction::Dispatch(msg) => dispatch(input, &msg),
        Instruction::InitConfig(config) => init_config(input, &config),
    }
}

/// Delivers a finalized peer message to its target program, no-op on replay.
///
/// The inbox does not decide who may deliver what. It authenticates transport
/// and nothing else: any program this zone hosts can be named as a target, with
/// instruction bytes and account ids the peer chose. So a program meant to be
/// reachable across zones MUST check the marker at position 0 against sources it
/// authorized itself, the way `wrapped_token` and `ping_receiver` do. A program
/// not meant to be reachable has only whatever its own code happens to do. Today
/// every other builtin refuses, but by three different accidents: four assert
/// `caller_program_id` is none; several run to completion and are stopped by the
/// host, either because they try to claim the marker without its authorization or
/// because they chain into its zero program id; and the rest are saved by an
/// address assert on a PDA. None of that was written with cross-zone delivery in
/// mind. User-deployed programs are reachable too, and were written with no
/// expectation of an inbox caller at all.
fn dispatch(input: ProgramInput, msg: &CrossZoneMessage) {
    assert!(
        msg.l1_inclusion_witness.is_none(),
        "l1_inclusion_witness must be None in v1"
    );

    // pre_states layout: [config, seen_shard, source marker, then the target accounts].
    let (config, seen, marker, target_accounts) = match input.pre_states.as_slice() {
        [config, seen, marker, target_accounts @ ..] => (config, seen, marker, target_accounts),
        [] => panic!("config account required"),
        [_] => panic!("seen shard account required"),
        [_, _] => panic!("source marker account required"),
    };

    assert_eq!(
        config.account_id,
        inbox_config_account_id(input.call.self_program_id),
        "First account must be the inbox config PDA"
    );
    assert_eq!(
        seen.account_id,
        inbox_seen_shard_account_id(input.call.self_program_id, &msg.src_zone, msg.src_block_id),
        "Second account must be the seen-shard PDA"
    );
    // The one value the chained call carries about where the message came from.
    // The target re-derives this address from the source it accepts, so binding it
    // here is what makes a target's own check meaningful.
    assert_eq!(
        marker.account_id,
        inbox_source_marker_account_id(
            input.call.self_program_id,
            &msg.src_zone,
            msg.src_program_id
        ),
        "Third account must be the source marker PDA for this message"
    );

    let cfg = InboxConfig::from_bytes(&config.account.data).expect("inbox config decodes");

    assert!(
        msg.src_zone != cfg.self_zone,
        "Source zone must not be this zone"
    );
    let mut shard = SeenShard::from_bytes(&seen.account.data).expect("seen shard decodes");

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
        (AccountDiffOutput::unchanged(seen.account_id), vec![])
    } else {
        shard.insert(msg.src_block_hash, msg.src_tx_index);
        let seen_diff = AccountDiff {
            id: seen.account_id,
            diff_balance: BalanceDiff::Add(0),
            diff_data: Some(
                shard
                    .to_bytes()
                    .try_into()
                    .expect("seen shard fits in account data"),
            ),
        };
        let seen_post = AccountDiffOutput::new_claimed_if_default(
            seen_diff,
            seen.account.program_owner,
            Claim::Pda(inbox_seen_shard_seed(&msg.src_zone, msg.src_block_id)),
        );

        // The payload carries the target instruction as borsh bytes: its instruction_data verbatim.
        let call_instruction_data = msg.payload.clone();

        // The marker leads, so a target reads its source at a fixed position
        // without knowing anything about the accounts that follow it.
        let mut call_accounts = vec![marker.account_id];
        call_accounts.extend(target_accounts.iter().map(|a| a.account_id));
        let call = ChainedCall {
            program_id: msg.target_program_id,
            accounts: call_accounts,
            instruction_data: call_instruction_data,
            pda_seeds: vec![],
        };
        (seen_post, vec![call])
    };

    let mut post_states = vec![
        AccountDiffOutput::unchanged(config.account_id),
        seen_post,
        AccountDiffOutput::unchanged(marker.account_id),
    ];
    post_states.extend(
        target_accounts
            .iter()
            .map(|pre| AccountDiffOutput::unchanged(pre.account_id)),
    );

    input
        .into_output(post_states)
        .with_chained_calls(chained_calls)
        .write();
}

/// Writes the inbox config into the config PDA exactly once at genesis.
fn init_config(input: ProgramInput, config: &InboxConfig) {
    // pre_states: [config PDA].
    let [config_meta] = input.pre_states.as_slice() else {
        panic!("InitConfig requires the config account");
    };
    assert_eq!(
        config_meta.account_id,
        inbox_config_account_id(input.call.self_program_id),
        "account must be the inbox config PDA"
    );
    // Init-once, idempotent under genesis replay: a `default` config is a first
    // init; an already-owned config must already hold exactly this, since genesis
    // is replayed onto seeded state during multi-sequencer reconstruction.
    // `new_claimed_if_default` alone would not stop the owning program from
    // rewriting its own config data on a later call.
    if config_meta.account != Account::default() {
        assert_eq!(
            config_meta.account.program_owner,
            input.call.self_program_id.into(),
            "inbox config PDA is owned by another program"
        );
        assert_eq!(
            *config_meta.account.data,
            config.to_bytes(),
            "inbox config already initialized differently"
        );
    }

    let config_diff = AccountDiff {
        id: config_meta.account_id,
        diff_balance: BalanceDiff::Add(0),
        diff_data: Some(
            config
                .to_bytes()
                .try_into()
                .expect("inbox config fits in account data"),
        ),
    };
    let config_post = AccountDiffOutput::new_claimed_if_default(
        config_diff,
        config_meta.account.program_owner,
        Claim::Pda(inbox_config_seed()),
    );

    input.into_output(vec![config_post]).write();
}
