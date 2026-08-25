use cross_zone_inbox_core::{
    CrossZoneMessage, InboxConfig, Instruction, SeenShard, inbox_config_account_id,
    inbox_seen_shard_account_id,
};
use cross_zone_marker_core::inbox_source_marker_account_id;
use lee_core::{
    account::{Account, AccountWithMetadata},
    program::{ChainedCall, ProgramId, ProgramInput, ProgramOutput, read_lee_inputs},
};

fn unchanged(pre: &AccountWithMetadata) -> Account {
    pre.account.clone()
}

fn main() {
    let (
        ProgramInput {
            self_program_id,
            caller_program_id,
            pre_states,
            instruction,
        },
        instruction_data,
    ) = read_lee_inputs::<Instruction>();

    assert!(
        caller_program_id.is_none(),
        "Inbox is only invoked as a top-level sequencer-origin transaction"
    );

    match instruction {
        Instruction::Dispatch(msg) => dispatch(
            self_program_id,
            caller_program_id,
            pre_states,
            instruction_data,
            &msg,
        ),
        Instruction::InitConfig(config) => init_config(
            self_program_id,
            caller_program_id,
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
/// not meant to be reachable has only whatever its own code happens to do. Today
/// every other builtin refuses, but by two different accidents: several assert
/// `caller_program_id` is none, and the rest are saved by an address assert on a
/// PDA. None of that was written with cross-zone delivery in mind.
/// User-deployed programs are reachable too, and were written with no
/// expectation of an inbox caller at all.
fn dispatch(
    self_program_id: ProgramId,
    caller_program_id: Option<ProgramId>,
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
        inbox_config_account_id(self_program_id),
        "First account must be the inbox config PDA"
    );
    assert_eq!(
        seen.account_id,
        inbox_seen_shard_account_id(self_program_id, &msg.src_zone, msg.src_block_id),
        "Second account must be the seen-shard PDA"
    );
    // The one value the chained call carries about where the message came from.
    // The target re-derives this address from the source it accepts, so binding it
    // here is what makes a target's own check meaningful.
    assert_eq!(
        marker.account_id,
        inbox_source_marker_account_id(self_program_id, &msg.src_zone, msg.src_program_id),
        "Third account must be the source marker PDA for this message"
    );

    let cfg = InboxConfig::from_bytes(config.account.data(self_program_id))
        .expect("inbox config decodes");

    assert!(
        msg.src_zone != cfg.self_zone,
        "Source zone must not be this zone"
    );
    let mut shard =
        SeenShard::from_bytes(seen.account.data(self_program_id)).expect("seen shard decodes");

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
        let mut seen_post = seen.account.clone();
        seen_post.slot_mut(self_program_id).data = shard
            .to_bytes()
            .try_into()
            .expect("seen shard fits in account data");

        // The payload carries the target instruction as borsh bytes: its instruction_data verbatim.
        let call_instruction_data = msg.payload.clone();

        // The marker leads, so a target reads its source at a fixed position
        // without knowing anything about the accounts that follow it.
        let mut call_pre_states = vec![marker.clone()];
        call_pre_states.extend(target_accounts.clone());
        let call = ChainedCall {
            program_id: msg.target_program_id,
            pre_states: call_pre_states,
            instruction_data: call_instruction_data,
        };
        (seen_post, vec![call])
    };

    let mut post_states = vec![unchanged(&config), seen_post, unchanged(&marker)];
    post_states.extend(target_accounts.iter().map(unchanged));

    let mut output_pre_states = vec![config, seen, marker];
    output_pre_states.extend(target_accounts);

    ProgramOutput::new(
        self_program_id,
        caller_program_id,
        instruction_data,
        output_pre_states,
        post_states,
    )
    .with_chained_calls(chained_calls)
    .write();
}

/// Writes the inbox config into the config PDA exactly once at genesis.
fn init_config(
    self_program_id: ProgramId,
    caller_program_id: Option<ProgramId>,
    pre_states: Vec<AccountWithMetadata>,
    instruction_data: Vec<u8>,
    config: &InboxConfig,
) {
    // pre_states: [config PDA].
    let [config_meta] = <[AccountWithMetadata; 1]>::try_from(pre_states)
        .expect("InitConfig requires the config account");
    assert_eq!(
        config_meta.account_id,
        inbox_config_account_id(self_program_id),
        "account must be the inbox config PDA"
    );
    // Init-once, idempotent under genesis replay: an account this program has not
    // written is a first init; an already-written one must already hold exactly
    // this, since genesis is replayed onto seeded state during multi-sequencer
    // reconstruction.
    if let Some(slot) = config_meta.account.slot(self_program_id) {
        assert_eq!(
            *slot.data,
            config.to_bytes(),
            "inbox config already initialized differently"
        );
    }

    let mut config_post = config_meta.account.clone();
    config_post.slot_mut(self_program_id).data = config
        .to_bytes()
        .try_into()
        .expect("inbox config fits in account data");

    ProgramOutput::new(
        self_program_id,
        caller_program_id,
        instruction_data,
        vec![config_meta],
        vec![config_post],
    )
    .write();
}
