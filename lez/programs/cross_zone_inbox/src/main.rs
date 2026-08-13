use cross_zone_inbox_core::{
    CrossZoneMessage, InboxConfig, Instruction, SeenShard, inbox_config_account_id,
    inbox_config_seed, inbox_seen_shard_account_id, inbox_seen_shard_seed,
};
use lee_core::{
    account::{Account, AccountWithMetadata},
    program::{
        AccountPostState, ChainedCall, Claim, ProgramId, ProgramInput, ProgramOutput,
        read_lee_inputs,
    },
};

fn unchanged(pre: &AccountWithMetadata) -> AccountPostState {
    AccountPostState::new(pre.account.clone())
}

fn main() {
    let (
        ProgramInput {
            self_program_id,
            caller_program_id,
            pre_states,
            instruction,
        },
        instruction_words,
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
            instruction_words,
            &msg,
        ),
        Instruction::InitConfig(config) => init_config(
            self_program_id,
            caller_program_id,
            pre_states,
            instruction_words,
            &config,
        ),
    }
}

/// Delivers a finalized peer message to its target program, no-op on replay.
fn dispatch(
    self_program_id: ProgramId,
    caller_program_id: Option<ProgramId>,
    pre_states: Vec<AccountWithMetadata>,
    instruction_words: Vec<u32>,
    msg: &CrossZoneMessage,
) {
    assert!(
        msg.l1_inclusion_witness.is_none(),
        "l1_inclusion_witness must be None in v1"
    );

    // pre_states layout: [config, seen_shard, then the target accounts].
    let mut accounts = pre_states.into_iter();
    let config = accounts.next().expect("config account required");
    let seen = accounts.next().expect("seen shard account required");
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

    let cfg = InboxConfig::from_bytes(&config.account.data.clone().into_inner())
        .expect("inbox config decodes");

    assert!(
        msg.src_zone != cfg.self_zone,
        "Source zone must not be this zone"
    );
    // Checked as a pair. The emitting program is as much a part of the
    // authorization as the target: an emitter whose caller chooses the target
    // reaches everything the peer may reach, so a target allowlist on its own
    // lets any such emitter stand in for every other one.
    assert!(
        cfg.permits(&msg.src_zone, msg.src_program_id, msg.target_program_id),
        "No route from this source program to this target program for this peer"
    );

    let mut shard =
        SeenShard::from_bytes(&seen.account.data.clone().into_inner()).expect("seen shard decodes");

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
        let mut seen_account = seen.account.clone();
        seen_account.data = shard
            .to_bytes()
            .try_into()
            .expect("seen shard fits in account data");
        let seen_post = AccountPostState::new_claimed_if_default(
            seen_account,
            Claim::Pda(inbox_seen_shard_seed(&msg.src_zone, msg.src_block_id)),
        );

        // The payload carries the target instruction as risc0 words, little-endian.
        assert!(
            msg.payload.len().is_multiple_of(4),
            "payload must be u32-aligned instruction words"
        );
        let instruction_data = msg
            .payload
            .chunks_exact(4)
            .map(|c| u32::from_le_bytes(c.try_into().unwrap_or_else(|_| unreachable!())))
            .collect();

        let call = ChainedCall {
            program_id: msg.target_program_id,
            pre_states: target_accounts.clone(),
            instruction_data,
            pda_seeds: vec![],
        };
        (seen_post, vec![call])
    };

    let mut post_states = vec![unchanged(&config), seen_post];
    post_states.extend(target_accounts.iter().map(unchanged));

    let mut output_pre_states = vec![config, seen];
    output_pre_states.extend(target_accounts);

    ProgramOutput::new(
        self_program_id,
        caller_program_id,
        instruction_words,
        output_pre_states,
        post_states,
    )
    .with_chained_calls(chained_calls)
    .write();
}

/// Writes the inbox config (peer + target allowlists) into the config PDA exactly
/// once at genesis.
fn init_config(
    self_program_id: ProgramId,
    caller_program_id: Option<ProgramId>,
    pre_states: Vec<AccountWithMetadata>,
    instruction_words: Vec<u32>,
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
    // Init-once, idempotent under genesis replay: a `default` config is a first
    // init; an already-owned config must already hold exactly these allowlists (the
    // genesis block is replayed onto seeded state during multi-sequencer
    // reconstruction), otherwise reject a post-genesis attempt to change them.
    // `new_claimed_if_default` alone would not stop the owning program from
    // rewriting its own config data on a later call.
    if config_meta.account != Account::default() {
        assert_eq!(
            config_meta.account.program_owner, self_program_id,
            "inbox config PDA is owned by another program"
        );
        assert_eq!(
            config_meta.account.data.clone().into_inner(),
            config.to_bytes(),
            "inbox config already initialized with different allowlists"
        );
    }

    let mut config_account = config_meta.account.clone();
    config_account.data = config
        .to_bytes()
        .try_into()
        .expect("inbox config fits in account data");
    let config_post =
        AccountPostState::new_claimed_if_default(config_account, Claim::Pda(inbox_config_seed()));

    ProgramOutput::new(
        self_program_id,
        caller_program_id,
        instruction_words,
        vec![config_meta],
        vec![config_post],
    )
    .write();
}
