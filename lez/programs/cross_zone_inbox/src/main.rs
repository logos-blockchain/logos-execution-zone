use cross_zone_inbox_core::{
    InboxConfig, Instruction, SeenShard, inbox_config_account_id, inbox_seen_shard_account_id,
    inbox_seen_shard_seed, message_key,
};
use lee_core::{
    account::AccountWithMetadata,
    program::{AccountPostState, ChainedCall, Claim, ProgramInput, ProgramOutput, read_lee_inputs},
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

    let Instruction::Dispatch(msg) = instruction;

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
    let allowed_targets = cfg
        .allowed_targets
        .get(&msg.src_zone)
        .expect("Source zone is not an allowed peer");
    assert!(
        allowed_targets.contains(&msg.target_program_id),
        "Target program is not allowed for this peer"
    );

    let key = message_key(&msg.src_zone, msg.src_block_id, msg.src_tx_index);
    let mut shard =
        SeenShard::from_bytes(&seen.account.data.clone().into_inner()).expect("seen shard decodes");
    let already_seen = shard.contains(&key);

    // On replay this is a no-op: the seen shard is untouched and no call is made.
    let (seen_post, chained_calls) = if already_seen {
        (unchanged(&seen), vec![])
    } else {
        shard.insert(key);
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
