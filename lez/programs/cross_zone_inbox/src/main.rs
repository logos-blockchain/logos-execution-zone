use std::convert::Infallible;

use cross_zone_inbox_core::{
    CrossZoneMessage, InboxConfig, Instruction, SeenShard, inbox_config_account_id,
    inbox_config_seed, inbox_seen_shard_account_id, inbox_seen_shard_seed,
    inbox_source_marker_account_id,
};
use lee_core::{
    account::{Account, AccountDiff, AccountWithMetadata, BalanceDiff, Data},
    program::{
        AccountDiffOutput, ChainedCall, Claim, ProgramCall, ProgramId, ProgramInput,
        ProgramOutput, read_lee_call, write_update_from_diff_output,
    },
};

fn update_from_diff(_pre_state: Account, diff_data: Vec<u8>) -> Result<Data, Infallible> {
    Ok(diff_data
        .try_into()
        .expect("diff_data was already validated to fit under DATA_MAX_LENGTH when constructed"))
}

fn unchanged(pre: &AccountWithMetadata) -> AccountDiffOutput {
    AccountDiffOutput::new(AccountDiff {
        id: pre.account_id,
        diff_balance: BalanceDiff::Add(0),
        diff_data: None,
    })
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
    ) = match read_lee_call::<Instruction>() {
        ProgramCall::Execute(input, instruction_words) => (input, instruction_words),
        ProgramCall::UpdateFromDiff {
            pre_state,
            diff_data,
        } => {
            let data = update_from_diff(pre_state.clone(), diff_data.clone())
                .expect("update_from_diff should not fail");
            write_update_from_diff_output(&pre_state, &diff_data, &data);
            return;
        }
    };

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

    let cfg = InboxConfig::from_bytes(&config.account.data.clone().into_inner())
        .expect("inbox config decodes");

    assert!(
        msg.src_zone != cfg.self_zone,
        "Source zone must not be this zone"
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
        let seen_post = AccountDiffOutput::new_claimed_if_default(
            AccountDiff {
                id: seen.account_id,
                diff_balance: BalanceDiff::Add(0),
                diff_data: Some(shard.to_bytes()),
            },
            seen.account.program_owner,
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

        // The marker leads, so a target reads its source at a fixed position
        // without knowing anything about the accounts that follow it.
        let mut call_pre_states = vec![marker.clone()];
        call_pre_states.extend(target_accounts.clone());
        let call = ChainedCall {
            program_id: msg.target_program_id,
            pre_states: call_pre_states,
            instruction_data,
            pda_seeds: vec![],
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
        instruction_words,
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
    // init; an already-owned config must already hold exactly this, since genesis
    // is replayed onto seeded state during multi-sequencer reconstruction.
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
            "inbox config already initialized differently"
        );
    }

    let config_post = AccountDiffOutput::new_claimed_if_default(
        AccountDiff {
            id: config_meta.account_id,
            diff_balance: BalanceDiff::Add(0),
            diff_data: Some(config.to_bytes()),
        },
        config_meta.account.program_owner,
        Claim::Pda(inbox_config_seed()),
    );

    ProgramOutput::new(
        self_program_id,
        caller_program_id,
        instruction_words,
        vec![config_meta],
        vec![config_post],
    )
    .write();
}
