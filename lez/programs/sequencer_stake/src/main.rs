use std::collections::btree_map::Entry;

use lee_core::{
    BlockId,
    account::{AccountId, Actor},
    native_token::{self, custody_transfer},
    program::{BlockValidityWindow, Envelope, Origin, ReceiveInput, Response, run_actor},
};
use sequencer_stake_core::{
    ChannelParams, Message, PendingUnstake, SequencerEntry, SequencerKey, SequencerStakeConfig,
    SlashApproval, StakeRecord, UNSTAKE_REQUEST_WINDOW,
    ed25519_dalek::{Signature, VerifyingKey},
    sequencer_stake_config_account_id, slash_approval_message, slash_approval_threshold,
    slash_sink_account_id, stake_funds_account_id, stake_funds_seed,
};

fn main() {
    run_actor(receive)
}

fn receive(input: &ReceiveInput, message: Message) -> Response {
    match message {
        Message::Stake {
            sequencer_key,
            amount,
            has_record,
            funding,
        } => stake(input, sequencer_key, amount, has_record, funding),
        Message::UnstakeRequest {
            sequencer_key,
            amount,
            destination,
            requested_at,
        } => unstake_request(input, sequencer_key, amount, destination, requested_at),
        Message::FinalizeUnstake {
            sequencer_key,
            amount,
            requested_at,
            exit_delay,
            destination,
        } => finalize_unstake(
            input,
            sequencer_key,
            amount,
            requested_at,
            exit_delay,
            destination,
        ),
        Message::Slash {
            sequencer_key,
            inscription,
            approvals,
            total_staked,
        } => slash(input, sequencer_key, inscription, approvals, total_staked),
        Message::InitChannelParams { params, channel_id } => {
            init_channel_params(input, params, channel_id)
        }
        Message::RecordStake {
            sequencer_key,
            ownership,
            amount,
            has_record,
        } => record_stake(input, sequencer_key, ownership, amount, has_record),
        Message::TrackUnstakeRequest {
            sequencer_key,
            ownership,
            amount,
        } => track_unstake_request(input, sequencer_key, ownership, amount),
        Message::SettleUnstake {
            sequencer_key,
            ownership,
            amount,
            exit_delay,
        } => settle_unstake(input, sequencer_key, ownership, amount, exit_delay),
        Message::ApplySlash {
            sequencer_key,
            ownership,
            inscription,
            approvals,
            total_staked,
        } => apply_slash(
            input,
            sequencer_key,
            ownership,
            inscription,
            &approvals,
            total_staked,
        ),
    }
}

fn stake(
    input: &ReceiveInput,
    sequencer_key: SequencerKey,
    amount: u128,
    has_record: bool,
    funding: AccountId,
) -> Response {
    assert_root(
        input,
        "Stake is only invoked as a top-level user transaction",
    );
    assert!(input.is_authorized, "must sign for the ownership account");
    // The stake shard remains after a full exit, so presence is what distinguishes a
    // new stake from a top-up.
    assert_eq!(
        !input.pre_data.is_empty(),
        has_record,
        "stake claims an ownership record this account does not match"
    );
    if has_record {
        let record = decode_record(&input.pre_data);
        assert_eq!(
            record.sequencer_key, sequencer_key,
            "ownership account backs a different sequencer key"
        );
        assert!(
            record.pending_unstake.is_none(),
            "cannot top up while an unstake request is pending"
        );
    }

    let program = input.receiver.program_account_id;
    let ownership = input.receiver.account_id;
    Response::write(
        StakeRecord {
            sequencer_key,
            pending_unstake: None,
        }
        .to_bytes(),
    )
    .send(to_config(
        program,
        &Message::RecordStake {
            sequencer_key,
            ownership,
            amount,
            has_record,
        },
    ))
    .send(Envelope::new(
        Actor::native_balance(funding),
        &native_token::Message::Transfer {
            to: stake_funds_account_id(program, &ownership),
            amount,
            expect_balance: None,
        },
    ))
}

fn unstake_request(
    input: &ReceiveInput,
    sequencer_key: SequencerKey,
    amount: u128,
    destination: AccountId,
    requested_at: BlockId,
) -> Response {
    assert_root(
        input,
        "UnstakeRequest is only invoked as a top-level user transaction",
    );
    assert!(input.is_authorized, "must sign for the ownership account");
    let mut record = decode_record(&input.pre_data);
    assert_eq!(
        record.sequencer_key, sequencer_key,
        "ownership account backs a different sequencer key"
    );
    assert!(
        record.pending_unstake.is_none(),
        "an unstake request is already pending"
    );
    record.pending_unstake = Some(PendingUnstake {
        amount,
        destination,
        requested_at,
    });

    // Only data changes here; the transfer happens in FinalizeUnstake.
    Response::write(record.to_bytes())
        .block_window(request_window(requested_at))
        .send(to_config(
            input.receiver.program_account_id,
            &Message::TrackUnstakeRequest {
                sequencer_key,
                ownership: input.receiver.account_id,
                amount,
            },
        ))
}

/// `FinalizeUnstake` carries no signature, so the ownership record is the only thing that says
/// this release was ever requested, for this amount, to this destination.
fn finalize_unstake(
    input: &ReceiveInput,
    sequencer_key: SequencerKey,
    amount: u128,
    requested_at: BlockId,
    exit_delay: u64,
    destination: AccountId,
) -> Response {
    assert_root(
        input,
        "FinalizeUnstake is only invoked as a top-level user transaction",
    );
    // No signature check: already authorized back in UnstakeRequest. That is exactly why the
    // release below may only be sized and addressed by what the record turns out to hold.
    let mut record = decode_record(&input.pre_data);
    assert_eq!(
        record.sequencer_key, sequencer_key,
        "ownership account backs a different sequencer key"
    );
    let pending = record
        .pending_unstake
        .take()
        .expect("no unstake request pending on this account");
    assert_eq!(
        pending.amount, amount,
        "amount does not match the recorded unstake request"
    );
    assert_eq!(
        pending.destination, destination,
        "destination does not match the recorded unstake request"
    );
    assert_eq!(
        pending.requested_at, requested_at,
        "request date does not match the recorded unstake request"
    );

    let program = input.receiver.program_account_id;
    let ownership = input.receiver.account_id;
    Response::write(record.to_bytes())
        .block_window(requested_at.saturating_add(exit_delay)..)
        .send(to_config(
            program,
            &Message::SettleUnstake {
                sequencer_key,
                ownership,
                amount,
                exit_delay,
            },
        ))
        .send(custody_transfer(
            stake_funds_account_id(program, &ownership),
            stake_funds_seed(&ownership),
            destination,
            amount,
        ))
}

fn slash(
    input: &ReceiveInput,
    sequencer_key: SequencerKey,
    inscription: [u8; 32],
    approvals: Vec<SlashApproval>,
    total_staked: u128,
) -> Response {
    assert_root(
        input,
        "Slash is only invoked as a top-level user transaction",
    );
    let mut record = decode_record(&input.pre_data);
    assert_eq!(
        record.sequencer_key, sequencer_key,
        "ownership account backs a different sequencer key"
    );
    // The whole tracked stake burns, including any pending unstake.
    record.pending_unstake = None;

    let program = input.receiver.program_account_id;
    let ownership = input.receiver.account_id;
    Response::write(record.to_bytes())
        .send(to_config(
            program,
            &Message::ApplySlash {
                sequencer_key,
                ownership,
                inscription,
                approvals,
                total_staked,
            },
        ))
        .send(custody_transfer(
            stake_funds_account_id(program, &ownership),
            stake_funds_seed(&ownership),
            slash_sink_account_id(program),
            total_staked,
        ))
}

fn init_channel_params(
    input: &ReceiveInput,
    params: ChannelParams,
    channel_id: [u8; 32],
) -> Response {
    assert_root(
        input,
        "InitChannelParams is only invoked as a top-level user transaction",
    );
    assert_config_account(input);

    // A zero timeframe would leave round robin unable to move off index 0, and
    // a zero minimum would accredit every key that ever staked a nonzero amount.
    assert!(
        params.posting_timeframe > 0,
        "posting_timeframe must be non-zero"
    );
    // A timeout above the timeframe never fires: the turn ends first.
    assert!(
        params.posting_timeout > 0 && params.posting_timeout <= params.posting_timeframe,
        "posting_timeout must be non-zero and no longer than posting_timeframe"
    );
    assert!(
        params.minimum_sequencer_stake > 0,
        "minimum_sequencer_stake must be non-zero"
    );
    assert!(params.exit_delay > 0, "exit_delay must be non-zero");

    let mut config = decode_config(&input.pre_data);
    assert!(
        config.channel_params.is_none(),
        "channel params are already set and cannot be changed"
    );
    config.channel_params = Some(params);
    config.channel_id = Some(channel_id);
    Response::write(config.to_bytes())
}

fn record_stake(
    input: &ReceiveInput,
    sequencer_key: SequencerKey,
    ownership: AccountId,
    amount: u128,
    has_record: bool,
) -> Response {
    assert_bookkeeping(input);
    let mut config = decode_config(&input.pre_data);
    assert!(
        amount >= channel_params(&config).minimum_sequencer_stake,
        "a stake or top-up must add at least the minimum"
    );
    match config.entries.entry(sequencer_key) {
        Entry::Occupied(mut occupied) => {
            assert!(
                has_record,
                "this sequencer key already has an ownership account"
            );
            let entry = occupied.get_mut();
            assert_eq!(
                entry.account_id, ownership,
                "config entry points at a different ownership account"
            );
            entry.total_staked = entry
                .total_staked
                .checked_add(amount)
                .expect("total staked overflow");
        }
        Entry::Vacant(vacant) => {
            vacant.insert(SequencerEntry {
                account_id: ownership,
                total_staked: amount,
                total_pending_unstake: 0,
            });
        }
    }
    Response::write(config.to_bytes())
}

fn track_unstake_request(
    input: &ReceiveInput,
    sequencer_key: SequencerKey,
    ownership: AccountId,
    amount: u128,
) -> Response {
    assert_bookkeeping(input);
    let mut config = decode_config(&input.pre_data);
    let minimum_sequencer_stake = channel_params(&config).minimum_sequencer_stake;
    let entry = entry_of(&mut config, sequencer_key, ownership);
    // Sized against the tracked stake, never the account balance: anyone can
    // credit any account, so balance can exceed `total_staked`.
    assert!(
        entry.allows_unstake_request(amount, minimum_sequencer_stake),
        "unstake request must be covered by the staked total and leave the key at zero or at/above the minimum"
    );
    entry.total_pending_unstake = entry
        .total_pending_unstake
        .checked_add(amount)
        .expect("total pending unstake overflow");
    Response::write(config.to_bytes())
}

fn settle_unstake(
    input: &ReceiveInput,
    sequencer_key: SequencerKey,
    ownership: AccountId,
    amount: u128,
    exit_delay: u64,
) -> Response {
    assert_bookkeeping(input);
    let mut config = decode_config(&input.pre_data);
    assert_eq!(
        channel_params(&config).exit_delay,
        exit_delay,
        "exit delay does not match the channel params"
    );
    let entry = entry_of(&mut config, sequencer_key, ownership);
    entry.total_staked = entry
        .total_staked
        .checked_sub(amount)
        .expect("total staked underflow");
    entry.total_pending_unstake = entry
        .total_pending_unstake
        .checked_sub(amount)
        .expect("total pending unstake underflow");
    if entry.total_staked == 0 {
        config.entries.remove(&sequencer_key);
    }
    Response::write(config.to_bytes())
}

fn apply_slash(
    input: &ReceiveInput,
    sequencer_key: SequencerKey,
    ownership: AccountId,
    inscription: [u8; 32],
    approvals: &[SlashApproval],
    total_staked: u128,
) -> Response {
    assert_bookkeeping(input);
    let mut config = decode_config(&input.pre_data);
    // The approvals are the whole authorization, and accreditation is this config's
    // own answer.
    verify_approvals(&config, sequencer_key, inscription, approvals);
    let entry = config
        .entries
        .remove(&sequencer_key)
        .expect("slashed key must have a config entry");
    assert_eq!(
        entry.account_id, ownership,
        "config entry points at a different ownership account"
    );
    assert_eq!(
        entry.total_staked, total_staked,
        "slash must burn exactly the stake this config tracks"
    );
    Response::write(config.to_bytes())
}

fn assert_root(input: &ReceiveInput, message: &str) {
    assert!(matches!(input.origin, Origin::Root), "{message}");
}

/// Other accounts also hold this program's shards, so the config is pinned by address.
fn assert_config_account(input: &ReceiveInput) {
    assert_eq!(
        input.receiver.account_id,
        sequencer_stake_config_account_id(input.receiver.program_account_id),
        "not the sequencer_stake config account"
    );
}

fn assert_bookkeeping(input: &ReceiveInput) {
    assert_config_account(input);
    // This program sends bookkeeping only from an ownership actor, filling `ownership` from
    // that receiver, so the named account is the one whose operation sent it.
    assert!(
        input.from_own_program(),
        "stake bookkeeping is only sent by this program's ownership accounts"
    );
}

fn to_config(program: AccountId, message: &Message) -> Envelope {
    Envelope::new(
        Actor::new(sequencer_stake_config_account_id(program), program),
        message,
    )
}

fn decode_config(pre_data: &[u8]) -> SequencerStakeConfig {
    SequencerStakeConfig::from_bytes(pre_data)
        .expect("config account data should decode as SequencerStakeConfig")
}

fn decode_record(pre_data: &[u8]) -> StakeRecord {
    StakeRecord::from_bytes(pre_data).expect("ownership account should decode as StakeRecord")
}

fn entry_of(
    config: &mut SequencerStakeConfig,
    sequencer_key: SequencerKey,
    ownership_account_id: AccountId,
) -> &mut SequencerEntry {
    let entry = config
        .entries
        .get_mut(&sequencer_key)
        .expect("staked key must already have a config entry");
    assert_eq!(
        entry.account_id, ownership_account_id,
        "config entry points at a different ownership account"
    );
    entry
}

fn verify_approvals(
    config: &SequencerStakeConfig,
    sequencer_key: SequencerKey,
    inscription: [u8; 32],
    approvals: &[SlashApproval],
) {
    let message = slash_approval_message(channel_id(config), sequencer_key, inscription);

    let mut approvers: Vec<SequencerKey> = Vec::with_capacity(approvals.len());
    for approval in approvals {
        assert!(
            config.is_accredited_committee_member(&approval.signer),
            "approval from a key this config does not accredit"
        );
        assert!(
            !approvers.contains(&approval.signer),
            "the same key approved twice"
        );

        let verifying_key = VerifyingKey::from_bytes(&approval.signer.to_bytes())
            .expect("a SequencerKey is a valid Ed25519 public key");
        let signature = Signature::from_slice(&approval.signature)
            .expect("approval signature should be 64 bytes");
        verifying_key
            .verify_strict(&message, &signature)
            .expect("approval signature should verify against its signer");

        approvers.push(approval.signer);
    }

    assert!(
        approvers.len() >= slash_approval_threshold(config.accredited_committee_members_count()),
        "slash carries fewer approvals than the threshold"
    );
}

const fn channel_params(config: &SequencerStakeConfig) -> ChannelParams {
    config
        .channel_params
        .expect("genesis sets the channel params before any stake exists")
}

/// The channel genesis fixed, on the same terms as [`channel_params`].
const fn channel_id(config: &SequencerStakeConfig) -> [u8; 32] {
    config
        .channel_id
        .expect("genesis sets the channel id before any stake exists")
}

/// The blocks an `UnstakeRequest` dated `requested_at` may land in, so the date is never
/// earlier than the block that records it.
fn request_window(requested_at: BlockId) -> BlockValidityWindow {
    (requested_at.saturating_sub(UNSTAKE_REQUEST_WINDOW)..requested_at.saturating_add(1))
        .try_into()
        .expect("a request window is never empty")
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use lee_core::{account::ShardData, program::Transition};
    use sequencer_stake_core::ed25519_dalek::{Signer as _, SigningKey};

    use super::*;

    const PROGRAM: AccountId = AccountId::new([7; 32]);
    const OTHER_PROGRAM: AccountId = AccountId::new([6; 32]);
    const OWNER: AccountId = AccountId::new([1; 32]);
    const OTHER_OWNER: AccountId = AccountId::new([2; 32]);
    const DESTINATION: AccountId = AccountId::new([3; 32]);
    const ATTACKER: AccountId = AccountId::new([4; 32]);
    const FUNDING: AccountId = AccountId::new([5; 32]);
    const INSCRIPTION: [u8; 32] = [8; 32];
    const CHANNEL_ID: [u8; 32] = [9; 32];
    const MINIMUM: u128 = 1_000;
    const EXIT_DELAY: u64 = 10;
    const REQUESTED_AT: u64 = 7;

    fn signing_key(seed: u8) -> SigningKey {
        SigningKey::from_bytes(&[seed; 32])
    }

    fn key(seed: u8) -> SequencerKey {
        SequencerKey::new(signing_key(seed).verifying_key().to_bytes())
            .expect("a derived public key is a curve point")
    }

    fn config_with(entries: &[(SequencerKey, SequencerEntry)]) -> Vec<u8> {
        SequencerStakeConfig {
            channel_params: Some(ChannelParams {
                minimum_sequencer_stake: MINIMUM,
                posting_timeframe: 300,
                posting_timeout: 25,
                exit_delay: EXIT_DELAY,
            }),
            channel_id: Some(CHANNEL_ID),
            entries: entries.iter().copied().collect::<BTreeMap<_, _>>(),
        }
        .to_bytes()
    }

    fn committee_of_three() -> Vec<u8> {
        config_with(&[
            (key(1), entry(OWNER, 3_000, 0)),
            (key(2), entry(OTHER_OWNER, 3_000, 0)),
            (key(3), entry(OTHER_OWNER, 3_000, 0)),
        ])
    }

    fn entry(
        account_id: AccountId,
        total_staked: u128,
        total_pending_unstake: u128,
    ) -> SequencerEntry {
        SequencerEntry {
            account_id,
            total_staked,
            total_pending_unstake,
        }
    }

    fn record(sequencer_key: SequencerKey, pending_unstake: Option<PendingUnstake>) -> Vec<u8> {
        StakeRecord {
            sequencer_key,
            pending_unstake,
        }
        .to_bytes()
    }

    fn pending(amount: u128, destination: AccountId) -> PendingUnstake {
        PendingUnstake {
            amount,
            destination,
            requested_at: REQUESTED_AT,
        }
    }

    fn approval(seed: u8, sequencer_key: SequencerKey) -> SlashApproval {
        let signer = signing_key(seed);
        SlashApproval {
            signer: key(seed),
            signature: signer
                .sign(&slash_approval_message(
                    CHANNEL_ID,
                    sequencer_key,
                    INSCRIPTION,
                ))
                .to_bytes()
                .to_vec(),
        }
    }

    fn input(
        account: AccountId,
        program: AccountId,
        is_authorized: bool,
        origin: Origin,
        pre_data: &[u8],
        message: &Message,
    ) -> ReceiveInput {
        ReceiveInput {
            receiver: Actor::new(account, program),
            origin,
            is_authorized,
            pre_data: ShardData::try_from(pre_data.to_vec()).unwrap(),
            message: borsh::to_vec(message).unwrap(),
        }
    }

    fn run(
        account: AccountId,
        is_authorized: bool,
        origin: Origin,
        pre_data: &[u8],
        message: Message,
    ) -> Transition {
        let input = input(account, PROGRAM, is_authorized, origin, pre_data, &message);
        receive(&input, message).into_transition(input)
    }

    fn at_owner(is_authorized: bool, pre_data: &[u8], message: Message) -> Transition {
        run(OWNER, is_authorized, Origin::Root, pre_data, message)
    }

    fn at_config(origin: Origin, pre_data: &[u8], message: Message) -> Transition {
        run(
            sequencer_stake_config_account_id(PROGRAM),
            false,
            origin,
            pre_data,
            message,
        )
    }

    fn written(transition: &Transition) -> Vec<u8> {
        transition
            .post_data
            .as_ref()
            .expect("the shard is written")
            .to_vec()
    }

    fn decoded_config(transition: &Transition) -> SequencerStakeConfig {
        SequencerStakeConfig::from_bytes(&written(transition)).expect("the config decodes")
    }

    fn finalize(
        sequencer_key: SequencerKey,
        amount: u128,
        destination: AccountId,
        requested_at: u64,
    ) -> Message {
        Message::FinalizeUnstake {
            sequencer_key,
            amount,
            requested_at,
            exit_delay: EXIT_DELAY,
            destination,
        }
    }

    fn request(sequencer_key: SequencerKey, amount: u128) -> Message {
        Message::UnstakeRequest {
            sequencer_key,
            amount,
            destination: DESTINATION,
            requested_at: REQUESTED_AT,
        }
    }

    fn stake(has_record: bool) -> Message {
        Message::Stake {
            sequencer_key: key(1),
            amount: MINIMUM,
            has_record,
            funding: FUNDING,
        }
    }

    fn record_stake(ownership: AccountId, amount: u128, has_record: bool) -> Message {
        Message::RecordStake {
            sequencer_key: key(1),
            ownership,
            amount,
            has_record,
        }
    }

    fn settle(ownership: AccountId, amount: u128, exit_delay: u64) -> Message {
        Message::SettleUnstake {
            sequencer_key: key(1),
            ownership,
            amount,
            exit_delay,
        }
    }

    fn track(ownership: AccountId, amount: u128) -> Message {
        Message::TrackUnstakeRequest {
            sequencer_key: key(1),
            ownership,
            amount,
        }
    }

    fn apply_slash(
        ownership: AccountId,
        approvals: Vec<SlashApproval>,
        total_staked: u128,
    ) -> Message {
        Message::ApplySlash {
            sequencer_key: key(1),
            ownership,
            inscription: INSCRIPTION,
            approvals,
            total_staked,
        }
    }

    fn funds_of(ownership: AccountId) -> AccountId {
        stake_funds_account_id(PROGRAM, &ownership)
    }

    // --- FinalizeUnstake ---

    #[test]
    fn a_release_matching_the_pending_request_consumes_it() {
        let transition = at_owner(
            false,
            &record(key(1), Some(pending(500, DESTINATION))),
            finalize(key(1), 500, DESTINATION, REQUESTED_AT),
        );

        assert_eq!(written(&transition), record(key(1), None));
        assert_eq!(
            transition.block_validity_window.start(),
            Some(REQUESTED_AT + EXIT_DELAY)
        );
        assert_eq!(transition.block_validity_window.end(), None);
        assert_eq!(
            transition.sends,
            vec![
                to_config(PROGRAM, &settle(OWNER, 500, EXIT_DELAY)),
                custody_transfer(funds_of(OWNER), stake_funds_seed(&OWNER), DESTINATION, 500,),
            ]
        );
    }

    #[test]
    #[should_panic(expected = "no unstake request pending on this account")]
    fn a_release_with_no_request_behind_it_is_refused() {
        // FinalizeUnstake carries no signature, so without this any caller drains the funds
        // account of an account that never asked to unstake.
        let _transition = at_owner(
            false,
            &record(key(1), None),
            finalize(key(1), 500, ATTACKER, REQUESTED_AT),
        );
    }

    #[test]
    #[should_panic(expected = "amount does not match the recorded unstake request")]
    fn a_release_larger_than_the_pending_request_is_refused() {
        let _transition = at_owner(
            false,
            &record(key(1), Some(pending(500, DESTINATION))),
            finalize(key(1), 5_000, DESTINATION, REQUESTED_AT),
        );
    }

    #[test]
    #[should_panic(expected = "destination does not match the recorded unstake request")]
    fn a_release_to_another_address_is_refused() {
        // The whole drain: the custody transfer's recipient is this value.
        let _transition = at_owner(
            false,
            &record(key(1), Some(pending(500, DESTINATION))),
            finalize(key(1), 500, ATTACKER, REQUESTED_AT),
        );
    }

    #[test]
    #[should_panic(expected = "ownership account backs a different sequencer key")]
    fn a_release_naming_another_key_is_refused() {
        // The key selects which config entry the release is charged to.
        let _transition = at_owner(
            false,
            &record(key(1), Some(pending(500, DESTINATION))),
            finalize(key(2), 500, DESTINATION, REQUESTED_AT),
        );
    }

    #[test]
    #[should_panic(expected = "request date does not match the recorded unstake request")]
    fn a_release_dated_differently_is_refused() {
        // The date sets the release's earliest block; an earlier one would skip the delay.
        let _transition = at_owner(
            false,
            &record(key(1), Some(pending(500, DESTINATION))),
            finalize(key(1), 500, DESTINATION, REQUESTED_AT - 1),
        );
    }

    #[test]
    fn settling_a_release_drops_a_fully_drained_entry() {
        let transition = at_config(
            Origin::Program(PROGRAM),
            &config_with(&[(key(1), entry(OWNER, 3_000, 3_000))]),
            settle(OWNER, 3_000, EXIT_DELAY),
        );
        assert!(decoded_config(&transition).entries.is_empty());
    }

    #[test]
    fn settling_a_partial_release_leaves_the_rest_staked() {
        let transition = at_config(
            Origin::Program(PROGRAM),
            &config_with(&[(key(1), entry(OWNER, 3_000, 1_000))]),
            settle(OWNER, 1_000, EXIT_DELAY),
        );
        assert_eq!(
            decoded_config(&transition).entries.get(&key(1)).copied(),
            Some(entry(OWNER, 2_000, 0))
        );
    }

    #[test]
    #[should_panic(expected = "config entry points at a different ownership account")]
    fn a_release_cannot_be_charged_to_another_accounts_entry() {
        let _transition = at_config(
            Origin::Program(PROGRAM),
            &config_with(&[(key(1), entry(OWNER, 3_000, 500))]),
            settle(ATTACKER, 500, EXIT_DELAY),
        );
    }

    #[test]
    #[should_panic(expected = "exit delay does not match the channel params")]
    fn a_settlement_claiming_another_exit_delay_is_refused() {
        let _transition = at_config(
            Origin::Program(PROGRAM),
            &config_with(&[(key(1), entry(OWNER, 3_000, 500))]),
            settle(OWNER, 500, EXIT_DELAY - 1),
        );
    }

    // --- UnstakeRequest ---

    #[test]
    fn a_request_records_the_amount_and_destination() {
        let transition = at_owner(true, &record(key(1), None), request(key(1), 500));

        assert_eq!(
            written(&transition),
            record(key(1), Some(pending(500, DESTINATION)))
        );
        assert_eq!(transition.block_validity_window.start(), Some(0));
        assert_eq!(
            transition.block_validity_window.end(),
            Some(REQUESTED_AT + 1)
        );
        assert_eq!(
            transition.sends,
            vec![to_config(PROGRAM, &track(OWNER, 500))]
        );
    }

    #[test]
    #[should_panic(expected = "must sign for the ownership account")]
    fn an_unsigned_unstake_request_is_refused() {
        let _transition = at_owner(false, &record(key(1), None), request(key(1), 500));
    }

    #[test]
    #[should_panic(expected = "ownership account backs a different sequencer key")]
    fn a_request_cannot_name_a_key_this_account_does_not_back() {
        // The record and the config both read the proposed key; unchecked, it would point the
        // config's bookkeeping at a victim's entry.
        let _transition = at_owner(true, &record(key(1), None), request(key(2), 500));
    }

    #[test]
    #[should_panic(expected = "an unstake request is already pending")]
    fn a_second_request_is_refused() {
        let _transition = at_owner(
            true,
            &record(key(1), Some(pending(100, DESTINATION))),
            request(key(1), 500),
        );
    }

    #[test]
    #[should_panic(expected = "unstake request must be covered by the staked total")]
    fn a_request_beyond_the_tracked_stake_is_refused() {
        let _transition = at_config(
            Origin::Program(PROGRAM),
            &config_with(&[(key(1), entry(OWNER, 3_000, 0))]),
            track(OWNER, 3_001),
        );
    }

    #[test]
    #[should_panic(expected = "config entry points at a different ownership account")]
    fn a_request_cannot_be_tracked_against_another_accounts_entry() {
        let _transition = at_config(
            Origin::Program(PROGRAM),
            &config_with(&[(key(1), entry(OWNER, 3_000, 0))]),
            track(ATTACKER, 500),
        );
    }

    // --- Stake ---

    #[test]
    fn a_stake_opens_the_record_and_funds_the_stake() {
        let transition = at_owner(true, &[], stake(false));

        assert_eq!(written(&transition), record(key(1), None));
        assert_eq!(
            transition.sends,
            vec![
                to_config(PROGRAM, &record_stake(OWNER, MINIMUM, false)),
                Envelope::new(
                    Actor::native_balance(FUNDING),
                    &native_token::Message::Transfer {
                        to: funds_of(OWNER),
                        amount: MINIMUM,
                        expect_balance: None,
                    },
                ),
            ]
        );
    }

    #[test]
    #[should_panic(expected = "must sign for the ownership account")]
    fn an_unsigned_stake_is_refused() {
        let _transition = at_owner(false, &[], stake(false));
    }

    #[test]
    #[should_panic(expected = "Stake is only invoked as a top-level user transaction")]
    fn a_stake_from_another_program_is_refused() {
        let _transition = run(
            OWNER,
            true,
            Origin::Program(OTHER_PROGRAM),
            &[],
            stake(false),
        );
    }

    #[test]
    #[should_panic(expected = "stake claims an ownership record this account does not match")]
    fn a_stake_cannot_claim_a_record_an_empty_account_does_not_hold() {
        // `has_record` decides the config-side branch between a top-up and a first stake, and
        // a first stake is the only one the minimum applies to.
        let _transition = at_owner(true, &[], stake(true));
    }

    #[test]
    #[should_panic(expected = "stake claims an ownership record this account does not match")]
    fn a_stake_cannot_deny_a_record_the_account_holds() {
        let _transition = at_owner(true, &record(key(1), None), stake(false));
    }

    #[test]
    #[should_panic(expected = "cannot top up while an unstake request is pending")]
    fn a_top_up_during_a_pending_release_is_refused() {
        let _transition = at_owner(
            true,
            &record(key(1), Some(pending(500, DESTINATION))),
            stake(true),
        );
    }

    #[test]
    #[should_panic(expected = "a stake or top-up must add at least the minimum")]
    fn a_first_stake_below_the_minimum_is_refused() {
        let _transition = at_config(
            Origin::Program(PROGRAM),
            &config_with(&[]),
            record_stake(OWNER, MINIMUM - 1, false),
        );
    }

    #[test]
    #[should_panic(expected = "config entry points at a different ownership account")]
    fn another_account_cannot_top_up_an_existing_key() {
        let _transition = at_config(
            Origin::Program(PROGRAM),
            &config_with(&[(key(1), entry(OWNER, 3_000, 0))]),
            record_stake(ATTACKER, MINIMUM, true),
        );
    }

    #[test]
    #[should_panic(expected = "this sequencer key already has an ownership account")]
    fn a_first_stake_cannot_take_over_a_key_already_staked() {
        let _transition = at_config(
            Origin::Program(PROGRAM),
            &config_with(&[(key(1), entry(OWNER, 3_000, 0))]),
            record_stake(OTHER_OWNER, MINIMUM, false),
        );
    }

    // --- Slash ---

    #[test]
    fn a_slash_clears_the_record_and_burns_the_stake() {
        let approvals = vec![approval(2, key(1)), approval(3, key(1))];
        let transition = at_owner(
            false,
            &record(key(1), Some(pending(500, DESTINATION))),
            Message::Slash {
                sequencer_key: key(1),
                inscription: INSCRIPTION,
                approvals: approvals.clone(),
                total_staked: 3_000,
            },
        );

        assert_eq!(written(&transition), record(key(1), None));
        assert_eq!(
            transition.sends,
            vec![
                to_config(PROGRAM, &apply_slash(OWNER, approvals, 3_000)),
                custody_transfer(
                    funds_of(OWNER),
                    stake_funds_seed(&OWNER),
                    slash_sink_account_id(PROGRAM),
                    3_000,
                ),
            ]
        );
    }

    #[test]
    fn an_approved_slash_removes_the_entry() {
        let transition = at_config(
            Origin::Program(PROGRAM),
            &committee_of_three(),
            apply_slash(OWNER, vec![approval(2, key(1)), approval(3, key(1))], 3_000),
        );
        assert_eq!(decoded_config(&transition).entries.len(), 2);
    }

    #[test]
    #[should_panic(expected = "approval from a key this config does not accredit")]
    fn a_slash_approved_by_an_unaccredited_key_is_refused() {
        // Accreditation is the entire authorization for a slash, and only the real config
        // knows it.
        let _transition = at_config(
            Origin::Program(PROGRAM),
            &config_with(&[(key(1), entry(OWNER, 3_000, 0))]),
            apply_slash(OWNER, vec![approval(9, key(1))], 3_000),
        );
    }

    #[test]
    #[should_panic(expected = "slash carries fewer approvals than the threshold")]
    fn a_slash_approved_by_a_single_key_is_refused() {
        let _transition = at_config(
            Origin::Program(PROGRAM),
            &committee_of_three(),
            apply_slash(OWNER, vec![approval(2, key(1))], 3_000),
        );
    }

    #[test]
    #[should_panic(expected = "the same key approved twice")]
    fn a_slash_approved_twice_by_one_key_is_refused() {
        let _transition = at_config(
            Origin::Program(PROGRAM),
            &committee_of_three(),
            apply_slash(OWNER, vec![approval(2, key(1)), approval(2, key(1))], 3_000),
        );
    }

    #[test]
    #[should_panic(expected = "slash must burn exactly the stake this config tracks")]
    fn a_slash_cannot_burn_more_than_the_tracked_stake() {
        let _transition = at_config(
            Origin::Program(PROGRAM),
            &committee_of_three(),
            apply_slash(
                OWNER,
                vec![approval(2, key(1)), approval(3, key(1))],
                10_000,
            ),
        );
    }

    #[test]
    #[should_panic(expected = "config entry points at a different ownership account")]
    fn a_slash_cannot_be_charged_to_another_accounts_funds() {
        let _transition = at_config(
            Origin::Program(PROGRAM),
            &committee_of_three(),
            apply_slash(
                ATTACKER,
                vec![approval(2, key(1)), approval(3, key(1))],
                3_000,
            ),
        );
    }

    // --- InitChannelParams ---

    #[test]
    #[should_panic(expected = "channel params are already set")]
    fn channel_params_cannot_be_set_twice() {
        let _transition = at_config(
            Origin::Root,
            &config_with(&[]),
            Message::InitChannelParams {
                params: ChannelParams {
                    minimum_sequencer_stake: 1,
                    posting_timeframe: 1,
                    posting_timeout: 1,
                    exit_delay: 1,
                },
                channel_id: CHANNEL_ID,
            },
        );
    }

    // --- Bookkeeping origin ---

    #[test]
    #[should_panic(
        expected = "stake bookkeeping is only sent by this program's ownership accounts"
    )]
    fn bookkeeping_from_the_root_is_refused() {
        let _transition = at_config(
            Origin::Root,
            &config_with(&[]),
            record_stake(OWNER, MINIMUM, false),
        );
    }

    #[test]
    #[should_panic(
        expected = "stake bookkeeping is only sent by this program's ownership accounts"
    )]
    fn bookkeeping_from_another_program_is_refused() {
        let _transition = at_config(
            Origin::Program(OTHER_PROGRAM),
            &config_with(&[]),
            record_stake(OWNER, MINIMUM, false),
        );
    }

    #[test]
    #[should_panic(expected = "not the sequencer_stake config account")]
    fn bookkeeping_at_another_account_is_refused() {
        let _transition = run(
            OWNER,
            false,
            Origin::Program(PROGRAM),
            &config_with(&[]),
            record_stake(OWNER, MINIMUM, false),
        );
    }
}
