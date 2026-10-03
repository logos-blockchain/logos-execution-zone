use std::collections::btree_map::Entry;

use lee_core::{
    BlockId,
    account::{AccountId, Actor},
    native_token::{self, custody_transfer},
    program::{BlockValidityWindow, Call, ReceiveInput, Response, SendMode, run_actor},
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
        Message::FinalizeUnstake { sequencer_key } => finalize_unstake(input, sequencer_key),
        Message::Slash {
            sequencer_key,
            inscription,
            approvals,
        } => slash(input, sequencer_key, inscription, &approvals),
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
            destination,
            requested_at,
        } => track_unstake_request(
            input,
            sequencer_key,
            ownership,
            PendingUnstake {
                amount,
                destination,
                requested_at,
            },
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
    assert_root_origin(
        input,
        "Stake is only invoked as a top-level user transaction",
    );
    assert!(input.is_authorized, "must sign for the ownership account");
    // The stake actor state remains after a full exit, so presence is what distinguishes a
    // new stake from a top-up.
    assert_eq!(
        !input.pre_state.is_empty(),
        has_record,
        "stake claims an ownership record this account does not match"
    );
    if has_record {
        let record = decode_record(&input.pre_state);
        assert_eq!(
            record.sequencer_key, sequencer_key,
            "ownership account backs a different sequencer key"
        );
    }

    let program = input.receiver.program_account_id;
    let ownership = input.receiver.account_id;
    Response::set_state(StakeRecord { sequencer_key }.to_bytes())
        .send(to_config(
            program,
            &Message::RecordStake {
                sequencer_key,
                ownership,
                amount,
                has_record,
            },
        ))
        .call(
            Actor::native_balance(funding),
            &native_token::Message::Transfer {
                to: stake_funds_account_id(program, &ownership),
                amount,
                mode: SendMode::Call,
            },
        )
}

fn unstake_request(
    input: &ReceiveInput,
    sequencer_key: SequencerKey,
    amount: u128,
    destination: AccountId,
    requested_at: BlockId,
) -> Response {
    assert_root_origin(
        input,
        "UnstakeRequest is only invoked as a top-level user transaction",
    );
    assert!(input.is_authorized, "must sign for the ownership account");
    let record = decode_record(&input.pre_state);
    assert_eq!(
        record.sequencer_key, sequencer_key,
        "ownership account backs a different sequencer key"
    );

    // The config holds the request; the transfer happens in FinalizeUnstake.
    Response::keep_state()
        .block_window(request_window(requested_at))
        .send(to_config(
            input.receiver.program_account_id,
            &Message::TrackUnstakeRequest {
                sequencer_key,
                ownership: input.receiver.account_id,
                amount,
                destination,
                requested_at,
            },
        ))
}

/// Unsigned, so the release is sized and addressed only by the config's pending request, and cast
/// to the destination, which receives it in a later transaction.
fn finalize_unstake(input: &ReceiveInput, sequencer_key: SequencerKey) -> Response {
    assert_root_origin(
        input,
        "FinalizeUnstake is only invoked as a top-level user transaction",
    );
    assert_config_account(input);
    let mut config = decode_config(&input.pre_state);
    let exit_delay = channel_params(&config).exit_delay;
    let entry = config
        .entries
        .get_mut(&sequencer_key)
        .expect("staked key must already have a config entry");
    let pending = entry
        .pending_unstake
        .take()
        .expect("no unstake request pending for this key");
    entry.total_staked = entry
        .total_staked
        .checked_sub(pending.amount)
        .expect("total staked underflow");
    let ownership = entry.account_id;
    if entry.total_staked == 0 {
        config.entries.remove(&sequencer_key);
    }

    let program = input.receiver.program_account_id;
    Response::set_state(config.to_bytes())
        .block_window(pending.releasable_at(exit_delay)..)
        .send(custody_transfer(
            stake_funds_account_id(program, &ownership),
            stake_funds_seed(&ownership),
            pending.destination,
            pending.amount,
            SendMode::Cast,
        ))
}

fn slash(
    input: &ReceiveInput,
    sequencer_key: SequencerKey,
    inscription: [u8; 32],
    approvals: &[SlashApproval],
) -> Response {
    assert_root_origin(
        input,
        "Slash is only invoked as a top-level user transaction",
    );
    assert_config_account(input);
    let mut config = decode_config(&input.pre_state);
    // The approvals are the whole authorization, and accreditation is this config's
    // own answer.
    verify_approvals(&config, sequencer_key, inscription, approvals);
    // The whole tracked stake burns, including any pending unstake.
    let entry = config
        .entries
        .remove(&sequencer_key)
        .expect("slashed key must have a config entry");

    let program = input.receiver.program_account_id;
    Response::set_state(config.to_bytes()).send(custody_transfer(
        stake_funds_account_id(program, &entry.account_id),
        stake_funds_seed(&entry.account_id),
        slash_sink_account_id(program),
        entry.total_staked,
        SendMode::Call,
    ))
}

fn init_channel_params(
    input: &ReceiveInput,
    params: ChannelParams,
    channel_id: [u8; 32],
) -> Response {
    assert_root_origin(
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

    let mut config = decode_config(&input.pre_state);
    assert!(
        config.channel_params.is_none(),
        "channel params are already set and cannot be changed"
    );
    config.channel_params = Some(params);
    config.channel_id = Some(channel_id);
    Response::set_state(config.to_bytes())
}

fn record_stake(
    input: &ReceiveInput,
    sequencer_key: SequencerKey,
    ownership: AccountId,
    amount: u128,
    has_record: bool,
) -> Response {
    assert_bookkeeping(input);
    let mut config = decode_config(&input.pre_state);
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
            assert!(
                entry.pending_unstake.is_none(),
                "cannot top up while an unstake request is pending"
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
                pending_unstake: None,
            });
        }
    }
    Response::set_state(config.to_bytes())
}

fn track_unstake_request(
    input: &ReceiveInput,
    sequencer_key: SequencerKey,
    ownership: AccountId,
    pending: PendingUnstake,
) -> Response {
    assert_bookkeeping(input);
    let mut config = decode_config(&input.pre_state);
    let minimum_sequencer_stake = channel_params(&config).minimum_sequencer_stake;
    let entry = entry_of(&mut config, sequencer_key, ownership);
    assert!(
        entry.pending_unstake.is_none(),
        "an unstake request is already pending"
    );
    // Sized against the tracked stake, never the account balance: anyone can
    // credit any account, so balance can exceed `total_staked`.
    assert!(
        entry.allows_unstake_request(pending.amount, minimum_sequencer_stake),
        "unstake request must be covered by the staked total and leave the key at zero or at/above the minimum"
    );
    entry.pending_unstake = Some(pending);
    Response::set_state(config.to_bytes())
}

fn assert_root_origin(input: &ReceiveInput, message: &str) {
    assert!(input.origin.is_none(), "{message}");
}

/// Other accounts also hold this program's actor states, so the config is pinned by address.
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

fn to_config(program: AccountId, message: &Message) -> Call {
    Call::new(
        Actor::new(sequencer_stake_config_account_id(program), program),
        message,
    )
}

fn decode_config(pre_state: &[u8]) -> SequencerStakeConfig {
    SequencerStakeConfig::from_bytes(pre_state)
        .expect("config account data should decode as SequencerStakeConfig")
}

fn decode_record(pre_state: &[u8]) -> StakeRecord {
    StakeRecord::from_bytes(pre_state).expect("ownership account should decode as StakeRecord")
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

    use lee_core::{account::ActorState, program::Transition};
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

    fn entry(account_id: AccountId, total_staked: u128, pending: u128) -> SequencerEntry {
        SequencerEntry {
            account_id,
            total_staked,
            pending_unstake: (pending > 0).then_some(PendingUnstake {
                amount: pending,
                destination: DESTINATION,
                requested_at: REQUESTED_AT,
            }),
        }
    }

    fn record(sequencer_key: SequencerKey) -> Vec<u8> {
        StakeRecord { sequencer_key }.to_bytes()
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
        origin: Option<AccountId>,
        pre_state: &[u8],
        message: &Message,
    ) -> ReceiveInput {
        ReceiveInput {
            receiver: Actor::new(account, program),
            origin,
            is_authorized,
            pre_state: ActorState::from(pre_state.to_vec()),
            message: borsh::to_vec(message).unwrap(),
        }
    }

    fn run(
        account: AccountId,
        is_authorized: bool,
        origin: Option<AccountId>,
        pre_state: &[u8],
        message: Message,
    ) -> Transition {
        let input = input(account, PROGRAM, is_authorized, origin, pre_state, &message);
        receive(&input, message).into_transition(input)
    }

    fn at_owner(is_authorized: bool, pre_state: &[u8], message: Message) -> Transition {
        run(OWNER, is_authorized, None, pre_state, message)
    }

    fn at_config(origin: Option<AccountId>, pre_state: &[u8], message: Message) -> Transition {
        run(
            sequencer_stake_config_account_id(PROGRAM),
            false,
            origin,
            pre_state,
            message,
        )
    }

    fn written(transition: &Transition) -> Vec<u8> {
        transition
            .response
            .post_state
            .as_ref()
            .expect("the actor state is written")
            .to_vec()
    }

    fn decoded_config(transition: &Transition) -> SequencerStakeConfig {
        SequencerStakeConfig::from_bytes(&written(transition)).expect("the config decodes")
    }

    fn finalize(sequencer_key: SequencerKey) -> Message {
        Message::FinalizeUnstake { sequencer_key }
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

    fn track(ownership: AccountId, amount: u128) -> Message {
        Message::TrackUnstakeRequest {
            sequencer_key: key(1),
            ownership,
            amount,
            destination: DESTINATION,
            requested_at: REQUESTED_AT,
        }
    }

    fn slash(approvals: Vec<SlashApproval>) -> Message {
        Message::Slash {
            sequencer_key: key(1),
            inscription: INSCRIPTION,
            approvals,
        }
    }

    fn funds_of(ownership: AccountId) -> AccountId {
        stake_funds_account_id(PROGRAM, &ownership)
    }

    // --- FinalizeUnstake ---

    #[test]
    fn a_release_matching_the_pending_request_consumes_it() {
        let transition = at_config(
            None,
            &config_with(&[(key(1), entry(OWNER, 3_000, 500))]),
            finalize(key(1)),
        );

        assert_eq!(
            decoded_config(&transition).entries.get(&key(1)).copied(),
            Some(entry(OWNER, 2_500, 0))
        );
        assert_eq!(
            transition.response.block_validity_window.start(),
            Some(REQUESTED_AT + EXIT_DELAY)
        );
        assert_eq!(transition.response.block_validity_window.end(), None);
        assert_eq!(
            (transition.response.calls, transition.response.casts),
            (
                vec![custody_transfer(
                    funds_of(OWNER),
                    stake_funds_seed(&OWNER),
                    DESTINATION,
                    500,
                    SendMode::Cast,
                )],
                Vec::new()
            )
        );
    }

    #[test]
    #[should_panic(expected = "no unstake request pending for this key")]
    fn a_release_with_no_request_behind_it_is_refused() {
        // FinalizeUnstake carries no signature, so without this any caller drains the funds
        // account of an account that never asked to unstake.
        let _transition = at_config(
            None,
            &config_with(&[(key(1), entry(OWNER, 3_000, 0))]),
            finalize(key(1)),
        );
    }

    #[test]
    fn settling_a_release_drops_a_fully_drained_entry() {
        let transition = at_config(
            None,
            &config_with(&[(key(1), entry(OWNER, 3_000, 3_000))]),
            finalize(key(1)),
        );
        assert!(decoded_config(&transition).entries.is_empty());
    }

    #[test]
    fn settling_a_partial_release_leaves_the_rest_staked() {
        let transition = at_config(
            None,
            &config_with(&[(key(1), entry(OWNER, 3_000, 1_000))]),
            finalize(key(1)),
        );
        assert_eq!(
            decoded_config(&transition).entries.get(&key(1)).copied(),
            Some(entry(OWNER, 2_000, 0))
        );
    }

    #[test]
    #[should_panic(expected = "not the sequencer_stake config account")]
    fn a_finalize_away_from_the_config_account_is_refused() {
        let _transition = at_owner(false, &record(key(1)), finalize(key(1)));
    }

    // --- UnstakeRequest ---

    #[test]
    fn a_request_records_the_amount_and_destination() {
        let transition = at_owner(true, &record(key(1)), request(key(1), 500));

        assert!(transition.response.post_state.is_none());
        assert_eq!(transition.response.block_validity_window.start(), Some(0));
        assert_eq!(
            transition.response.block_validity_window.end(),
            Some(REQUESTED_AT + 1)
        );
        assert_eq!(
            (transition.response.calls, transition.response.casts),
            (vec![to_config(PROGRAM, &track(OWNER, 500))], Vec::new())
        );
    }

    #[test]
    #[should_panic(expected = "must sign for the ownership account")]
    fn an_unsigned_unstake_request_is_refused() {
        let _transition = at_owner(false, &record(key(1)), request(key(1), 500));
    }

    #[test]
    #[should_panic(expected = "ownership account backs a different sequencer key")]
    fn a_request_cannot_name_a_key_this_account_does_not_back() {
        // The record and the config both read the proposed key; unchecked, it would point the
        // config's bookkeeping at a victim's entry.
        let _transition = at_owner(true, &record(key(1)), request(key(2), 500));
    }

    #[test]
    #[should_panic(expected = "an unstake request is already pending")]
    fn a_second_request_is_refused() {
        let _transition = at_config(
            Some(PROGRAM),
            &config_with(&[(key(1), entry(OWNER, 3_000, 100))]),
            track(OWNER, 500),
        );
    }

    #[test]
    #[should_panic(expected = "unstake request must be covered by the staked total")]
    fn a_request_beyond_the_tracked_stake_is_refused() {
        let _transition = at_config(
            Some(PROGRAM),
            &config_with(&[(key(1), entry(OWNER, 3_000, 0))]),
            track(OWNER, 3_001),
        );
    }

    #[test]
    #[should_panic(expected = "config entry points at a different ownership account")]
    fn a_request_cannot_be_tracked_against_another_accounts_entry() {
        let _transition = at_config(
            Some(PROGRAM),
            &config_with(&[(key(1), entry(OWNER, 3_000, 0))]),
            track(ATTACKER, 500),
        );
    }

    // --- Stake ---

    #[test]
    fn a_stake_opens_the_record_and_funds_the_stake() {
        let transition = at_owner(true, &[], stake(false));

        assert_eq!(written(&transition), record(key(1)));
        assert_eq!(
            (transition.response.calls, transition.response.casts),
            (
                vec![
                    to_config(PROGRAM, &record_stake(OWNER, MINIMUM, false)),
                    Call::new(
                        Actor::native_balance(FUNDING),
                        &native_token::Message::Transfer {
                            to: funds_of(OWNER),
                            amount: MINIMUM,
                            mode: SendMode::Call
                        },
                    ),
                ],
                Vec::new()
            )
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
        let _transition = run(OWNER, true, Some(OTHER_PROGRAM), &[], stake(false));
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
        let _transition = at_owner(true, &record(key(1)), stake(false));
    }

    #[test]
    #[should_panic(expected = "cannot top up while an unstake request is pending")]
    fn a_top_up_during_a_pending_release_is_refused() {
        let _transition = at_config(
            Some(PROGRAM),
            &config_with(&[(key(1), entry(OWNER, 3_000, 500))]),
            record_stake(OWNER, MINIMUM, true),
        );
    }

    #[test]
    #[should_panic(expected = "a stake or top-up must add at least the minimum")]
    fn a_first_stake_below_the_minimum_is_refused() {
        let _transition = at_config(
            Some(PROGRAM),
            &config_with(&[]),
            record_stake(OWNER, MINIMUM - 1, false),
        );
    }

    #[test]
    #[should_panic(expected = "config entry points at a different ownership account")]
    fn another_account_cannot_top_up_an_existing_key() {
        let _transition = at_config(
            Some(PROGRAM),
            &config_with(&[(key(1), entry(OWNER, 3_000, 0))]),
            record_stake(ATTACKER, MINIMUM, true),
        );
    }

    #[test]
    #[should_panic(expected = "this sequencer key already has an ownership account")]
    fn a_first_stake_cannot_take_over_a_key_already_staked() {
        let _transition = at_config(
            Some(PROGRAM),
            &config_with(&[(key(1), entry(OWNER, 3_000, 0))]),
            record_stake(OTHER_OWNER, MINIMUM, false),
        );
    }

    // --- Slash ---

    #[test]
    fn an_approved_slash_removes_the_entry() {
        let transition = at_config(
            None,
            &config_with(&[
                (key(1), entry(OWNER, 3_000, 500)),
                (key(2), entry(OTHER_OWNER, 3_000, 0)),
                (key(3), entry(OTHER_OWNER, 3_000, 0)),
            ]),
            slash(vec![approval(2, key(1)), approval(3, key(1))]),
        );

        assert!(!decoded_config(&transition).entries.contains_key(&key(1)));
        assert_eq!(
            (transition.response.calls, transition.response.casts),
            (
                vec![custody_transfer(
                    funds_of(OWNER),
                    stake_funds_seed(&OWNER),
                    slash_sink_account_id(PROGRAM),
                    3_000,
                    SendMode::Call
                )],
                Vec::new()
            )
        );
    }

    #[test]
    #[should_panic(expected = "approval from a key this config does not accredit")]
    fn a_slash_approved_by_an_unaccredited_key_is_refused() {
        // Accreditation is the entire authorization for a slash, and only the real config
        // knows it.
        let _transition = at_config(
            None,
            &config_with(&[(key(1), entry(OWNER, 3_000, 0))]),
            slash(vec![approval(9, key(1))]),
        );
    }

    #[test]
    #[should_panic(expected = "slash carries fewer approvals than the threshold")]
    fn a_slash_approved_by_a_single_key_is_refused() {
        let _transition = at_config(
            None,
            &committee_of_three(),
            slash(vec![approval(2, key(1))]),
        );
    }

    #[test]
    #[should_panic(expected = "the same key approved twice")]
    fn a_slash_approved_twice_by_one_key_is_refused() {
        let _transition = at_config(
            None,
            &committee_of_three(),
            slash(vec![approval(2, key(1)), approval(2, key(1))]),
        );
    }

    #[test]
    #[should_panic(expected = "not the sequencer_stake config account")]
    fn a_slash_away_from_the_config_account_is_refused() {
        let _transition = at_owner(
            false,
            &record(key(1)),
            slash(vec![approval(2, key(1)), approval(3, key(1))]),
        );
    }

    // --- InitChannelParams ---

    #[test]
    #[should_panic(expected = "channel params are already set")]
    fn channel_params_cannot_be_set_twice() {
        let _transition = at_config(
            None,
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
        let _transition = at_config(None, &config_with(&[]), record_stake(OWNER, MINIMUM, false));
    }

    #[test]
    #[should_panic(
        expected = "stake bookkeeping is only sent by this program's ownership accounts"
    )]
    fn bookkeeping_from_another_program_is_refused() {
        let _transition = at_config(
            Some(OTHER_PROGRAM),
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
            Some(PROGRAM),
            &config_with(&[]),
            record_stake(OWNER, MINIMUM, false),
        );
    }
}
