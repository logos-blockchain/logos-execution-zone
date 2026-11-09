use std::collections::btree_map::Entry;

use lee_core::{
    account::{AccountId, Actor, Balance},
    native_token::{self, custody_transfer},
    program::{ReceiveInput, Response, SyncMessage},
};
use sequencer_stake_core::{
    ChannelParams, CommitteeApproval, MAX_MAX_BLOCK_SIZE, MIN_MAX_BLOCK_SIZE, MIN_POSTING_TIMEOUT,
    Message, PendingUnstake, SLASH_APPROVAL_DOMAIN, SequencerEntry, SequencerKey,
    SequencerStakeConfig, SlashApproval, StakeRecord, committee_approval_message,
    ed25519_dalek::{Signature, VerifyingKey},
    params_vote_threshold, sequencer_stake_config_account_id, slash_approval_message,
    slash_approval_threshold, slash_sink_account_id, stake_funds_account_id, stake_funds_seed,
};

lee_core::actor_entrypoint!(handle_message);

fn handle_message(input: &ReceiveInput, message: Message) -> Response {
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
        } => unstake_request(input, sequencer_key, amount, destination),
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
        } => track_unstake_request(
            input,
            sequencer_key,
            ownership,
            PendingUnstake {
                amount,
                destination,
            },
        ),
        Message::VerifyApprovals {
            domain,
            payload,
            approvals,
        } => verify_committee_approvals(input, domain, &payload, &approvals),
        Message::VoteChannelParams {
            sequencer_key,
            params,
        } => vote_channel_params(input, sequencer_key, params),
        Message::RecordChannelParamsVote {
            sequencer_key,
            ownership,
            params,
        } => record_channel_params_vote(input, sequencer_key, ownership, params),
    }
}

fn stake(
    input: &ReceiveInput,
    sequencer_key: SequencerKey,
    amount: Balance,
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
        .send_sync(
            Actor::native_balance(funding),
            &native_token::Message::Transfer {
                to: stake_funds_account_id(program, &ownership),
                amount,
            },
        )
}

fn unstake_request(
    input: &ReceiveInput,
    sequencer_key: SequencerKey,
    amount: Balance,
    destination: AccountId,
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
    Response::keep_state().send(to_config(
        input.receiver.program_account_id,
        &Message::TrackUnstakeRequest {
            sequencer_key,
            ownership: input.receiver.account_id,
            amount,
            destination,
        },
    ))
}

/// Unsigned, so the release is sized and addressed only by the config's pending request, and sent
/// asynchronously to the destination.
fn finalize_unstake(input: &ReceiveInput, sequencer_key: SequencerKey) -> Response {
    assert_root_origin(
        input,
        "FinalizeUnstake is only invoked as a top-level user transaction",
    );
    assert_config_account(input);
    let mut config = decode_config(&input.pre_state);
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
        config.remove_key(&sequencer_key);
    }

    let program = input.receiver.program_account_id;
    Response::set_state(config.to_bytes()).send(custody_transfer(
        stake_funds_account_id(program, &ownership),
        stake_funds_seed(&ownership),
        pending.destination,
        pending.amount,
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
        .remove_key(&sequencer_key)
        .expect("slashed key must have a config entry");

    let program = input.receiver.program_account_id;
    Response::set_state(config.to_bytes()).send(custody_transfer(
        stake_funds_account_id(program, &entry.account_id),
        stake_funds_seed(&entry.account_id),
        slash_sink_account_id(program),
        entry.total_staked,
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
    assert_valid_params(&params);

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
    amount: Balance,
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

fn vote_channel_params(
    input: &ReceiveInput,
    sequencer_key: SequencerKey,
    params: ChannelParams,
) -> Response {
    assert_root_origin(
        input,
        "VoteChannelParams is only invoked as a top-level user transaction",
    );
    assert!(input.is_authorized, "must sign for the ownership account");
    let record = decode_record(&input.pre_state);
    assert_eq!(
        record.sequencer_key, sequencer_key,
        "ownership account backs a different sequencer key"
    );
    assert_valid_params(&params);

    Response::keep_state().send(to_config(
        input.receiver.program_account_id,
        &Message::RecordChannelParamsVote {
            sequencer_key,
            ownership: input.receiver.account_id,
            params,
        },
    ))
}

fn record_channel_params_vote(
    input: &ReceiveInput,
    sequencer_key: SequencerKey,
    ownership: AccountId,
    params: ChannelParams,
) -> Response {
    assert_bookkeeping(input);
    let mut config = decode_config(&input.pre_state);
    let params_in_force = channel_params(&config);
    assert!(
        entry_of(&mut config, sequencer_key, ownership)
            .is_accredited(params_in_force.minimum_sequencer_stake),
        "only an accredited key may vote on channel params"
    );
    // Nodes judge full releases at the depth in their own final state, so it never moves.
    assert_eq!(
        params.finality_depth, params_in_force.finality_depth,
        "finality_depth is fixed at genesis"
    );

    if params == params_in_force {
        config.params_votes.remove(&sequencer_key);
        return Response::set_state(config.to_bytes());
    }
    config.params_votes.insert(sequencer_key, params);

    let votes = config
        .params_votes
        .iter()
        .filter(|(voter, voted)| **voted == params && config.is_accredited_committee_member(voter))
        .count();
    if votes >= params_vote_threshold(config.accredited_committee_members_count()) {
        config.channel_params = Some(params);
        config.params_votes.clear();
        assert!(
            config.accredited_committee_members_count() > 0,
            "new channel params would leave no key accredited"
        );
    }
    Response::set_state(config.to_bytes())
}

/// Bounds every channel params value, at genesis and on a vote.
fn assert_valid_params(params: &ChannelParams) {
    // A timeout above the timeframe never fires: the turn ends first.
    assert!(
        (MIN_POSTING_TIMEOUT..=params.posting_timeframe).contains(&params.posting_timeout),
        "posting_timeout must be at least MIN_POSTING_TIMEOUT and no longer than posting_timeframe"
    );
    // A zero minimum would accredit every key that ever staked a nonzero amount.
    assert!(
        params.minimum_sequencer_stake > 0,
        "minimum_sequencer_stake must be non-zero"
    );
    assert!(params.finality_depth > 0, "finality_depth must be non-zero");
    assert!(
        (MIN_MAX_BLOCK_SIZE..=MAX_MAX_BLOCK_SIZE).contains(&params.max_block_size),
        "max_block_size must be between MIN_MAX_BLOCK_SIZE and MAX_MAX_BLOCK_SIZE"
    );
}

fn assert_root_origin(input: &ReceiveInput, message: &str) {
    assert!(input.from.is_none(), "{message}");
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

fn to_config(program: AccountId, message: &Message) -> SyncMessage {
    SyncMessage::new(
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
    verify_signatures(
        config,
        approvals.iter().map(|approval| {
            (
                approval.signer,
                approval.signature.as_slice(),
                message.clone(),
            )
        }),
        "slash carries fewer approvals than the threshold",
    );
}

/// Handles `VerifyApprovals`: the same rules as `Slash`, each approval signed with its own
/// `valid_until`, which bounds the transaction.
fn verify_committee_approvals(
    input: &ReceiveInput,
    domain: [u8; 32],
    payload: &[u8],
    approvals: &[CommitteeApproval],
) -> Response {
    assert_config_account(input);
    // A slash approval's bytes match a committee approval's under this domain.
    assert_ne!(
        domain, SLASH_APPROVAL_DOMAIN,
        "VerifyApprovals cannot verify slash approvals"
    );
    let config = decode_config(&input.pre_state);
    let channel_id = channel_id(&config);
    verify_signatures(
        &config,
        approvals.iter().map(|approval| {
            (
                approval.signer,
                approval.signature.as_slice(),
                committee_approval_message(domain, channel_id, payload, approval.valid_until),
            )
        }),
        "the change carries fewer approvals than the threshold",
    );
    let valid_until = approvals
        .iter()
        .map(|approval| approval.valid_until)
        .min()
        .expect("a change requires approvals");
    Response::keep_state().block_window(..valid_until.saturating_add(1))
}

/// Each `(signer, signature, message)` is by a distinct key this config accredits and verifies,
/// and there are at least the threshold of them.
fn verify_signatures<'approval>(
    config: &SequencerStakeConfig,
    approvals: impl IntoIterator<Item = (SequencerKey, &'approval [u8], Vec<u8>)>,
    too_few: &str,
) {
    let mut approvers: Vec<SequencerKey> = Vec::new();
    for (signer, signature, message) in approvals {
        assert!(
            config.is_accredited_committee_member(&signer),
            "approval from a key this config does not accredit"
        );
        assert!(!approvers.contains(&signer), "the same key approved twice");

        let verifying_key = VerifyingKey::from_bytes(&signer.to_bytes())
            .expect("a SequencerKey is a valid Ed25519 public key");
        let signature =
            Signature::from_slice(signature).expect("approval signature should be 64 bytes");
        verifying_key
            .verify_strict(&message, &signature)
            .expect("approval signature should verify against its signer");

        approvers.push(signer);
    }

    assert!(
        approvers.len() >= slash_approval_threshold(config.accredited_committee_members_count()),
        "{too_few}"
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

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use lee_core::{BlockId, account::ActorState, program::Transition};
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
    const DOMAIN: [u8; 32] = [11; 32];
    const PAYLOAD: &[u8] = b"a change";

    fn signing_key(seed: u8) -> SigningKey {
        SigningKey::from_bytes(&[seed; 32])
    }

    fn key(seed: u8) -> SequencerKey {
        SequencerKey::new(signing_key(seed).verifying_key().to_bytes())
            .expect("a derived public key is a curve point")
    }

    const fn genesis_params() -> ChannelParams {
        ChannelParams {
            minimum_sequencer_stake: MINIMUM,
            posting_timeframe: 300,
            posting_timeout: 25,
            max_block_size: 1 << 20,
            finality_depth: 5,
        }
    }

    /// Valid params that differ from [`genesis_params`].
    const fn new_params() -> ChannelParams {
        ChannelParams {
            minimum_sequencer_stake: 2 * MINIMUM,
            posting_timeframe: 600,
            posting_timeout: 50,
            max_block_size: 1 << 19,
            finality_depth: genesis_params().finality_depth,
        }
    }

    fn config_with(entries: &[(SequencerKey, SequencerEntry)]) -> Vec<u8> {
        config_with_votes(entries, &[])
    }

    fn config_with_votes(
        entries: &[(SequencerKey, SequencerEntry)],
        votes: &[(SequencerKey, ChannelParams)],
    ) -> Vec<u8> {
        SequencerStakeConfig {
            channel_params: Some(genesis_params()),
            channel_id: Some(CHANNEL_ID),
            entries: entries.iter().copied().collect::<BTreeMap<_, _>>(),
            params_votes: votes.iter().copied().collect::<BTreeMap<_, _>>(),
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

    /// Three keys staked at twice the minimum, so [`new_params`] keeps them all accredited.
    fn committee_of_three_with_votes(votes: &[(SequencerKey, ChannelParams)]) -> Vec<u8> {
        config_with_votes(
            &[
                (key(1), entry(OWNER, 2 * MINIMUM, 0)),
                (key(2), entry(OTHER_OWNER, 2 * MINIMUM, 0)),
                (key(3), entry(OTHER_OWNER, 2 * MINIMUM, 0)),
            ],
            votes,
        )
    }

    fn entry(account_id: AccountId, total_staked: u128, pending: u128) -> SequencerEntry {
        SequencerEntry {
            account_id,
            total_staked,
            pending_unstake: (pending > 0).then_some(PendingUnstake {
                amount: pending,
                destination: DESTINATION,
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
            from: origin.map(|sender| Actor::new(sender, sender)),
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
        handle_message(&input, message).into_transition(input)
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
        }
    }

    fn vote(params: ChannelParams) -> Message {
        Message::VoteChannelParams {
            sequencer_key: key(1),
            params,
        }
    }

    fn record_vote(ownership: AccountId, params: ChannelParams) -> Message {
        Message::RecordChannelParamsVote {
            sequencer_key: key(1),
            ownership,
            params,
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
        assert_eq!(transition.response.validity.blocks.start(), None);
        assert_eq!(transition.response.validity.blocks.end(), None);
        assert_eq!(
            (
                transition.response.sync_messages,
                transition.response.async_messages
            ),
            (
                vec![custody_transfer(
                    funds_of(OWNER),
                    stake_funds_seed(&OWNER),
                    DESTINATION,
                    500,
                )],
                Vec::new()
            )
        );
    }

    #[test]
    fn a_full_release_drops_the_keys_vote() {
        let transition = at_config(
            None,
            &config_with_votes(
                &[(key(1), entry(OWNER, 3_000, 3_000))],
                &[(key(1), new_params())],
            ),
            finalize(key(1)),
        );
        assert!(decoded_config(&transition).params_votes.is_empty());
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
        assert_eq!(transition.response.validity.blocks.start(), None);
        assert_eq!(transition.response.validity.blocks.end(), None);
        assert_eq!(
            (
                transition.response.sync_messages,
                transition.response.async_messages
            ),
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
    fn a_tracked_request_records_the_pending_unstake() {
        let transition = at_config(
            Some(PROGRAM),
            &config_with(&[(key(1), entry(OWNER, 3_000, 0))]),
            track(OWNER, 500),
        );

        assert_eq!(
            decoded_config(&transition)
                .entries
                .get(&key(1))
                .and_then(|entry| entry.pending_unstake),
            Some(PendingUnstake {
                amount: 500,
                destination: DESTINATION,
            })
        );
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
            (
                transition.response.sync_messages,
                transition.response.async_messages
            ),
            (
                vec![
                    to_config(PROGRAM, &record_stake(OWNER, MINIMUM, false)),
                    SyncMessage::new(
                        Actor::native_balance(FUNDING),
                        &native_token::Message::Transfer {
                            to: funds_of(OWNER),
                            amount: MINIMUM,
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
            &config_with_votes(
                &[
                    (key(1), entry(OWNER, 3_000, 500)),
                    (key(2), entry(OTHER_OWNER, 3_000, 0)),
                    (key(3), entry(OTHER_OWNER, 3_000, 0)),
                ],
                &[(key(1), new_params())],
            ),
            slash(vec![approval(2, key(1)), approval(3, key(1))]),
        );

        let config = decoded_config(&transition);
        assert!(!config.entries.contains_key(&key(1)));
        assert!(config.params_votes.is_empty());
        assert_eq!(
            (
                transition.response.sync_messages,
                transition.response.async_messages
            ),
            (
                vec![custody_transfer(
                    funds_of(OWNER),
                    stake_funds_seed(&OWNER),
                    slash_sink_account_id(PROGRAM),
                    3_000
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
                params: new_params(),
                channel_id: CHANNEL_ID,
            },
        );
    }

    #[test]
    #[should_panic(
        expected = "max_block_size must be between MIN_MAX_BLOCK_SIZE and MAX_MAX_BLOCK_SIZE"
    )]
    fn genesis_cannot_set_a_block_size_bedrock_cannot_carry() {
        let mut config = SequencerStakeConfig::from_bytes(&config_with(&[])).unwrap();
        config.channel_params = None;
        let _transition = at_config(
            None,
            &config.to_bytes(),
            Message::InitChannelParams {
                params: ChannelParams {
                    max_block_size: MAX_MAX_BLOCK_SIZE + 1,
                    ..genesis_params()
                },
                channel_id: CHANNEL_ID,
            },
        );
    }

    // --- VoteChannelParams ---

    #[test]
    fn a_vote_is_forwarded_to_the_config() {
        let transition = at_owner(true, &record(key(1)), vote(new_params()));

        assert!(transition.response.post_state.is_none());
        assert_eq!(
            (
                transition.response.sync_messages,
                transition.response.async_messages
            ),
            (
                vec![to_config(PROGRAM, &record_vote(OWNER, new_params()))],
                Vec::new()
            )
        );
    }

    #[test]
    #[should_panic(expected = "must sign for the ownership account")]
    fn an_unsigned_vote_is_refused() {
        let _transition = at_owner(false, &record(key(1)), vote(new_params()));
    }

    #[test]
    #[should_panic(expected = "ownership account backs a different sequencer key")]
    fn a_vote_cannot_name_a_key_this_account_does_not_back() {
        let _transition = at_owner(true, &record(key(2)), vote(new_params()));
    }

    #[test]
    #[should_panic(expected = "VoteChannelParams is only invoked as a top-level user transaction")]
    fn a_vote_from_another_program_is_refused() {
        let _transition = run(
            OWNER,
            true,
            Some(OTHER_PROGRAM),
            &record(key(1)),
            vote(new_params()),
        );
    }

    #[test]
    #[should_panic(
        expected = "posting_timeout must be at least MIN_POSTING_TIMEOUT and no longer than posting_timeframe"
    )]
    fn a_vote_for_invalid_params_is_refused() {
        let _transition = at_owner(
            true,
            &record(key(1)),
            vote(ChannelParams {
                posting_timeout: 601,
                ..new_params()
            }),
        );
    }

    #[test]
    #[should_panic(
        expected = "posting_timeout must be at least MIN_POSTING_TIMEOUT and no longer than posting_timeframe"
    )]
    fn a_vote_for_a_posting_timeout_under_the_floor_is_refused() {
        let _transition = at_owner(
            true,
            &record(key(1)),
            vote(ChannelParams {
                posting_timeout: MIN_POSTING_TIMEOUT - 1,
                ..new_params()
            }),
        );
    }

    #[test]
    fn a_vote_for_the_posting_timeout_floor_is_forwarded() {
        let params = ChannelParams {
            posting_timeout: MIN_POSTING_TIMEOUT,
            ..new_params()
        };
        let transition = at_owner(true, &record(key(1)), vote(params));

        assert_eq!(
            transition.response.sync_messages,
            vec![to_config(PROGRAM, &record_vote(OWNER, params))]
        );
    }

    #[test]
    fn a_vote_short_of_the_threshold_is_recorded() {
        let transition = at_config(
            Some(PROGRAM),
            &committee_of_three_with_votes(&[]),
            record_vote(OWNER, new_params()),
        );

        let config = decoded_config(&transition);
        assert_eq!(config.channel_params, Some(genesis_params()));
        assert_eq!(
            config.params_votes,
            BTreeMap::from([(key(1), new_params())])
        );
    }

    #[test]
    fn a_vote_reaching_two_thirds_replaces_the_params_and_clears_every_vote() {
        let other = ChannelParams {
            posting_timeframe: 900,
            ..new_params()
        };
        let transition = at_config(
            Some(PROGRAM),
            &committee_of_three_with_votes(&[(key(2), new_params()), (key(3), other)]),
            record_vote(OWNER, new_params()),
        );

        let config = decoded_config(&transition);
        assert_eq!(config.channel_params, Some(new_params()));
        assert!(config.params_votes.is_empty());
    }

    #[test]
    fn votes_for_different_params_do_not_add_up() {
        let other = ChannelParams {
            posting_timeframe: 900,
            ..new_params()
        };
        let transition = at_config(
            Some(PROGRAM),
            &committee_of_three_with_votes(&[(key(2), other)]),
            record_vote(OWNER, new_params()),
        );

        let config = decoded_config(&transition);
        assert_eq!(config.channel_params, Some(genesis_params()));
        assert_eq!(config.params_votes.len(), 2);
    }

    #[test]
    fn a_new_vote_replaces_the_keys_old_one() {
        let other = ChannelParams {
            posting_timeframe: 900,
            ..new_params()
        };
        let transition = at_config(
            Some(PROGRAM),
            &committee_of_three_with_votes(&[(key(1), other)]),
            record_vote(OWNER, new_params()),
        );

        assert_eq!(
            decoded_config(&transition).params_votes,
            BTreeMap::from([(key(1), new_params())])
        );
    }

    #[test]
    fn a_vote_for_the_params_in_force_withdraws_the_keys_vote() {
        let transition = at_config(
            Some(PROGRAM),
            &committee_of_three_with_votes(&[(key(1), new_params()), (key(2), new_params())]),
            record_vote(OWNER, genesis_params()),
        );

        let config = decoded_config(&transition);
        assert_eq!(config.channel_params, Some(genesis_params()));
        assert_eq!(
            config.params_votes,
            BTreeMap::from([(key(2), new_params())])
        );
    }

    #[test]
    #[should_panic(expected = "finality_depth is fixed at genesis")]
    fn a_vote_changing_the_finality_depth_is_refused() {
        let _transition = at_config(
            Some(PROGRAM),
            &committee_of_three_with_votes(&[]),
            record_vote(
                OWNER,
                ChannelParams {
                    finality_depth: 2 * genesis_params().finality_depth,
                    ..new_params()
                },
            ),
        );
    }

    #[test]
    fn a_vote_held_by_a_key_on_its_way_out_is_not_counted() {
        // Four staked keys, three accredited: the threshold is two, and key 4's vote does not
        // count while its whole stake is pending release.
        let transition = at_config(
            Some(PROGRAM),
            &config_with_votes(
                &[
                    (key(1), entry(OWNER, 2 * MINIMUM, 0)),
                    (key(2), entry(OTHER_OWNER, 2 * MINIMUM, 0)),
                    (key(3), entry(OTHER_OWNER, 2 * MINIMUM, 0)),
                    (key(4), entry(OTHER_OWNER, 2 * MINIMUM, 2 * MINIMUM)),
                ],
                &[(key(4), new_params())],
            ),
            record_vote(OWNER, new_params()),
        );

        assert_eq!(
            decoded_config(&transition).channel_params,
            Some(genesis_params())
        );
    }

    #[test]
    fn a_key_on_its_way_out_does_not_raise_the_threshold() {
        // Four staked keys, three accredited: two votes reach the threshold, where four keys
        // would need three.
        let transition = at_config(
            Some(PROGRAM),
            &config_with_votes(
                &[
                    (key(1), entry(OWNER, 2 * MINIMUM, 0)),
                    (key(2), entry(OTHER_OWNER, 2 * MINIMUM, 0)),
                    (key(3), entry(OTHER_OWNER, 2 * MINIMUM, 0)),
                    (key(4), entry(OTHER_OWNER, 2 * MINIMUM, 2 * MINIMUM)),
                ],
                &[(key(2), new_params())],
            ),
            record_vote(OWNER, new_params()),
        );

        let config = decoded_config(&transition);
        assert_eq!(config.channel_params, Some(new_params()));
        assert!(config.params_votes.is_empty());
    }

    #[test]
    #[should_panic(expected = "only an accredited key may vote on channel params")]
    fn a_key_on_its_way_out_cannot_vote() {
        let _transition = at_config(
            Some(PROGRAM),
            &config_with(&[(key(1), entry(OWNER, 3_000, 3_000))]),
            record_vote(OWNER, new_params()),
        );
    }

    #[test]
    #[should_panic(expected = "config entry points at a different ownership account")]
    fn a_vote_cannot_be_recorded_for_another_accounts_key() {
        let _transition = at_config(
            Some(PROGRAM),
            &committee_of_three_with_votes(&[]),
            record_vote(ATTACKER, new_params()),
        );
    }

    #[test]
    #[should_panic(expected = "new channel params would leave no key accredited")]
    fn params_that_accredit_no_key_are_refused() {
        let _transition = at_config(
            Some(PROGRAM),
            &config_with(&[(key(1), entry(OWNER, MINIMUM, 0))]),
            record_vote(OWNER, new_params()),
        );
    }

    #[test]
    #[should_panic(
        expected = "stake bookkeeping is only sent by this program's ownership accounts"
    )]
    fn a_vote_recorded_from_the_root_is_refused() {
        let _transition = at_config(
            None,
            &committee_of_three_with_votes(&[]),
            record_vote(OWNER, new_params()),
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

    fn committee_approval(seed: u8, payload: &[u8], valid_until: BlockId) -> CommitteeApproval {
        CommitteeApproval {
            signer: key(seed),
            valid_until,
            signature: signing_key(seed)
                .sign(&committee_approval_message(
                    DOMAIN,
                    CHANNEL_ID,
                    payload,
                    valid_until,
                ))
                .to_bytes()
                .to_vec(),
        }
    }

    fn verify(approvals: Vec<CommitteeApproval>) -> Message {
        Message::VerifyApprovals {
            domain: DOMAIN,
            payload: PAYLOAD.to_vec(),
            approvals,
        }
    }

    #[test]
    fn approvals_meeting_the_threshold_bound_the_transaction_and_change_nothing() {
        let transition = at_config(
            Some(ATTACKER),
            &committee_of_three(),
            verify(vec![
                committee_approval(1, PAYLOAD, 30),
                committee_approval(2, PAYLOAD, 20),
            ]),
        );

        assert_eq!(transition.response.post_state, None);
        let blocks = &transition.response.validity.blocks;
        assert!(blocks.is_valid_for(20), "valid through the earliest expiry");
        assert!(!blocks.is_valid_for(21), "and not past it");
    }

    #[test]
    #[should_panic(expected = "the change carries fewer approvals than the threshold")]
    fn approvals_below_the_threshold_are_refused() {
        let _transition = at_config(
            None,
            &committee_of_three(),
            verify(vec![committee_approval(1, PAYLOAD, 30)]),
        );
    }

    #[test]
    #[should_panic(expected = "approval signature should verify against its signer")]
    fn an_approval_of_another_payload_is_refused() {
        let _transition = at_config(
            None,
            &committee_of_three(),
            verify(vec![
                committee_approval(1, PAYLOAD, 30),
                committee_approval(2, b"another change", 30),
            ]),
        );
    }

    #[test]
    #[should_panic(expected = "not the sequencer_stake config account")]
    fn approvals_are_verified_only_at_the_config() {
        let _transition = at_owner(
            false,
            &committee_of_three(),
            verify(vec![
                committee_approval(1, PAYLOAD, 30),
                committee_approval(2, PAYLOAD, 30),
            ]),
        );
    }

    /// A slash approval, read as a committee approval of key ‖ inscription[..24] valid until
    /// inscription[24..], has the same bytes; the Slash domain is refused outright.
    #[test]
    #[should_panic(expected = "VerifyApprovals cannot verify slash approvals")]
    fn slash_approvals_cannot_pass_as_committee_approvals() {
        let mut payload = key(1).to_bytes().to_vec();
        payload.extend_from_slice(&INSCRIPTION[..24]);
        let valid_until = u64::from_le_bytes(INSCRIPTION[24..].try_into().unwrap());
        let approvals = [2, 3]
            .map(|seed| {
                let slash = approval(seed, key(1));
                CommitteeApproval {
                    signer: slash.signer,
                    valid_until,
                    signature: slash.signature,
                }
            })
            .to_vec();
        assert_eq!(
            committee_approval_message(SLASH_APPROVAL_DOMAIN, CHANNEL_ID, &payload, valid_until),
            slash_approval_message(CHANNEL_ID, key(1), INSCRIPTION),
            "the two formats collide"
        );

        let _transition = at_config(
            None,
            &committee_of_three(),
            Message::VerifyApprovals {
                domain: SLASH_APPROVAL_DOMAIN,
                payload,
                approvals,
            },
        );
    }
}
