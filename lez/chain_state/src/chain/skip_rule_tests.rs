use common::{
    block::{Block, HashableBlockData},
    test_utils::{create_transaction_native_token_transfer, produce_dummy_block},
    transaction::LeeTransaction,
};
use lee::{V03State, privacy_preserving_transaction::circuit::Proof};
use logos_blockchain_core::mantle::ops::channel::MsgId;
use logos_blockchain_zone_sdk::Slot;
use sequencer_stake_core::ChannelParams;
use testnet_initial_state::initial_pub_accounts_private_keys;

use crate::{
    BlockIngestError, ChainState, ChannelEntry, Judged, ProofStore, Verdict,
    apply::tests::{private_sender_state, private_tx, settled_block, tip_of},
    apply_block,
    test_utils::{inbox_fee, required_for},
};

const SKIP_WINDOW: u32 = 10;

struct PlainFixture {
    initial: V03State,
    genesis: Block,
    public_candidate: Block,
    skip_candidate: Block,
    on_genesis: V03State,
}

struct Fixture {
    plain: PlainFixture,
    private_candidate: Block,
    proof: Proof,
    // Confirms the private candidate when published by another signer.
    confirming_successor: Block,
    after_private_candidate: V03State,
}

impl std::ops::Deref for Fixture {
    type Target = PlainFixture;

    fn deref(&self) -> &Self::Target {
        &self.plain
    }
}

impl PlainFixture {
    fn node(&self, skip_window: u32) -> ChainState {
        self.node_with(skip_window, ProofStore::new(usize::MAX))
    }

    fn node_with(&self, skip_window: u32, proofs: ProofStore) -> ChainState {
        let config = system_accounts::sequencer_stake_config_account(
            Some(ChannelParams {
                minimum_sequencer_stake: system_accounts::DEFAULT_MINIMUM_SEQUENCER_STAKE,
                posting_timeframe: system_accounts::DEFAULT_SEQUENCER_POSTING_TIMEFRAME,
                posting_timeout: system_accounts::DEFAULT_SEQUENCER_POSTING_TIMEOUT,
                skip_window,
                exit_delay: system_accounts::DEFAULT_SEQUENCER_EXIT_DELAY,
                max_block_size: system_accounts::DEFAULT_MAX_BLOCK_SIZE,
            }),
            None,
        );
        let id = system_accounts::sequencer_stake_config_account_id();
        let initial = self.initial.clone().with_public_accounts([(id, config)]);
        ChainState::new(initial, proofs)
    }

    fn after_skip_candidate(&self) -> V03State {
        let mut after_skip_candidate = self.on_genesis.clone();
        apply_block(
            Some(&tip_of(&self.genesis)),
            &self.skip_candidate,
            &mut after_skip_candidate,
        )
        .expect("skip candidate applies");
        after_skip_candidate
    }

    fn private_successor_of_skip(&self) -> (Block, Proof) {
        let after_skip_candidate = self.after_skip_candidate();
        let (transaction, proof) = deshield(&after_skip_candidate, 13);
        (
            settled_block(
                3,
                self.skip_candidate.header.hash,
                vec![transaction],
                &after_skip_candidate,
            ),
            proof,
        )
    }

    fn failing_on_genesis(&self) -> (Block, Proof) {
        let (failing, proof) = deshield(&self.on_genesis, 12);
        let block = settled_block(2, self.genesis.header.hash, vec![failing], &self.on_genesis);
        (without_clock_tail(block), proof)
    }
}

impl Fixture {
    fn private_successor(&self) -> (Block, Proof) {
        let (transaction, proof) = deshield(&self.after_private_candidate, 10);
        (
            settled_block(
                3,
                self.private_candidate.header.hash,
                vec![transaction],
                &self.after_private_candidate,
            ),
            proof,
        )
    }

    fn public_successor(&self) -> Block {
        let accounts = initial_pub_accounts_private_keys();
        let nonce = self
            .after_private_candidate
            .get_account_by_id(accounts[0].account_id)
            .nonce
            .0;
        let transfer = create_transaction_native_token_transfer(
            accounts[0].account_id,
            nonce,
            accounts[1].account_id,
            1,
            &accounts[0].pub_sign_key,
        );
        settled_block(
            3,
            self.private_candidate.header.hash,
            vec![transfer],
            &self.after_private_candidate,
        )
    }

    fn failing_successor(&self) -> (Block, Proof) {
        let (failing, proof) = deshield(&self.after_private_candidate, 11);
        let block = settled_block(
            3,
            self.private_candidate.header.hash,
            vec![failing],
            &self.after_private_candidate,
        );
        (without_clock_tail(block), proof)
    }
}

fn plain_fixture() -> PlainFixture {
    let (initial, _) = private_sender_state(&[0, 1]);
    let genesis = produce_dummy_block(1, None, vec![]);
    let mut on_genesis = initial.clone();
    apply_block(None, &genesis, &mut on_genesis).expect("genesis applies");

    let accounts = initial_pub_accounts_private_keys();
    let transfer = create_transaction_native_token_transfer(
        accounts[0].account_id,
        0,
        accounts[1].account_id,
        1,
        &accounts[0].pub_sign_key,
    );
    let public_candidate = settled_block(2, genesis.header.hash, vec![transfer], &on_genesis);
    let skip_candidate = settled_block(2, genesis.header.hash, vec![], &on_genesis);
    PlainFixture {
        initial,
        genesis,
        public_candidate,
        skip_candidate,
        on_genesis,
    }
}

fn fixture() -> Fixture {
    let plain = plain_fixture();
    let (genesis, state) = (&plain.genesis, &plain.on_genesis);
    let (_, senders) = private_sender_state(&[0, 1]);
    let accounts = initial_pub_accounts_private_keys();
    let paying = |amount| {
        let fee = inbox_fee(amount, senders[0].0.account_id());
        private_tx(state, &senders[0], accounts[0].account_id, 10, Some(fee))
    };
    let private = paying(required_for(0, paying));
    let proof = private.proof().cloned().expect("a private transaction");
    let private_candidate = settled_block(2, genesis.header.hash, vec![private], state);
    let mut after_private_candidate = state.clone();
    apply_block(
        Some(&tip_of(genesis)),
        &private_candidate,
        &mut after_private_candidate,
    )
    .expect("private candidate applies");
    let confirming_successor = settled_block(
        3,
        private_candidate.header.hash,
        vec![],
        &after_private_candidate,
    );
    Fixture {
        plain,
        private_candidate,
        proof,
        confirming_successor,
        after_private_candidate,
    }
}

fn deshield(state: &V03State, amount: u128) -> (LeeTransaction, Proof) {
    let (_, senders) = private_sender_state(&[0, 1]);
    let paying = |fee_amount| {
        let fee = inbox_fee(fee_amount, senders[1].0.account_id());
        private_tx(
            state,
            &senders[1],
            initial_pub_accounts_private_keys()[0].account_id,
            amount,
            Some(fee),
        )
    };
    let private = paying(required_for(0, paying));
    let proof = private.proof().cloned().expect("a private transaction");
    (private, proof)
}

fn without_clock_tail(block: Block) -> Block {
    let mut data = HashableBlockData::from(block);
    data.transactions.pop();
    data.into_pending_block()
}

fn lineage(blocks: &[(&Block, [u8; 32])]) -> Vec<ChannelEntry> {
    let mut parent = MsgId::root();
    blocks
        .iter()
        .zip(1..)
        .map(|(&(block, signer), n)| {
            let entry = ChannelEntry {
                msg: MsgId::from([n; 32]),
                parent,
                signer: Some(signer),
                slot: None,
                block: Some(block.digested()),
            };
            parent = entry.msg;
            entry
        })
        .collect()
}

fn at_slots(entries: &[ChannelEntry], slots: &[u64]) -> Vec<ChannelEntry> {
    entries
        .iter()
        .zip(slots)
        .map(|(entry, &slot)| ChannelEntry {
            slot: Some(Slot::from(slot)),
            ..entry.clone()
        })
        .collect()
}

fn reported(outcomes: &[Judged], entry: &ChannelEntry) -> bool {
    outcomes.iter().any(|judged| {
        judged.msg == entry.msg
            && matches!(
                judged.verdict,
                Verdict::Dropped {
                    punishable: true,
                    ..
                }
            )
    })
}

fn misplaced(outcomes: &[Judged], entry: &ChannelEntry, expected: u64, got: u64) -> bool {
    outcomes.iter().any(|judged| {
        judged.msg == entry.msg
            && matches!(
                &judged.verdict,
                Verdict::Dropped {
                    error: BlockIngestError::UnexpectedBlockId {
                        expected: dropped_expected,
                        got: dropped_got,
                    },
                    punishable: true,
                } if *dropped_expected == expected && *dropped_got == got
            )
    })
}

fn dropped(outcomes: &[Judged], entry: &ChannelEntry) -> bool {
    outcomes
        .iter()
        .any(|judged| judged.msg == entry.msg && matches!(judged.verdict, Verdict::Dropped { .. }))
}

fn at_once_and_stepwise(
    fixture: &PlainFixture,
    proofs: &[&Proof],
    entries: &[ChannelEntry],
    slots: &[u64],
    steps: &[(usize, u64)],
) -> [(ChainState, Vec<Judged>); 2] {
    let finalized = at_slots(entries, slots);
    let at_once = [(finalized.len(), steps.last().expect("a step").1)];
    [at_once.as_slice(), steps].map(|updates| {
        let mut node = fixture.node(SKIP_WINDOW);
        for proof in proofs {
            node.proofs().insert(proof);
        }
        node.apply_extension(entries.to_vec());
        let mut start = 0;
        let mut outcomes = Vec::new();
        for &(end, lib) in updates {
            outcomes.extend(
                node.apply_finalized(&finalized[start..end], Slot::from(lib))
                    .judged,
            );
            start = end;
        }
        (node, outcomes)
    })
}

#[test]
fn nodes_with_and_without_the_proof_take_a_skip_that_only_an_l1_reorg_undoes() {
    let fixture = fixture();
    let entries = lineage(&[
        (&fixture.genesis, [1; 32]),
        (&fixture.private_candidate, [1; 32]),
        (&fixture.skip_candidate, [2; 32]),
    ]);
    let mut holding = fixture.node(SKIP_WINDOW);
    holding.proofs().insert(&fixture.proof);
    let mut lacking = fixture.node(SKIP_WINDOW);

    for node in [&mut holding, &mut lacking] {
        node.apply_extension(entries.clone());
        assert_eq!(node.head_tip(), Some(tip_of(&fixture.skip_candidate)));
    }
    assert!(holding.head_state() == lacking.head_state());

    holding.replace_unfinalized_view(entries[..2].to_vec());
    assert_eq!(holding.head_tip(), Some(tip_of(&fixture.private_candidate)));

    lacking.proofs().insert(&fixture.proof);
    lacking.hydrate();
    assert_eq!(lacking.head_tip(), Some(tip_of(&fixture.skip_candidate)));
    for node in [&mut holding, &mut lacking] {
        node.apply_extension(vec![entries[1].clone()]);
        let outcomes = node
            .apply_finalized(&at_slots(&entries, &[1, 2, 3]), Slot::from(3))
            .judged;

        assert_eq!(node.head_tip(), Some(tip_of(&fixture.skip_candidate)));
        assert!(!dropped(&outcomes, &entries[1]));
    }
}

#[test]
fn a_node_without_a_confirmed_blocks_proof_stalls_instead_of_diverging_until_the_proof_arrives() {
    let fixture = fixture();
    let entries = lineage(&[
        (&fixture.genesis, [1; 32]),
        (&fixture.private_candidate, [1; 32]),
        (&fixture.confirming_successor, [2; 32]),
    ]);
    let mut following = fixture.node(SKIP_WINDOW);
    let mut stalled = fixture.node(SKIP_WINDOW);
    for node in [&mut following, &mut stalled] {
        node.apply_extension(entries.clone());
        assert_eq!(node.head_tip(), Some(tip_of(&fixture.genesis)));
        assert_eq!(node.missing_proofs(), vec![fixture.proof.digest()]);
    }

    following.proofs().insert(&fixture.proof);
    following.hydrate();
    assert_eq!(
        following.head_tip(),
        Some(tip_of(&fixture.confirming_successor))
    );

    let finalized = at_slots(&entries, &[1, 2, 3]);
    let outcomes = stalled.apply_finalized(&finalized, Slot::from(100)).judged;
    assert_eq!(stalled.head_tip(), Some(tip_of(&fixture.genesis)));
    assert_eq!(stalled.final_tip(), Some(tip_of(&fixture.genesis)));
    for pending in &entries[1..] {
        assert!(!dropped(&outcomes, pending));
    }

    stalled.proofs().insert(&fixture.proof);
    stalled.hydrate();
    stalled.apply_finalized(&[], Slot::from(100));
    following.apply_finalized(&finalized, Slot::from(100));
    for node in [&following, &stalled] {
        assert_eq!(
            node.final_tip(),
            Some(tip_of(&fixture.confirming_successor))
        );
    }
    assert!(stalled.final_state() == following.final_state());
}

#[test]
fn a_final_skip_is_counted_once_for_its_signer() {
    let fixture = fixture();
    let entries = lineage(&[
        (&fixture.genesis, [1; 32]),
        (&fixture.private_candidate, [1; 32]),
        (&fixture.skip_candidate, [2; 32]),
    ]);
    let mut node = fixture.node(SKIP_WINDOW);
    node.proofs().insert(&fixture.proof);

    node.apply_extension(entries.clone());
    assert!(
        node.apply_finalized(&[], Slot::from(0))
            .skip_signers
            .is_empty()
    );
    let finalized = at_slots(&entries, &[1, 2, 3]);
    assert_eq!(
        node.apply_finalized(&finalized, Slot::from(3)).skip_signers,
        vec![[2; 32]]
    );
    assert!(
        node.apply_finalized(&finalized, Slot::from(30))
            .skip_signers
            .is_empty()
    );
}

#[test]
fn a_skip_of_a_plain_block_is_misplaced() {
    let fixture = plain_fixture();
    let entries = lineage(&[
        (&fixture.genesis, [1; 32]),
        (&fixture.public_candidate, [1; 32]),
        (&fixture.skip_candidate, [2; 32]),
    ]);
    let finalized = at_slots(&entries, &[1, 2, 3]);
    let mut node = fixture.node(SKIP_WINDOW);

    node.apply_extension(entries.clone());
    assert_eq!(node.head_tip(), Some(tip_of(&fixture.public_candidate)));

    let outcomes = node.apply_finalized(&finalized, Slot::from(3)).judged;
    assert!(misplaced(&outcomes, &entries[2], 3, 2));
}

#[test]
fn a_writer_cannot_skip_its_own_run() {
    let fixture = fixture();
    let entries = lineage(&[
        (&fixture.genesis, [1; 32]),
        (&fixture.private_candidate, [1; 32]),
        (&fixture.skip_candidate, [1; 32]),
    ]);
    let mut holding = fixture.node(SKIP_WINDOW);
    holding.proofs().insert(&fixture.proof);
    let mut lacking = fixture.node(SKIP_WINDOW);

    holding.apply_extension(entries.clone());
    lacking.apply_extension(entries);
    assert_eq!(holding.head_tip(), Some(tip_of(&fixture.private_candidate)));
    assert_eq!(lacking.head_tip(), Some(tip_of(&fixture.genesis)));
}

#[test]
fn a_provisional_block_settles_once_the_window_passes_and_at_l1_finality_with_a_zero_window() {
    let fixture = fixture();
    let entries = lineage(&[
        (&fixture.genesis, [1; 32]),
        (&fixture.private_candidate, [1; 32]),
    ]);
    let mut windowed = fixture.node(SKIP_WINDOW);
    let mut zero_window = fixture.node(0);
    for node in [&mut windowed, &mut zero_window] {
        node.proofs().insert(&fixture.proof);
        node.apply_extension(entries.clone());
        node.apply_finalized(&at_slots(&entries, &[1, 10]), Slot::from(10));
    }
    assert_eq!(
        zero_window.final_tip(),
        Some(tip_of(&fixture.private_candidate))
    );

    windowed.apply_finalized(&[], Slot::from(19));
    assert_eq!(windowed.final_tip(), Some(tip_of(&fixture.genesis)));
    windowed.apply_finalized(&[], Slot::from(20));
    assert_eq!(
        windowed.final_tip(),
        Some(tip_of(&fixture.private_candidate))
    );
}

#[test]
fn the_settled_chain_does_not_depend_on_how_far_each_update_moves_the_lib() {
    let fixture = fixture();
    let entries = lineage(&[
        (&fixture.genesis, [1; 32]),
        (&fixture.private_candidate, [1; 32]),
        (&fixture.confirming_successor, [2; 32]),
    ]);

    let [(at_once, _), (stepwise, _)] = at_once_and_stepwise(
        &fixture,
        &[&fixture.proof],
        &entries,
        &[1, 10, 15],
        &[(1, 1), (2, 12), (3, 40)],
    );

    assert_eq!(
        at_once.final_tip(),
        Some(tip_of(&fixture.confirming_successor))
    );
    assert_eq!(stepwise.final_tip(), at_once.final_tip());
    assert!(stepwise.final_state() == at_once.final_state());
}

#[test]
fn a_confirmation_outlives_the_cut_of_the_block_that_gave_it() {
    let fixture = fixture();
    let (private_successor, successor_proof) = fixture.private_successor();
    let entries = lineage(&[
        (&fixture.genesis, [1; 32]),
        (&fixture.private_candidate, [2; 32]),
        (&private_successor, [3; 32]),
        (&fixture.confirming_successor, [2; 32]),
        (&fixture.skip_candidate, [4; 32]),
    ]);

    let [(at_once, at_once_outcomes), (stepwise, stepwise_outcomes)] = at_once_and_stepwise(
        &fixture,
        &[&fixture.proof, &successor_proof],
        &entries,
        &[1, 2, 3, 4, 5],
        &[(3, 3), (5, 5)],
    );

    assert_eq!(
        at_once.final_tip(),
        Some(tip_of(&fixture.confirming_successor))
    );
    assert_eq!(stepwise.final_tip(), at_once.final_tip());
    assert!(stepwise.final_state() == at_once.final_state());
    assert!(!reported(&at_once_outcomes, &entries[4]));
    assert!(!reported(&stepwise_outcomes, &entries[4]));
}

#[test]
fn a_plain_block_above_an_unsettled_private_block_cannot_be_skipped() {
    let fixture = fixture();
    let public_successor = fixture.public_successor();
    let entries = lineage(&[
        (&fixture.genesis, [1; 32]),
        (&fixture.private_candidate, [1; 32]),
        (&fixture.confirming_successor, [1; 32]),
        (&public_successor, [2; 32]),
    ]);
    let mut node = fixture.node(SKIP_WINDOW);
    node.proofs().insert(&fixture.proof);
    node.apply_extension(entries.clone());

    let outcomes = node
        .apply_finalized(&at_slots(&entries, &[1, 2, 3, 4]), Slot::from(4))
        .judged;
    assert_eq!(node.final_tip(), Some(tip_of(&fixture.genesis)));
    assert_eq!(node.head_tip(), Some(tip_of(&fixture.confirming_successor)));
    assert!(misplaced(&outcomes, &entries[3], 4, 3));

    node.apply_finalized(&[], Slot::from(12));
    assert_eq!(
        node.final_tip(),
        Some(tip_of(&fixture.confirming_successor))
    );
}

#[test]
fn a_late_skip_and_the_blocks_on_it_are_ignored_without_an_offence_however_the_lib_moves() {
    let fixture = fixture();
    let skip_successor = settled_block(
        3,
        fixture.skip_candidate.header.hash,
        vec![],
        &fixture.after_skip_candidate(),
    );
    let entries = lineage(&[
        (&fixture.genesis, [1; 32]),
        (&fixture.private_candidate, [1; 32]),
        (&fixture.skip_candidate, [2; 32]),
        (&skip_successor, [2; 32]),
    ]);

    for (node, outcomes) in at_once_and_stepwise(
        &fixture,
        &[&fixture.proof],
        &entries,
        &[1, 10, 21, 22],
        &[(2, 20), (4, 22)],
    ) {
        assert_eq!(node.head_tip(), Some(tip_of(&fixture.private_candidate)));
        assert_eq!(node.final_tip(), Some(tip_of(&fixture.private_candidate)));
        for late in &entries[2..] {
            assert!(!dropped(&outcomes, late));
        }
    }
}

#[test]
fn a_failed_private_block_is_skipped_like_a_missing_one() {
    let fixture = plain_fixture();
    let (failing_on_genesis, failing_on_genesis_proof) = fixture.failing_on_genesis();
    let entries = lineage(&[
        (&fixture.genesis, [1; 32]),
        (&failing_on_genesis, [1; 32]),
        (&fixture.public_candidate, [1; 32]),
        (&fixture.skip_candidate, [2; 32]),
    ]);
    let finalized = at_slots(&entries, &[1, 2, 3, 4]);
    let mut holding = fixture.node(SKIP_WINDOW);
    holding.proofs().insert(&failing_on_genesis_proof);
    let mut lacking = fixture.node(SKIP_WINDOW);

    holding.apply_extension(entries.clone());
    let holding_outcomes = holding.apply_finalized(&finalized, Slot::from(4)).judged;
    lacking.apply_extension(entries.clone());
    let lacking_outcomes = lacking.apply_finalized(&finalized, Slot::from(4)).judged;

    for (node, outcomes) in [(&holding, &holding_outcomes), (&lacking, &lacking_outcomes)] {
        assert_eq!(node.final_tip(), Some(tip_of(&fixture.skip_candidate)));
        assert!(!reported(outcomes, &entries[3]));
    }
    assert!(holding.final_state() == lacking.final_state());
    assert!(holding_outcomes.iter().any(|judged| {
        judged.msg == entries[2].msg
            && matches!(
                &judged.verdict,
                Verdict::Dropped { error, punishable: true } if !error.is_invalid_block()
            )
    }));
}

#[test]
fn a_node_without_the_proof_of_a_confirmed_failed_block_stalls_then_converges() {
    let fixture = fixture();
    let (failing_successor, failing_successor_proof) = fixture.failing_successor();
    let on_failing = settled_block(
        4,
        failing_successor.header.hash,
        vec![],
        &fixture.after_private_candidate,
    );
    let entries = lineage(&[
        (&fixture.genesis, [1; 32]),
        (&fixture.private_candidate, [1; 32]),
        (&failing_successor, [1; 32]),
        (&on_failing, [2; 32]),
        (&fixture.skip_candidate, [2; 32]),
    ]);
    let finalized = at_slots(&entries, &[1, 2, 3, 4, 5]);
    let mut holding = fixture.node(SKIP_WINDOW);
    holding.proofs().insert(&failing_successor_proof);
    let mut lacking = fixture.node(SKIP_WINDOW);
    for node in [&mut holding, &mut lacking] {
        node.proofs().insert(&fixture.proof);
        node.apply_extension(entries.clone());
        node.apply_finalized(&finalized, Slot::from(20));
    }

    assert_eq!(
        holding.final_tip(),
        Some(tip_of(&fixture.private_candidate))
    );
    assert_eq!(lacking.final_tip(), Some(tip_of(&fixture.genesis)));
    let blocked = |node: &ChainState| {
        node.blocker()
            .map(|blocker| (blocker.msg, blocker.private, blocker.in_unconfirmed_run))
    };
    assert_eq!(blocked(&holding), Some((entries[2].msg, true, false)));
    assert_eq!(blocked(&lacking), Some((entries[2].msg, true, true)));

    lacking.proofs().insert(&failing_successor_proof);
    lacking.hydrate();
    lacking.apply_finalized(&[], Slot::from(20));
    assert_eq!(
        lacking.final_tip(),
        Some(tip_of(&fixture.private_candidate))
    );
    assert!(lacking.final_state() == holding.final_state());
}

#[test]
fn a_failed_private_block_nobody_skips_leaves_when_its_window_closes() {
    let fixture = plain_fixture();
    let (failing_on_genesis, failing_on_genesis_proof) = fixture.failing_on_genesis();
    let entries = lineage(&[
        (&fixture.genesis, [1; 32]),
        (&failing_on_genesis, [1; 32]),
        (&fixture.public_candidate, [1; 32]),
    ]);
    let finalized = at_slots(&entries, &[1, 2, 13]);
    let mut holding = fixture.node(SKIP_WINDOW);
    holding.proofs().insert(&failing_on_genesis_proof);
    let mut lacking = fixture.node(SKIP_WINDOW);
    for node in [&mut holding, &mut lacking] {
        node.apply_extension(entries.clone());
        node.apply_finalized(&finalized, Slot::from(13));
    }

    assert_eq!(holding.final_tip(), Some(tip_of(&fixture.public_candidate)));
    assert_eq!(lacking.final_tip(), Some(tip_of(&fixture.genesis)));

    lacking.proofs().insert(&failing_on_genesis_proof);
    lacking.hydrate();
    lacking.apply_finalized(&[], Slot::from(13));
    assert_eq!(lacking.final_tip(), Some(tip_of(&fixture.public_candidate)));
    assert!(lacking.final_state() == holding.final_state());
}

#[test]
fn a_node_without_the_proof_cuts_the_blocks_held_behind_a_skipped_block() {
    let fixture = fixture();
    let (private_successor_of_skip, skip_successor_proof) = fixture.private_successor_of_skip();
    let entries = lineage(&[
        (&fixture.genesis, [1; 32]),
        (&fixture.private_candidate, [1; 32]),
        (&fixture.confirming_successor, [1; 32]),
        (&fixture.skip_candidate, [2; 32]),
        (&private_successor_of_skip, [2; 32]),
    ]);
    let mut lacking = fixture.node(SKIP_WINDOW);
    lacking.proofs().insert(&skip_successor_proof);

    lacking.apply_extension(entries.clone());
    let outcomes = lacking
        .apply_finalized(&at_slots(&entries, &[1, 10, 11, 12, 13]), Slot::from(22))
        .judged;

    let judged_excluded = |entry: &ChannelEntry| {
        outcomes
            .iter()
            .any(|judged| judged.msg == entry.msg && matches!(judged.verdict, Verdict::Excluded))
    };
    assert!(judged_excluded(&entries[1]));
    assert!(judged_excluded(&entries[2]));
    assert_eq!(lacking.final_tip(), Some(tip_of(&fixture.skip_candidate)));
    let view: Vec<MsgId> = lacking.view().iter().map(|entry| entry.msg).collect();
    assert_eq!(view, vec![entries[4].msg]);

    lacking.apply_finalized(&[], Slot::from(23));
    assert_eq!(
        lacking.final_tip(),
        Some(tip_of(&private_successor_of_skip))
    );
}

#[test]
fn a_held_misplaced_block_is_still_reported_after_an_unfinalized_skip_turns_late() {
    let fixture = fixture();
    let misplaced = produce_dummy_block(4, Some(fixture.private_candidate.header.hash), vec![]);
    let entries = lineage(&[
        (&fixture.genesis, [1; 32]),
        (&fixture.private_candidate, [1; 32]),
        (&misplaced, [1; 32]),
        (&fixture.skip_candidate, [2; 32]),
    ]);
    let mut lacking = fixture.node(SKIP_WINDOW);

    lacking.apply_extension(entries.clone());
    let mut outcomes = lacking
        .apply_finalized(&at_slots(&entries[..3], &[1, 10, 11]), Slot::from(11))
        .judged;
    outcomes.extend(lacking.apply_finalized(&[], Slot::from(20)).judged);
    outcomes.extend(
        lacking
            .apply_finalized(&at_slots(&entries[3..], &[21]), Slot::from(21))
            .judged,
    );
    lacking.proofs().insert(&fixture.proof);
    lacking.hydrate();
    outcomes.extend(lacking.apply_finalized(&[], Slot::from(21)).judged);

    assert!(reported(&outcomes, &entries[2]));
}

#[test]
fn a_blocks_proof_survives_eviction_until_its_entry_leaves_the_view() {
    let fixture = fixture();
    let held = lineage(&[
        (&fixture.genesis, [1; 32]),
        (&fixture.private_candidate, [1; 32]),
    ]);
    let cut = lineage(&[
        (&fixture.genesis, [1; 32]),
        (&fixture.private_candidate, [1; 32]),
        (&fixture.skip_candidate, [2; 32]),
    ]);
    let size = fixture.proof.clone().into_inner().len();
    let filler = |fill| Proof::from_inner(vec![fill; size]);
    for (entries, slots, lib, tip) in [
        (held, &[1, 10][..], 20, &fixture.private_candidate),
        (cut, &[1, 2, 3][..], 3, &fixture.skip_candidate),
    ] {
        let store = ProofStore::new(size);
        store.insert(&fixture.proof);
        let mut node = fixture.node_with(SKIP_WINDOW, store.clone());

        node.apply_extension(entries.clone());
        store.insert(&filler(0));
        store.insert(&filler(1));
        assert_eq!(node.head_tip(), Some(tip_of(tip)));
        assert_eq!(store.get(&filler(0).digest()), None);
        assert_eq!(
            store.get(&fixture.proof.digest()),
            Some(fixture.proof.clone())
        );

        node.apply_finalized(&at_slots(&entries, slots), Slot::from(lib));
        assert_eq!(node.final_tip(), Some(tip_of(tip)));
        assert_eq!(
            store.get(&fixture.proof.digest()),
            Some(fixture.proof.clone())
        );
        store.insert(&filler(2));
        assert_eq!(store.get(&fixture.proof.digest()), None);
    }
}
