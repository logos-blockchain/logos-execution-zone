Feature: Sequencer registration — a first Stake turns balance into stake

  # Node-level (L3) registration coverage: a first Stake turns balance into
  # stake. Every scenario runs against a deployed LEZ stack: transactions are
  # signed and submitted through the scenario wallet, executed by the real
  # sequencer, and every assertion reads state back through the sequencer's
  # RPC API. The @P-NN tags are stable case ids.
  #
  # Rejection semantics at node level: an invalid transaction is admitted to
  # the mempool and only fails during block building, where the builder drops
  # it from the block without surfacing the in-program rejection reason
  # through any API. Rejection scenarios therefore assert non-inclusion plus
  # unchanged accounts; the expected in-program reason is kept as a comment
  # on each scenario and stays pinned by sequencer_core's unit tests.
  #
  # The non-inclusion protocol depends on two node properties that no API
  # documents or pins; if either changes, the rejection scenarios weaken to
  # vacuous passes rather than failing:
  # - mempool admission is synchronous with the send RPC reply, so a tip read
  #   after submission is at or past the admission point
  # - the block builder pulls the whole mempool on every turn, so two blocks
  #   past that tip guarantee a post-admission pull tried the transaction;
  #   this is the "within the next 2 blocks" window each rejection step names
  # Should the node ever gain a transaction status API (pending, included, or
  # dropped with a reason), replace the two-block window with it.
  #
  # Registration cases not yet covered here:
  # - P-15, P-16 need a bad-mover guest
  # - P-17, P-19 need a chained-caller guest
  # - P-21 needs a second mover program fitting Stake's two-account slot
  # - G-01..G-03 exercise genesis builders private to sequencer_core, where
  #   G-01 and G-02 are already covered

  Background:
    Given a LEZ stack with fast blocks and configured public accounts
    And the sequencer_stake config account is at the default minimum stake
    And a sequencer key with no config entry
    And a default-owned, unclaimed ownership account for the sequencer key
    And a funding account holding "ten times the minimum stake"
    And chain waits give up after 60 blocks

  @stake_registration_ci @P-01 @P0 @L3
  # Mirrors the registration leg of tests/sequencer_stake_demo.rs,
  # additionally asserting the config entry and both balance deltas.
  Scenario: Happy-path registration through authenticated_transfer
    When a Stake of "twice the minimum stake" is submitted
    Then the stake transaction is accepted
    And the config entry tracks the staked amount with no pending unstake
    And the config entry points at the ownership account
    And the ownership account is claimed by sequencer_stake backing the sequencer key with no pending unstake
    And the funds account balance increased by the staked amount
    And the funding account balance decreased by the staked amount

  @stake_registration_ci @P-02 @P0 @L3
  # In-program reason: "an initial stake must already meet the minimum".
  Scenario: Registration one below the minimum is rejected
    When a Stake of "one below the minimum stake" is submitted
    Then the stake transaction is not included within the next 2 blocks
    And the ownership account is not claimed
    And the config has no entry for the sequencer key
    And the config, funding and ownership accounts are unchanged

  @stake_registration_ci @P-03 @P0 @L3
  # The boundary is ≥ and genesis relies on it.
  Scenario: Registration at exactly the minimum is accepted
    When a Stake of "the minimum stake" is submitted
    Then the stake transaction is accepted
    And the config entry tracks the staked amount with no pending unstake

  @stake_registration_ci @P-04 @P0 @L3
  # In-program reason: "must sign for the ownership account".
  Scenario: Registration without the ownership account's signature is rejected
    When a Stake of "twice the minimum stake" is submitted without the ownership account's signature
    Then the stake transaction is not included within the next 2 blocks
    And the config, funding and ownership accounts are unchanged

  @stake_registration_ci @P-13 @P1 @L3
  # In-program reason: "not a sequencer_stake ownership account". Claiming is
  # implicit on data writes, so a plain transfer leaves its recipient
  # unowned; the token program claims the ownership account by writing a
  # token holding into it, which is the foreign owner the plan names.
  Scenario: Ownership account owned by another program is rejected
    Given the ownership account is already claimed by the token program
    When a Stake of "twice the minimum stake" is submitted
    Then the stake transaction is not included within the next 2 blocks
    And the config has no entry for the sequencer key
    And the config, funding and ownership accounts are unchanged

  @stake_registration_ci @P-14 @P0 @L3
  # In-program reason: "not the sequencer_stake config account". Mirrors
  # lez/sequencer/core/src/tests.rs::an_ownership_account_cannot_stand_in_for_the_config_account
  # for the Stake path: the stand-in is owned by sequencer_stake too, so only
  # the id check can reject it.
  Scenario: An ownership account cannot stand in for the config account
    Given a second sequencer key staked through its own ownership account
    When a Stake of "twice the minimum stake" is submitted with the second ownership account standing in for the config account
    Then the stake transaction is not included within the next 2 blocks
    And the ownership account is not claimed
    And the config, funding, ownership and second ownership accounts are unchanged

  @stake_registration_ci @P-25 @P0 @L3
  # In-program reason: "Sender has insufficient balance" — the mover call
  # itself fails, so the whole transaction is rejected atomically. The most
  # common real-world rejection on the stake-in walk.
  Scenario: Funding account holds less than the amount
    Given a funding account holding "one below the minimum stake"
    When a Stake of "the minimum stake" is submitted
    Then the stake transaction is not included within the next 2 blocks
    And the ownership account is not claimed
    And the config has no entry for the sequencer key
    And the config, funding and ownership accounts are unchanged

  @stake_registration_ci @P-18 @P0 @L3
  # In-program reason: "ConfirmStake can only be invoked as a self-chained
  # call". The expected balance matches the stake funds account, the account
  # ConfirmStake reads, and the caller check is the handler's first assert,
  # so it is the one that rejects. The ownership account signs because a
  # top-level transaction needs a signer and the funds PDA has no key.
  Scenario: ConfirmStake submitted top-level is rejected
    When a ConfirmStake matching the current funds balance is submitted as a top-level transaction
    Then the stake transaction is not included within the next 2 blocks
    And the config, funding and ownership accounts are unchanged

  @stake_registration_ci @P-20 @P2 @L3
  # In-program reason: "Stake requires a funding account, an ownership
  # account, the stake funds account, and the config account". The canonical
  # count is 4, so the examples sit one short of and one past it; a
  # 4-account list with a wrong funds slot is P-27, not this case.
  Scenario Outline: Wrong pre-state account count is rejected
    When a Stake of "the minimum stake" is submitted with <count> pre-state accounts
    Then the stake transaction is not included within the next 2 blocks
    And the config, funding and ownership accounts are unchanged

    Examples:
      | count |
      | 2     |
      | 5     |

  @stake_registration_ci @P-23 @P1 @L3
  # The plan expects a donation made before the first Stake to be absorbed
  # into the stake (expected_balance_after = donation + amount). Two dev
  # changes move the goalposts: a credit leaves a default-owned account
  # unowned (claiming is implicit on data writes only), so the donation lands
  # and the first Stake still claims the account; and the stake is custodied
  # in the funds PDA, so the donation stays on the ownership account and the
  # entry tracks only the staked amount. Revisit with the plan's §15.8
  # decision.
  Scenario: A donation to the unclaimed ownership account stays outside the first Stake
    When a donation of 25 to the unclaimed ownership account is submitted
    Then the donation transaction is accepted
    And the ownership account is not claimed
    And the ownership account balance increased by the donated amount
    And the config and funding accounts are unchanged
    When a Stake of "twice the minimum stake" is submitted
    Then the stake transaction is accepted
    And the config entry tracks the staked amount with no pending unstake
    And the ownership account is claimed by sequencer_stake backing the sequencer key with no pending unstake
    And the funds account balance increased by the staked amount
    And the ownership account balance is unchanged

  @stake_registration_ci @P-24 @P1 @L3
  # The borsh half mirrors sequencer_stake core's
  # a_non_curve_point_is_not_a_sequencer_key; the instruction half is
  # the 🆕 path of the plan: an off-curve Stake never reaches the handler
  # (the instruction decode panics inside the zkVM guest and surfaces as a
  # program-execution failure).
  Scenario: SequencerKey accepts only Ed25519 curve points
    Given 32 bytes that are not an Ed25519 curve point
    Then the bytes are not decodable as a SequencerKey
    And a StakeRecord carrying the bytes fails to decode
    And an Instruction carrying the bytes fails to deserialize
    When a Stake carrying the off-curve key bytes is submitted
    Then the stake transaction is not included within the next 2 blocks
    And the config, funding and ownership accounts are unchanged
