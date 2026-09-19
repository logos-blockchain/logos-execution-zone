Feature: Sequencer registration

  # Node-level (L3) coverage of the amount a first Stake moves: the happy
  # path, the minimum-stake boundary from both sides, a funding account that
  # cannot cover the amount, and a donation that reaches the ownership
  # account before the first Stake. Every scenario runs against a deployed
  # LEZ stack: transactions are signed and submitted through the scenario
  # wallet, executed by the real sequencer, and every assertion reads state
  # back through the sequencer's RPC API. The @P-NN tags are stable case ids.
  #
  # The account list a Stake names is covered by stake_account_validation.feature
  # and the instruction bytes and call path by stake_instruction_validation.feature.
  #
  # Rejection semantics at node level: an invalid transaction is admitted to
  # the mempool and only fails during block building, where the builder drops
  # it from the block without surfacing the in-program rejection reason
  # through any API. Rejection scenarios therefore assert non-inclusion plus
  # unchanged accounts; the expected in-program reason is kept as a comment
  # on each scenario and stays pinned by sequencer_core's unit tests.
  #
  # Non-inclusion alone is not evidence of a rejection: a transaction the
  # builder accepted into a candidate block whose publish then failed is also
  # in no block for ever, since a failed turn does not requeue what it popped,
  # and later turns move the chain on regardless. The non-inclusion step
  # therefore submits a canary, a plain transfer signed by the second genesis
  # supply account, right behind the transaction under test, and asserts the
  # canary landed in a block within the named window. That rests on two node
  # properties that no API documents or pins:
  # - mempool admission is synchronous with the send RPC reply, so a tip read
  #   after submission is at or past the admission point, and the canary is
  #   admitted behind the transaction under test
  # - the block builder pulls the whole mempool on every turn, in admission
  #   order, so the turn that pulled the canary had pulled the transaction
  #   under test; the canary landing proves that turn published, and two
  #   blocks past the tip bound where it lands, the "within the next 2 blocks"
  #   window each rejection step names
  # A canary that lands later, or never, fails the step instead of letting a
  # failed turn pass as a rejection. One gap stays open: a turn that starts
  # between the two admissions, pulls only the transaction under test and
  # then fails to publish. With a two-second block cadence that needs the turn
  # to begin inside the milliseconds between the two sends, and the RPC API
  # exposes nothing that would close it. Should the node ever gain a
  # transaction status API (pending, included, or dropped with a reason),
  # replace the canary with it.
  #
  # Registration cases not yet covered here:
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
