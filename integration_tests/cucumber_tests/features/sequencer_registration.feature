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
  #   past that tip guarantee a post-admission pull tried the transaction
  # Should the node ever gain a transaction status API (pending, included, or
  # dropped with a reason), replace the two-block window with it.
  #
  Background:
    Given a LEZ stack with fast blocks and configured public accounts
    And the sequencer_stake config account is at the default minimum stake
    And a sequencer key with no config entry
    And a default-owned, unclaimed ownership account for the sequencer key
    And a funding account holding "ten times the minimum stake"

  @stake_registration_ci @P-01 @P0 @L3
  # Mirrors the registration leg of tests/sequencer_stake_demo.rs,
  # additionally asserting the config entry and both balance deltas.
  Scenario: Happy-path registration through authenticated_transfer
    When a Stake of "twice the minimum stake" is submitted
    Then the stake transaction is accepted
    And the config entry tracks the staked amount with no pending unstake
    And the config entry points at the ownership account
    And the ownership account is claimed by sequencer_stake backing the sequencer key with no pending unstake
    And the ownership account balance increased by the staked amount
    And the funding account balance decreased by the staked amount

  @stake_registration_ci @P-02 @P0 @L3
  # In-program reason: "an initial stake must already meet the minimum".
  Scenario: Registration one below the minimum is rejected
    When a Stake of "one below the minimum stake" is submitted
    Then the stake transaction is not included in a block
    And the ownership account is not claimed
    And the config has no entry for the sequencer key
    And the stake accounts are unchanged

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
    Then the stake transaction is not included in a block
    And the stake accounts are unchanged

  @stake_registration_ci @P-13 @P1 @L3
  # In-program reason: "not a sequencer_stake ownership account". The plan
  # names the token program as the foreign owner; at node level the only
  # foreign owner reachable through deployed programs is
  # authenticated_transfer, which claims a default-owned recipient on a
  # signed transfer. The guest's owner check rejects both the same way.
  Scenario: Ownership account owned by another program is rejected
    Given the ownership account is already claimed by the authenticated_transfer program
    When a Stake of "twice the minimum stake" is submitted
    Then the stake transaction is not included in a block
    And the config has no entry for the sequencer key
    And the stake accounts are unchanged

  @stake_registration_ci @P-14 @P0 @L3
  # In-program reason: "not the sequencer_stake config account". Mirrors
  # lez/sequencer/core/src/tests.rs::an_ownership_account_cannot_stand_in_for_the_config_account
  # for the Stake path: the stand-in is owned by sequencer_stake too, so only
  # the id check can reject it.
  Scenario: An ownership account cannot stand in for the config account
    Given a second sequencer key staked through its own ownership account
    When a Stake of "twice the minimum stake" is submitted with the second ownership account standing in for the config account
    Then the stake transaction is not included in a block
    And the ownership account is not claimed
    And the stake accounts are unchanged

  @stake_registration_ci @P-15 @P0 @L3
  # No bad-mover guest needed: the mover instruction data is caller-controlled
  # and opaque to sequencer_stake, so authenticated_transfer itself plays the
  # bad mover when told to move one coin less than the Stake declares. The
  # runtime rejects the chained ConfirmStake's declared pre-state against the
  # actual post-mover balance (InconsistentAccountPreState) before the
  # in-guest equality assert can fire.
  Scenario: Mover deposits less than the requested amount
    When a Stake of "twice the minimum stake" is submitted with the mover told to deposit one coin less
    Then the stake transaction is not included in a block
    And the ownership account is not claimed
    And the config has no entry for the sequencer key
    And the stake accounts are unchanged

  @stake_registration_ci @P-16 @P0 @L3
  # The balance equality check is two-sided: a surplus cannot be smuggled into
  # total_staked. Same mechanism as P-15, with authenticated_transfer told to
  # move one coin more than the Stake declares.
  Scenario: Mover deposits more than the requested amount
    When a Stake of "twice the minimum stake" is submitted with the mover told to deposit one coin more
    Then the stake transaction is not included in a block
    And the ownership account is not claimed
    And the config has no entry for the sequencer key
    And the stake accounts are unchanged

  @stake_registration_ci @P-25 @P0 @L3
  # In-program reason: "Sender has insufficient balance" — the mover call
  # itself fails, so the whole transaction is rejected atomically. The most
  # common real-world rejection on the stake-in walk.
  Scenario: Funding account holds less than the amount
    Given a funding account holding "one below the minimum stake"
    When a Stake of "the minimum stake" is submitted
    Then the stake transaction is not included in a block
    And the ownership account is not claimed
    And the config has no entry for the sequencer key
    And the stake accounts are unchanged

  @stake_registration_ci @P-18 @P0 @L3
  # In-program reason: "ConfirmStake can only be invoked as a self-chained
  # call". The ownership balance already matches the expected post-balance,
  # so the caller check is the only assert that can reject it.
  Scenario: ConfirmStake submitted top-level is rejected
    When a ConfirmStake matching the current ownership balance is submitted as a top-level transaction
    Then the stake transaction is not included in a block
    And the stake accounts are unchanged

  @stake_registration_ci @P-17 @P1 @L3
  # In-program reason: "Stake is only invoked as a top-level user
  # transaction". The stake_chain_caller test program (deployed at runtime)
  # forwards an otherwise well-formed Stake into sequencer_stake as a chained
  # call, so the caller-is-none guard is the only assert that can reject it.
  Scenario: Stake invoked as a chained call is rejected
    Given the stake_chain_caller test program is deployed
    When a Stake of "twice the minimum stake" is submitted as a chained call through the stake_chain_caller program
    Then the stake transaction is not included in a block
    And the ownership account is not claimed
    And the config has no entry for the sequencer key
    And the stake accounts are unchanged

  @stake_registration_ci @P-19 @P1 @L3
  # In-program reason: "ConfirmStake can only be invoked as a self-chained
  # call". The chained mirror of P-18: the stake_chain_caller test program
  # (deployed at runtime) forwards a ConfirmStake whose expected balance
  # matches the current ownership balance, so the caller check — the caller
  # is stake_chain_caller, not sequencer_stake — is the only assert that can
  # reject it.
  Scenario: ConfirmStake chained from a different program is rejected
    Given the stake_chain_caller test program is deployed
    When a ConfirmStake matching the current ownership balance is submitted as a chained call through the stake_chain_caller program
    Then the stake transaction is not included in a block
    And the stake accounts are unchanged

  @stake_registration_ci @P-20 @P2 @L3
  # In-program reason: "Stake requires a funding account, an ownership
  # account, and the config account".
  Scenario Outline: Wrong pre-state account count is rejected
    When a Stake of "the minimum stake" is submitted with <count> pre-state accounts
    Then the stake transaction is not included in a block
    And the stake accounts are unchanged

    Examples:
      | count |
      | 2     |
      | 4     |

  @stake_registration_ci @P-21 @P2 @L3
  # Stake is generic over its mover. The simple_balance_transfer test program
  # (deployed at runtime) is a native two-account transfer distinct from
  # authenticated_transfer; the funding account is claimed under it so it may
  # debit it.
  Scenario: Registration through a second mover program is accepted
    Given the simple_balance_transfer test program is deployed
    And a funding account owned by the simple_balance_transfer program holding "twice the minimum stake"
    When a Stake of "twice the minimum stake" is submitted with simple_balance_transfer as the mover
    Then the stake transaction is accepted
    And the config entry tracks the staked amount with no pending unstake
    And the ownership account balance increased by the staked amount
    And the funding account balance decreased by the staked amount

  @stake_registration_ci @P-23 @P1 @L3
  # ⚠️ Diverges further from the plan than the earlier L1 port did. The plan
  # expects acceptance with expected_balance_after = donation + amount; at L1
  # the runtime instead rejected the Stake because the donation had made the
  # unclaimed ownership account non-default (validate_execution rule 6). At
  # node level even the donated pre-state is unreachable: claiming a
  # default-owned recipient needs the recipient's signature, so a plain
  # transfer at an unclaimed account is itself dropped
  # (ClaimedUnauthorizedAccount) and the account stays fresh. This scenario
  # pins that behaviour and shows registration is unaffected afterwards.
  # Revisit with the plan's §12 decisions.
  Scenario: A donation cannot reach an unclaimed ownership account before the first Stake
    When a donation of 25 to the unclaimed ownership account is submitted
    Then the donation transaction is not included in a block
    And the ownership account is not claimed
    And the stake accounts are unchanged
    When a Stake of "twice the minimum stake" is submitted
    Then the stake transaction is accepted
    And the ownership account balance increased by the staked amount

  @stake_registration_ci @P-24 @P1 @L3
  # The borsh half mirrors sequencer_stake core's
  # a_non_curve_point_is_not_a_sequencer_key; the serde/instruction half is
  # the 🆕 path of the plan: an off-curve Stake never reaches the handler
  # (the instruction decode panics inside the zkVM guest and surfaces as a
  # program-execution failure).
  Scenario: SequencerKey accepts only Ed25519 curve points
    Given 32 bytes that are not an Ed25519 curve point
    Then the bytes are not decodable as a SequencerKey
    And a StakeRecord carrying the bytes fails to decode
    And an Instruction carrying the bytes fails to deserialize
    When a Stake carrying the off-curve key bytes is submitted
    Then the stake transaction is not included in a block
    And the stake accounts are unchanged

  @stake_registration_ci @P-26 @P1 @L3
  # The registration mirror of the plan's simultaneous-exit cases (M-04,
  # M-07): both Stakes are admitted before either is included, so one builder
  # pull tries both in the same block build and both write the shared config
  # account. Pins that neither write is lost and neither transaction is
  # dropped — a builder drop would be final, since dropped transactions are
  # not requeued. The two signing pairs are disjoint, so the submissions do
  # not couple through any account's nonce.
  Scenario: Two keys register through the shared config account at the same time
    Given a second sequencer key with its own unclaimed ownership account and a funding account holding "ten times the minimum stake"
    When a Stake of "twice the minimum stake" is submitted for each sequencer key back-to-back
    Then both stake transactions are accepted
    And the config holds an entry for each sequencer key pointing at its own ownership account
    And each ownership account is claimed by sequencer_stake backing its sequencer key
    And each stake moved the staked amount from its funding account to its ownership account

  @stake_registration_ci @D-15 @P1 @L3
  # Node-level mirror of committee_discovery's two_new_keys_join_in_one_update:
  # both Stakes ride one block, finalize together and qualify in the same
  # discovery window, so a single ChannelConfigOp admits both keys — observed
  # through Bedrock channel state, where no poll may catch one key accredited
  # without the other. In the rare race where the Stakes land in different
  # blocks, split updates are legitimate and only the eventual outcome is
  # asserted.
  Scenario: Two simultaneous registrations enter the live committee in one update
    Given a second sequencer key with its own unclaimed ownership account and a funding account holding "ten times the minimum stake"
    When a Stake of "twice the minimum stake" is submitted for each sequencer key back-to-back
    Then both stake transactions are accepted
    And both sequencer keys join the live committee together
