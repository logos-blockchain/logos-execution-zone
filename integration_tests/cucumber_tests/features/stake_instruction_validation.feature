Feature: Stake instruction validation

  # Node-level (L3) coverage of the message itself rather than the amount
  # or the accounts: the bytes a Stake carries and the call path a
  # message may arrive on. Every scenario runs against a deployed LEZ
  # stack through the scenario wallet and the sequencer's RPC API. The @P-NN
  # tags are stable case ids.
  #
  # Rejection scenarios assert non-inclusion plus unchanged accounts; the
  # non-inclusion protocol and its two-block window are described in
  # sequencer_registration.feature.
  #
  # P-17 deploys a test program at runtime through program_loader, since test
  # guests are not in the node's compiled-in program set. A deployed program is
  # addressed by the header account its deployment claims, not by its image id.
  #
  # P-19 (a ConfirmStake sent from another program) has no target any more:
  # Stake moves the funds natively and ConfirmStake is gone from the program.

  Background:
    Given a LEZ stack with fast blocks and configured public accounts
    And the sequencer_stake config account is at the default minimum stake
    And a sequencer key with no config entry
    And a fresh, unclaimed ownership account for the sequencer key
    And a funding account holding "ten times the minimum stake"
    And chain waits give up after 60 blocks

  @stake_instruction_ci @P-17 @P1 @L3
  # In-program reason: "Stake is only invoked as a top-level user
  # transaction". The scripted test program relays an otherwise well-formed
  # Stake to the ownership account's sequencer_stake actor, which sees the
  # relay, not the transaction, as its sender, so the root-origin guard is the
  # only assert that can reject it.
  #
  # Unlike the other rejection scenarios, the transaction is delivered to the
  # test program, not sequencer_stake, so it is fee-charged rather than exempt.
  # A charged transaction whose execution fails is not dropped: it is included
  # with its fee kept and its effects reverted, advancing only the signers'
  # nonces. The rejection therefore shows as inclusion with no state change
  # apart from those nonces. A genesis supply account pays the fee, so the
  # funding account's balance stays put; the funds and config accounts do not
  # sign, so they are unchanged outright.
  Scenario: Stake sent from another actor is rejected
    Given the scripted test program is deployed
    When a Stake of "twice the minimum stake" is sent from the scripted test program
    Then the stake transaction is included in a block
    And the ownership account is not claimed
    And the config has no entry for the sequencer key
    And the config and funds accounts are unchanged
    And the funding account balance is unchanged
    And the ownership account balance is unchanged

  @stake_instruction_ci @P-24 @P1 @L3
  # The borsh half mirrors sequencer_stake core's
  # a_non_curve_point_is_not_a_sequencer_key; the message half is
  # the 🆕 path of the plan: an off-curve Stake never reaches the handler
  # (the message decode panics inside the zkVM guest and surfaces as a
  # program-execution failure).
  Scenario: SequencerKey accepts only Ed25519 curve points
    Given 32 bytes that are not an Ed25519 curve point
    Then the bytes are not decodable as a SequencerKey
    And a StakeRecord carrying the bytes fails to decode
    And a Stake message carrying the bytes fails to deserialize
    When a Stake carrying the off-curve key bytes is submitted
    Then the stake transaction is not included within the next 2 blocks
    And the config, funding and ownership accounts are unchanged
