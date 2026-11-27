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
  # Message cases not yet covered here:
  # - P-17, P-19 need a guest that sends the Stake from another actor

  Background:
    Given a LEZ stack with fast blocks and configured public accounts
    And the sequencer_stake config account is at the default minimum stake
    And a sequencer key with no config entry
    And a default-owned, unclaimed ownership account for the sequencer key
    And a funding account holding "ten times the minimum stake"
    And chain waits give up after 60 blocks

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
