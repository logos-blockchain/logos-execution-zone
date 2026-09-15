Feature: Stake instruction validation

  # Node-level (L3) coverage of the instruction itself rather than the amount
  # or the accounts: the bytes a Stake carries and the call path an
  # instruction may arrive on. Every scenario runs against a deployed LEZ
  # stack through the scenario wallet and the sequencer's RPC API. The @P-NN
  # tags are stable case ids.
  #
  # Rejection scenarios assert non-inclusion plus unchanged accounts; the
  # non-inclusion protocol and its two-block window are described in
  # sequencer_registration.feature.
  #
  # P-17 and P-19 deploy a test program at runtime through program_loader,
  # since test guests are not in the node's compiled-in program set. A deployed
  # program is addressed by the header account its deployment claims, not by
  # its image id.

  Background:
    Given a LEZ stack with fast blocks and configured public accounts
    And the sequencer_stake config account is at the default minimum stake
    And a sequencer key with no config entry
    And a default-owned, unclaimed ownership account for the sequencer key
    And a funding account holding "ten times the minimum stake"
    And chain waits give up after 60 blocks

  @stake_instruction_ci @P-15 @P0 @L3
  # No bad-mover guest needed: the mover instruction data is caller-controlled
  # and opaque to sequencer_stake, so authenticated_transfer itself plays the
  # bad mover when told to move one coin less than the Stake declares. The
  # runtime hands the chained ConfirmStake the funds account as the mover left
  # it, so the in-program balance equality assert is what rejects: "mover call
  # did not deposit the expected amount into the stake funds account".
  Scenario: Mover deposits less than the requested amount
    When a Stake of "twice the minimum stake" is submitted with the mover told to deposit one coin less
    Then the stake transaction is not included within the next 2 blocks
    And the ownership account is not claimed
    And the config has no entry for the sequencer key
    And the config, funding and ownership accounts are unchanged

  @stake_instruction_ci @P-16 @P0 @L3
  # The balance equality check is two-sided: a surplus cannot be smuggled into
  # total_staked. Same mechanism as P-15, with authenticated_transfer told to
  # move one coin more than the Stake declares.
  Scenario: Mover deposits more than the requested amount
    When a Stake of "twice the minimum stake" is submitted with the mover told to deposit one coin more
    Then the stake transaction is not included within the next 2 blocks
    And the ownership account is not claimed
    And the config has no entry for the sequencer key
    And the config, funding and ownership accounts are unchanged

  @stake_instruction_ci @P-18 @P0 @L3
  # In-program reason: "ConfirmStake can only be invoked as a self-chained
  # call". The expected balance matches the stake funds account, the account
  # ConfirmStake reads, and the caller check is the handler's first assert,
  # so it is the one that rejects. The ownership account signs because a
  # top-level transaction needs a signer and the funds PDA has no key.
  Scenario: ConfirmStake submitted top-level is rejected
    When a ConfirmStake matching the current funds balance is submitted as a top-level transaction
    Then the stake transaction is not included within the next 2 blocks
    And the config, funding and ownership accounts are unchanged

  @stake_instruction_ci @P-17 @P1 @L3
  # In-program reason: "Stake is only invoked as a top-level user
  # transaction". The stake_chain_caller test program forwards an otherwise
  # well-formed Stake into sequencer_stake as a chained call, so the
  # caller-is-none guard is the only assert that can reject it.
  #
  # Unlike the other rejection scenarios, the top-level transaction targets the
  # test program, not sequencer_stake, so it is fee-charged rather than exempt.
  # A charged transaction whose execution fails is not dropped: it is included
  # with its fee kept and its effects reverted, advancing only the signers'
  # nonces. The rejection therefore shows as inclusion with no state change
  # apart from those nonces. A genesis supply account pays the fee, so the
  # funding account's balance stays put; the funds and config accounts do not
  # sign, so they are unchanged outright.
  Scenario: Stake invoked as a chained call is rejected
    Given the stake_chain_caller test program is deployed
    When a Stake of "twice the minimum stake" is submitted as a chained call through the stake_chain_caller program
    Then the stake transaction is included in a block
    And the ownership account is not claimed
    And the config has no entry for the sequencer key
    And the config and funds accounts are unchanged
    And the funding account balance is unchanged
    And the ownership account balance is unchanged

  @stake_instruction_ci @P-19 @P1 @L3
  # In-program reason: "ConfirmStake can only be invoked as a self-chained
  # call". The chained mirror of P-18: the stake_chain_caller test program
  # forwards a ConfirmStake whose expected balance matches the stake funds
  # account, so the caller check, the caller being stake_chain_caller rather
  # than sequencer_stake, is the only assert that can reject it.
  #
  # As in P-17 the top-level transaction targets the test program, so it is
  # fee-charged and its failure shows as inclusion with reverted effects: a
  # genesis supply account pays the fee and the signing ownership account
  # advances only its nonce.
  Scenario: ConfirmStake chained from a different program is rejected
    Given the stake_chain_caller test program is deployed
    When a ConfirmStake matching the current funds balance is submitted as a chained call through the stake_chain_caller program
    Then the stake transaction is included in a block
    And the ownership account is not claimed
    And the config has no entry for the sequencer key
    And the config, funding and funds accounts are unchanged
    And the ownership account balance is unchanged

  @stake_instruction_ci @P-24 @P1 @L3
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
