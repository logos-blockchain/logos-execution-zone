Feature: Stake account validation

  # Node-level (L3) coverage of the accounts a Stake declares: the ownership
  # account's stake actor it is delivered to, the stake funds PDA, the funding
  # account and the config account. The program checks that the ownership
  # account signed, and addresses the config account and the funds PDA
  # itself, so a transaction can only leave them undeclared, never substitute
  # them. Every scenario runs
  # against a deployed LEZ stack through the scenario wallet and the
  # sequencer's RPC API. The @P-NN tags are stable case ids.
  #
  # Rejection scenarios assert non-inclusion plus unchanged accounts; the
  # non-inclusion protocol and its two-block window are described in
  # sequencer_registration.feature.

  Background:
    Given a LEZ stack with fast blocks and configured public accounts
    And the sequencer_stake config account is at the default minimum stake
    And a sequencer key with no config entry
    And a fresh, unclaimed ownership account for the sequencer key
    And a funding account holding "ten times the minimum stake"
    And chain waits give up after 60 blocks

  @stake_accounts_ci @P-04 @P0 @L3
  # In-program reason: "must sign for the ownership account".
  Scenario: Registration without the ownership account's signature is rejected
    When a Stake of "twice the minimum stake" is submitted without the ownership account's signature
    Then the stake transaction is not included within the next 2 blocks
    And the config, funding and ownership accounts are unchanged

  @stake_accounts_ci @P-14 @P0 @L3
  # The Stake sends its record to the config account it derives, so a
  # stand-in, though owned by sequencer_stake too, leaves the real config
  # account undeclared and the transaction fails on it.
  Scenario: An ownership account cannot stand in for the config account
    Given a second sequencer key staked through its own ownership account
    When a Stake of "twice the minimum stake" is submitted with the second ownership account standing in for the config account
    Then the stake transaction is not included within the next 2 blocks
    And the ownership account is not claimed
    And the config, funding, ownership and second ownership accounts are unchanged

  @stake_accounts_ci @P-20 @P2 @L3
  # A Stake reaches all four declared accounts, so declaring only a prefix of
  # them leaves one it reaches undeclared. The examples sit one and two short
  # of the four; a longer list is not malformed, since an account the Stake
  # never reaches is merely unused.
  Scenario Outline: A Stake declaring too few accounts is rejected
    When a Stake of "the minimum stake" is submitted declaring only its first <count> accounts
    Then the stake transaction is not included within the next 2 blocks
    And the config, funding and ownership accounts are unchanged

    Examples:
      | count |
      | 2     |
      | 3     |
