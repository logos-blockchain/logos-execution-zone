Feature: Stake account validation

  # Node-level (L3) coverage of the pre-state account list a Stake names:
  # [funding, ownership, funds, config]. The program checks who signed, who
  # owns the ownership account, that the config slot holds the real config
  # account, and that the list has exactly four entries. Every scenario runs
  # against a deployed LEZ stack through the scenario wallet and the
  # sequencer's RPC API. The @P-NN tags are stable case ids.
  #
  # Rejection scenarios assert non-inclusion plus unchanged accounts; the
  # non-inclusion protocol and its two-block window are described in
  # sequencer_registration.feature.
  #
  # Account cases not yet covered here:
  # - P-21 needs a second mover program fitting Stake's two-account slot

  Background:
    Given a LEZ stack with fast blocks and configured public accounts
    And the sequencer_stake config account is at the default minimum stake
    And a sequencer key with no config entry
    And a default-owned, unclaimed ownership account for the sequencer key
    And a funding account holding "ten times the minimum stake"
    And chain waits give up after 60 blocks

  @stake_accounts_ci @P-04 @P0 @L3
  # In-program reason: "must sign for the ownership account".
  Scenario: Registration without the ownership account's signature is rejected
    When a Stake of "twice the minimum stake" is submitted without the ownership account's signature
    Then the stake transaction is not included within the next 2 blocks
    And the config, funding and ownership accounts are unchanged

  @stake_accounts_ci @P-13 @P1 @L3
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

  @stake_accounts_ci @P-14 @P0 @L3
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

  @stake_accounts_ci @P-20 @P2 @L3
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
