Feature: Authenticated transfers

  @auth_transfer_ci
  # Mirrors integration_tests/tests/auth_transfer/public.rs::successful_transfer_to_existing_account.
  # Coverage is equivalent for the transfer behavior and stronger for lifecycle coverage:
  # Cucumber also verifies indexer convergence and explicit runtime teardown. It uses balance
  # deltas instead of the legacy test's fixed 9900/20100 values.
  Scenario: Transfer funds between configured public accounts
    Given a LEZ stack with configured accounts
    When I transfer 100 from the first configured public account to the second
    Then the sender balance decreases by 100
    And the receiver balance increases by 100
    And the transfer is included in a block
    And only the sender signs the transfer
    And the indexer catches up to the sequencer
    Then I stop the runtime

  @auth_transfer_ci
  # Mirrors integration_tests/tests/auth_transfer/public.rs::failed_transfer_with_insufficient_balance.
  # Coverage is equivalent or stronger: it uses 10001 rather than 1_000_000, explicitly checks
  # block absence, and also verifies indexer convergence and explicit runtime teardown.
  Scenario: Reject a public transfer with insufficient sender balance
    Given a LEZ stack with configured accounts
    When I attempt to transfer 10001 from the first configured public account to the second
    Then the transfer is rejected
    And no transfer is included in a block
    And the sender balance remains unchanged
    And the receiver balance remains unchanged
    And the indexer catches up to the sequencer
    Then I stop the runtime

  @auth_transfer_ci
  # Mirrors integration_tests/tests/auth_transfer/public.rs::two_consecutive_successful_transfers.
  # Coverage is equivalent for the final balances and nonce progression, with additional checks
  # for both inclusions, sender-only signatures, indexer convergence, and runtime teardown. It
  # does not retain the legacy test's intermediate balance checkpoint after the first transfer.
  Scenario: Execute two consecutive transfers between configured public accounts
    Given a LEZ stack with configured accounts
    When I transfer 100 from the first configured public account to the second
    And I transfer another 100 from the first configured public account to the second
    Then the sender balance decreases by 200
    And the receiver balance increases by 200
    And both transfers are included in blocks
    And only the sender signs both transfers
    And the sender nonce advances across both transfers
    And the indexer catches up to the sequencer
    Then I stop the runtime
