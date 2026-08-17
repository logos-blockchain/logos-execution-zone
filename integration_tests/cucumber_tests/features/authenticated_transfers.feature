Feature: Authenticated transfers

  @auth_transfer_ci
  # Mirrors integration_tests/tests/auth_transfer/public.rs::successful_transfer_to_existing_account.
  # Coverage is equivalent for the transfer behavior and stronger for lifecycle coverage:
  # Cucumber also verifies indexer convergence and explicit runtime teardown. It uses balance
  # deltas instead of the legacy test's fixed 9900/20100 values.
  Scenario: Transfer funds between configured public accounts
    Given a LEZ stack with configured public accounts
    When I transfer 100 from the first configured public account to the second as "PUBLIC_TRANSFER"
    Then the sender balance for transfer "PUBLIC_TRANSFER" decreases by 100
    And the receiver balance for transfer "PUBLIC_TRANSFER" increases by 100
    And transfer "PUBLIC_TRANSFER" is included in a block within 120 seconds
    And only the sender signs transfer "PUBLIC_TRANSFER"
    And the indexer catches up to transfer "PUBLIC_TRANSFER" within 120 seconds
    Then I stop the runtime

  @auth_transfer_ci
  # Mirrors integration_tests/tests/auth_transfer/public.rs::failed_transfer_with_insufficient_balance.
  # Coverage is equivalent or stronger: it uses 10001 rather than 1_000_000, explicitly checks
  # block absence, and also verifies indexer convergence and explicit runtime teardown.
  Scenario: Reject a public transfer with insufficient sender balance
    Given a LEZ stack with configured public accounts
    When I attempt to transfer 10001 from the first configured public account to the second
    Then the transfer is rejected
    And no transfer is included in a block
    And the sender balance remains unchanged
    And the receiver balance remains unchanged
    And the indexer catches up to the sequencer within 120 seconds
    Then I stop the runtime

  @auth_transfer_ci
  # Mirrors integration_tests/tests/auth_transfer/public.rs::two_consecutive_successful_transfers.
  # Coverage is equivalent for the final balances and nonce progression, with additional checks
  # for both inclusions, sender-only signatures, indexer convergence, and runtime teardown. It
  # does not retain the legacy test's intermediate balance checkpoint after the first transfer.
  Scenario: Execute two consecutive transfers between configured public accounts
    Given a LEZ stack with configured public accounts
    When I transfer 100 from the first configured public account to the second as "FIRST_TRANSFER"
    And I transfer 100 from the first configured public account to the second as "SECOND_TRANSFER"
    Then the sender balance across transfers "FIRST_TRANSFER" and "SECOND_TRANSFER" decreases by 200
    And the receiver balance across transfers "FIRST_TRANSFER" and "SECOND_TRANSFER" increases by 200
    And transfer "FIRST_TRANSFER" is included in a block within 120 seconds
    And transfer "SECOND_TRANSFER" is included in a block within 120 seconds
    And only the sender signs transfer "FIRST_TRANSFER"
    And only the sender signs transfer "SECOND_TRANSFER"
    And the sender nonce advances across transfers "FIRST_TRANSFER" and "SECOND_TRANSFER"
    And the indexer catches up to transfer "SECOND_TRANSFER" within 120 seconds
    Then I stop the runtime

  @auth_transfer_ci
  # Mirrors integration_tests/tests/auth_transfer/public.rs::successful_transfer_to_new_account.
  # Coverage is equivalent for funding a previously absent public account. Cucumber additionally
  # verifies the recipient is absent before submission, transaction inclusion, both required
  # signatures, indexer convergence, and explicit runtime teardown.
  Scenario: Transfer funds to a new public account
    Given a LEZ stack with configured public accounts
    And a new public account
    When I transfer 100 from the first configured public account to the new account as "NEW_ACCOUNT_TRANSFER"
    Then the sender balance for transfer "NEW_ACCOUNT_TRANSFER" decreases by 100
    And the new account balance for transfer "NEW_ACCOUNT_TRANSFER" is 100
    And transfer "NEW_ACCOUNT_TRANSFER" is included in a block within 120 seconds
    And the sender and new account sign transfer "NEW_ACCOUNT_TRANSFER"
    And the indexer catches up to transfer "NEW_ACCOUNT_TRANSFER" within 120 seconds
    Then I stop the runtime

  @auth_transfer_ci
  # Mirrors integration_tests/tests/auth_transfer/private.rs::private_transfer_to_owned_account.
  # Coverage preserves the post-transfer commitment checks and additionally verifies private
  # balances, transaction inclusion, indexer convergence, and explicit runtime teardown.
  Scenario: Transfer funds between configured private accounts
    Given a LEZ stack with configured private accounts
    When I transfer 100 from the first configured private account to the second as "PRIVATE_TRANSFER"
    Then the sender private balance for transfer "PRIVATE_TRANSFER" decreases by 100
    And the receiver private balance for transfer "PRIVATE_TRANSFER" increases by 100
    And the sender private commitment for transfer "PRIVATE_TRANSFER" is in sequencer state
    And the receiver private commitment for transfer "PRIVATE_TRANSFER" is in sequencer state
    And transfer "PRIVATE_TRANSFER" is included in a block within 120 seconds
    And the indexer catches up to transfer "PRIVATE_TRANSFER" within 120 seconds
    Then I stop the runtime
