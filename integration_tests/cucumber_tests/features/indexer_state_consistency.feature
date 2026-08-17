Feature: LEZ indexer state consistency

  @indexer_state_ci
  # Mirrors the public-transfer and public-indexer-state portion of
  # integration_tests/tests/indexer_state_consistency.rs::indexer_state_consistency.
  # This is intentionally not a complete replacement: the legacy test also performs a
  # private transfer, whose indexer transition remains outside this Cucumber scenario.
  # Cucumber additionally uses transaction-anchored convergence, relative balance deltas,
  # and explicit runtime teardown.
  Scenario: Public indexer state remains consistent after a transfer
    Given a LEZ stack with configured public accounts
    When I transfer 100 from the first configured public account to the second as "INDEXER_TRANSFER"
    Then the sender balance for transfer "INDEXER_TRANSFER" decreases by 100
    And the receiver balance for transfer "INDEXER_TRANSFER" increases by 100
    And transfer "INDEXER_TRANSFER" is included in a block within 120 seconds
    And the indexer catches up to transfer "INDEXER_TRANSFER" within 120 seconds
    Then the transferred public account states for transfer "INDEXER_TRANSFER" match between the sequencer and indexer
    Then I stop the runtime

  @indexer_state_ci
  # Mirrors integration_tests/tests/indexer_state_consistency_with_labels.rs::indexer_state_consistency_with_labels.
  # Coverage is equivalent for label resolution, the public balance movement, and the
  # sequencer/indexer state comparison. Cucumber additionally verifies transaction
  # inclusion, transaction-anchored convergence, and explicit runtime teardown, while
  # expressing the balance assertion as a relative delta.
  Scenario: Indexer state remains consistent after a label-based transfer
    Given a LEZ stack with configured public accounts
    And the configured public accounts have sender label "idx-sender-label" and receiver label "idx-receiver-label"
    When I transfer 100 using the configured public account labels as "LABEL_TRANSFER"
    Then the sender balance for transfer "LABEL_TRANSFER" decreases by 100
    And the receiver balance for transfer "LABEL_TRANSFER" increases by 100
    And transfer "LABEL_TRANSFER" is included in a block within 120 seconds
    And the indexer catches up to transfer "LABEL_TRANSFER" within 120 seconds
    Then the transferred public account states for transfer "LABEL_TRANSFER" match between the sequencer and indexer
    Then I stop the runtime
