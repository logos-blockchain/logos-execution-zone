Feature: LEZ indexer state consistency

  @indexer_state_ci
  Scenario: Public indexer state remains consistent after a transfer
    Given a LEZ stack with configured public accounts
    When I transfer 100 from the first configured public account to the second as "INDEXER_TRANSFER"
    Then the sender balance for transfer "INDEXER_TRANSFER" decreases by 100
    And the receiver balance for transfer "INDEXER_TRANSFER" increases by 100
    And transfer "INDEXER_TRANSFER" is included in a block
    And the indexer catches up to transfer "INDEXER_TRANSFER" within 120 seconds
    Then the transferred public account states for transfer "INDEXER_TRANSFER" match between the sequencer and indexer
    Then I stop the runtime

  @indexer_state_ci
  Scenario: Indexer state remains consistent after a label-based transfer
    Given a LEZ stack with configured public accounts
    And the configured public accounts have sender label "idx-sender-label" and receiver label "idx-receiver-label"
    When I transfer 100 using the configured public account labels as "LABEL_TRANSFER"
    Then the sender balance for transfer "LABEL_TRANSFER" decreases by 100
    And the receiver balance for transfer "LABEL_TRANSFER" increases by 100
    And transfer "LABEL_TRANSFER" is included in a block
    And the indexer catches up to transfer "LABEL_TRANSFER" within 120 seconds
    Then the transferred public account states for transfer "LABEL_TRANSFER" match between the sequencer and indexer
    Then I stop the runtime
