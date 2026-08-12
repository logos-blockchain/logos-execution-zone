Feature: LEZ indexer state consistency

  @indexer_state_ci
  Scenario: Public indexer state remains consistent after a transfer
    Given a LEZ stack with configured public accounts
    When I transfer 100 from the first configured public account to the second
    Then the sender balance decreases by 100
    And the receiver balance increases by 100
    And the transfer is included in a block
    And the indexer catches up to the sequencer within 360 seconds
    Then the transferred public account states match between the sequencer and indexer
    Then I stop the runtime

  @indexer_state_ci
  Scenario: Indexer state remains consistent after a label-based transfer
    Given a LEZ stack with configured public accounts
    And the configured public accounts have sender label "idx-sender-label" and receiver label "idx-receiver-label"
    When I transfer 100 using the configured public account labels
    Then the sender balance decreases by 100
    And the receiver balance increases by 100
    And the transfer is included in a block
    And the indexer catches up to the sequencer within 360 seconds
    Then the transferred public account states match between the sequencer and indexer
    Then I stop the runtime
