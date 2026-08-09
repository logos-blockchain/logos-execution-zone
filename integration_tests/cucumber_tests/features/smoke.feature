Feature: LEZ integration environment

  @smoke_ci
  Scenario: LEZ smoke stack exposes its configured public account
    Given a LEZ smoke stack
    When I query the balance of the first configured public account
    Then its balance matches the configured initial balance
    And the indexer catches up to the sequencer
    Then I stop the runtime

  @smoke_ci
  Scenario: LEZ private smoke stack initializes its configured private account
    Given a LEZ private smoke stack
    When I query the balance of the first configured private account
    Then its balance matches the configured initial balance
    And the indexer catches up to the sequencer
    Then I stop the runtime
