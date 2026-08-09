Feature: Authenticated transfers

  @auth_transfer
  Scenario: Transfer funds between configured public accounts
    Given a LEZ stack with configured accounts
    When I transfer 100 from the first configured public account to the second
    Then the sender balance decreases by 100
    And the receiver balance increases by 100
    And the transfer is included in a block
    And only the sender signs the transfer
    And the indexer catches up to the sequencer
    Then I stop the runtime
