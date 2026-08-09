Feature: Authenticated transfers

  @auth_transfer_ci
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
