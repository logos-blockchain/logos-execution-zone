Feature: LEZ multi-sequencer committee convergence

  @multi_sequencer_ci
  Scenario: A live committee reconfiguration converges across sequencers and the indexer
    Given a LEZ multi-sequencer environment with 1 validator and 0 Blend nodes
    And the following LEZ sequencers are registered
      | alias  | signing_key |
      | SEQ_A  | 0xA1        |
      | SEQ_B  | 0xB2        |
    When I start sequencer "SEQ_A"
    And sequencer "SEQ_A" reaches block 2 within 120 seconds
    When sequencer "SEQ_A" configures the committee
      | posting_timeframe | posting_timeout | withdraw_threshold | deposit_threshold | authorized_sequencers |
      | 20                | 30              | 1                  | 1                  | SEQ_A, SEQ_B         |
    And sequencer "SEQ_A" advances after the committee reconfiguration within 120 seconds
    And I start sequencer "SEQ_B"
    And sequencer "SEQ_B" synchronizes to sequencer "SEQ_A" within 120 seconds
    When sequencers "SEQ_A" and "SEQ_B" advance across 8 rotation blocks within 120 seconds
    Then sequencers "SEQ_A" and "SEQ_B" have identical common block hashes
    When I record deterministic public account 1 balance on sequencer "SEQ_A"
    When I submit 10 from deterministic public account 0 to account 1 through sequencer "SEQ_B" as "COMMITTEE_TRANSFER"
    Then transfer "COMMITTEE_TRANSFER" is included in a block on sequencer "SEQ_B" within 120 seconds
    Then sequencer "SEQ_A" observes the receiver balance increase by 10 within 120 seconds
    And the indexer finalizes transfer "COMMITTEE_TRANSFER" on the committee chain within 120 seconds
    Then finalized indexer blocks match sequencer "SEQ_A"
    And the indexer is not stalled
    Then I stop the runtime
