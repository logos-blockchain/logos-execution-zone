Feature: LEZ multi-sequencer committee convergence

  @multi_sequencer_ci
# Mirrors the committee convergence, cross-sequencer transfer, and indexer checks in
# integration_tests/tests/multi_sequencer.rs::multi_sequencer_committee_converges.
# Cucumber preserves the legacy lifecycle: configured committee members are staked in
# shared genesis, A creates the channel, B joins later, and the scenario waits for B's
# posting turn. Cucumber additionally uses parameterized aliases and explicit runtime
# teardown.
  Scenario: A multi-sequencer committee converges across sequencers and the indexer
    Given a LEZ multi-sequencer environment with 1 validator and 0 Blend nodes
    And the following LEZ sequencers are registered
      | alias  | signing_key |
      | SEQ_A  | 0xA1        |
      | SEQ_B  | 0xB2        |
    And sequencer "SEQ_A" configures the committee
      | authorized_sequencers |
      | SEQ_A, SEQ_B          |
    When I start sequencer "SEQ_A"
    And sequencer "SEQ_A" reaches block 2 within 120 seconds
    And the committee configured by sequencer "SEQ_A" is active within 120 seconds
    And I start sequencer "SEQ_B"
    And sequencer "SEQ_B" synchronizes to sequencer "SEQ_A" within 120 seconds
    When sequencers "SEQ_A" and "SEQ_B" advance across 8 rotation blocks within 120 seconds
    And sequencer "SEQ_B" becomes the posting turn within 120 seconds
    Then sequencers "SEQ_A" and "SEQ_B" have identical common block hashes within 120 seconds
    When I record deterministic public account 1 balance on sequencer "SEQ_A"
    When I submit 10 from deterministic public account 0 to account 1 through sequencer "SEQ_B" as "COMMITTEE_TRANSFER"
    Then transfer "COMMITTEE_TRANSFER" is included in a block on sequencer "SEQ_B" within 120 seconds
    Then sequencer "SEQ_A" observes the receiver balance increase for transfer "COMMITTEE_TRANSFER" by 10 within 120 seconds
    And the indexer finalizes transfer "COMMITTEE_TRANSFER" on the committee chain within 120 seconds
    Then finalized indexer blocks match sequencer "SEQ_A"
    And the indexer is not stalled
    Then I stop the runtime
