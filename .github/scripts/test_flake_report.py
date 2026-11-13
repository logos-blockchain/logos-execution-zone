#!/usr/bin/env python3
from __future__ import annotations

import unittest

from flake_report import Tally, parse_log, report

RETRIED = """
2026-11-10T20:37:59Z   TRY 1 FAIL [ 231.733s] (───) integration_tests::sequencer_stake_demo stake_transaction_joins_the_bedrock_committee
2026-11-10T20:38:00Z     Error: Chain divergence at block 64: leader abc vs joiner def
2026-11-10T20:41:19Z   TRY 2 PASS [ 199.186s] (1/1) integration_tests::sequencer_stake_demo stake_transaction_joins_the_bedrock_committee
"""

CLEAN = """
2026-11-09T01:02:03Z         PASS [ 144.515s] (1/1) integration_tests::two_zone zones_stay_live
"""


class ParseTests(unittest.TestCase):
    def test_counts_only_the_first_attempt(self) -> None:
        tallies: dict[str, Tally] = {}
        parse_log(RETRIED, tallies)
        tally = tallies["sequencer_stake_demo::stake_transaction_joins_the_bedrock_committee"]
        self.assertEqual((tally.seen, tally.first_attempt_failures), (1, 1))

    def test_keeps_the_error_of_a_failed_first_attempt(self) -> None:
        tallies: dict[str, Tally] = {}
        parse_log(RETRIED, tallies)
        tally = tallies["sequencer_stake_demo::stake_transaction_joins_the_bedrock_committee"]
        self.assertIn("Chain divergence at block 64", tally.last_error)

    def test_a_retry_free_pass_has_no_try_prefix(self) -> None:
        tallies: dict[str, Tally] = {}
        parse_log(CLEAN, tallies)
        tally = tallies["two_zone::zones_stay_live"]
        self.assertEqual((tally.seen, tally.first_attempt_failures), (1, 0))

    def test_runs_accumulate_across_logs(self) -> None:
        tallies: dict[str, Tally] = {}
        parse_log(RETRIED, tallies)
        parse_log(RETRIED.replace("FAIL", "PASS", 1), tallies)
        tally = tallies["sequencer_stake_demo::stake_transaction_joins_the_bedrock_committee"]
        self.assertEqual((tally.seen, tally.first_attempt_failures), (2, 1))

    def test_report_lists_offenders_and_hides_clean_tests(self) -> None:
        tallies: dict[str, Tally] = {}
        parse_log(RETRIED, tallies)
        parse_log(CLEAN, tallies)
        text = report(tallies)
        self.assertIn("stake_transaction_joins_the_bedrock_committee", text)
        self.assertNotIn("zones_stay_live", text)

    def test_report_says_so_when_nothing_failed(self) -> None:
        tallies: dict[str, Tally] = {}
        parse_log(CLEAN, tallies)
        self.assertIn("no first-attempt failures", report(tallies))


if __name__ == "__main__":
    unittest.main()
