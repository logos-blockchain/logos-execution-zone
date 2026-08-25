#!/usr/bin/env python3
"""Discover integration-test binaries that have runnable nextest tests."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any


class DiscoveryError(ValueError):
    """Raised when nextest output cannot be used for target discovery."""


def _is_runnable_test(testcase: Any) -> bool:
    if not isinstance(testcase, dict):
        return False

    filter_match = testcase.get("filter-match")
    return (
        testcase.get("ignored") is False
        and isinstance(filter_match, dict)
        and filter_match.get("status") == "matches"
    )


def discover_targets(summary: dict[str, Any]) -> list[str]:
    """Return test binary names containing at least one runnable test."""
    suites = summary.get("rust-suites")
    if not isinstance(suites, dict):
        raise DiscoveryError(
            "nextest output does not contain rust-suites; use a full test listing"
        )

    targets: set[str] = set()
    for suite_id, suite in suites.items():
        if not isinstance(suite, dict) or suite.get("kind") != "test":
            continue

        binary_name = suite.get("binary-name")
        testcases = suite.get("testcases")
        if not isinstance(binary_name, str) or not isinstance(testcases, dict):
            raise DiscoveryError(f"invalid test suite metadata for {suite_id!r}")

        if binary_name != "tps" and any(
            _is_runnable_test(testcase) for testcase in testcases.values()
        ):
            targets.add(binary_name)

    return sorted(targets)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("summary", type=Path, help="nextest JSON test listing")
    args = parser.parse_args()

    try:
        with args.summary.open(encoding="utf-8") as summary_file:
            summary = json.load(summary_file)
        if not isinstance(summary, dict):
            raise DiscoveryError("nextest output must be a JSON object")
        targets = discover_targets(summary)
    except (OSError, json.JSONDecodeError, DiscoveryError) as error:
        print(f"Unable to discover integration-test targets: {error}", file=sys.stderr)
        return 1

    print(json.dumps(targets, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
