#!/usr/bin/env python3
"""Discover integration-test binaries that have runnable nextest tests."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any


# Scheduled one test per shard: both are far slower sharing a runner.
SPLIT_PER_TEST = frozenset({"scoped_reads", "slashing"})

# Each archive repeats a 42 MiB base, so more groups means a smaller download
# and more total bytes. One upload step per group in ci.yml, enforced by a test.
GROUP_COUNT = 8


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


def assign_groups(targets: list[str]) -> list[dict[str, str]]:
    """Pair each target with the archive group holding its binary."""
    binaries = sorted({target.split("::", 1)[0] for target in targets})
    group_of = {
        binary: f"g{index % GROUP_COUNT + 1}" for index, binary in enumerate(binaries)
    }
    return [
        {"name": target, "group": group_of[target.split("::", 1)[0]]}
        for target in targets
    ]


def discover_targets(summary: dict[str, Any]) -> list[str]:
    """Return shard targets: a binary name, or `binary::test` when split."""
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

        if binary_name == "tps":
            continue

        runnable = [
            name for name, testcase in testcases.items() if _is_runnable_test(testcase)
        ]
        if not runnable:
            continue

        if binary_name in SPLIT_PER_TEST:
            targets.update(f"{binary_name}::{name}" for name in runnable)
        else:
            targets.add(binary_name)

    return sorted(targets)


def group_filters(targets: list[dict[str, str]]) -> list[str]:
    """One `group<TAB>filterset` line per group, for the archive step."""
    binaries: dict[str, set[str]] = {}
    for target in targets:
        binary = target["name"].split("::", 1)[0]
        binaries.setdefault(target["group"], set()).add(binary)
    return [
        f"{group}\t" + " or ".join(f"binary({binary})" for binary in sorted(names))
        for group, names in sorted(binaries.items(), key=lambda kv: kv[0])
    ]


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("summary", type=Path, help="nextest JSON test listing")
    parser.add_argument(
        "--emit-group-filters",
        type=Path,
        help="write `group<TAB>filterset` lines here for the archive step",
    )
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

    grouped = assign_groups(targets)
    if args.emit_group_filters:
        args.emit_group_filters.write_text(
            "\n".join(group_filters(grouped)) + "\n", encoding="utf-8"
        )

    print(json.dumps(grouped, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
