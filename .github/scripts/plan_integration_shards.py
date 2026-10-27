#!/usr/bin/env python3
"""Plan integration-test shards from a nextest listing and measured weights."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any, Optional, Tuple

EXCLUDED_BINARIES = frozenset({"tps"})

NEEDS_CARGO_FETCH = frozenset({"tf_bedrock_builder", "tf_app_deployments"})

# nextest's one-thread group for these is intra-binary, so they need exclusive
# shards: a neighbour from another binary would stall their finality too.
SERIALIZED_BINARIES = frozenset({"slashing", "sequencer_bootstrap"})

# Measured: four 390s tests take 1300s each four-up on a 4-vCPU runner.
HEAVY_SECS = 120.0
HEAVY_LANES = 1.2
LIGHT_LANES = 3.6

# Pinned: a weight measured in a fuller shard reads high, so a derived budget
# would ratchet upward on every refresh.
CAP_SECS = 720.0

Item = Tuple[str, Optional[str]]


class PlanError(ValueError):
    """Raised when the nextest listing cannot be planned."""


def _is_runnable(testcase: Any) -> bool:
    if not isinstance(testcase, dict):
        return False
    match = testcase.get("filter-match")
    return (
        testcase.get("ignored") is False
        and isinstance(match, dict)
        and match.get("status") == "matches"
    )


def runnable_tests(summary: dict[str, Any]) -> dict[str, list[str]]:
    """Runnable test names per binary, exactly as nextest reports them."""
    suites = summary.get("rust-suites")
    if not isinstance(suites, dict):
        raise PlanError("nextest output has no rust-suites; use a full listing")

    found: dict[str, list[str]] = {}
    for suite_id, suite in suites.items():
        if not isinstance(suite, dict) or suite.get("kind") != "test":
            continue
        binary = suite.get("binary-name")
        testcases = suite.get("testcases")
        if not isinstance(binary, str) or not isinstance(testcases, dict):
            raise PlanError(f"invalid suite metadata for {suite_id!r}")
        if binary in EXCLUDED_BINARIES:
            continue
        names = sorted(n for n, t in testcases.items() if _is_runnable(t))
        if names:
            found[binary] = names
    return found


def wall_secs(weights: list[float]) -> float:
    """Estimated shard wall for these tests running together on one runner."""
    heavy = sum(w for w in weights if w > HEAVY_SECS)
    light = sum(w for w in weights if w <= HEAVY_SECS)
    return max(max(weights, default=0.0), heavy / HEAVY_LANES + light / LIGHT_LANES)


def _filter_for(items: list[Item]) -> str:
    # `=` on both matchers: `test()` would otherwise match substrings.
    parts = [
        f"binary(={binary})" if test is None else f"binary(={binary}) and test(={test})"
        for binary, test in items
    ]
    if len(parts) == 1:
        return parts[0]
    return " or ".join(f"({part})" for part in parts)


def _name_for(items: list[Item]) -> str:
    if len(items) == 1:
        binary, test = items[0]
        return binary if test is None else f"{binary}::{test}"
    binaries = sorted({binary for binary, _ in items})
    if len(binaries) <= 2:
        return "+".join(binaries)
    return f"{binaries[0]}+{len(binaries) - 1}"


def plan_shards(
    summary: dict[str, Any],
    weights: dict[str, float],
    *,
    cap_secs: Optional[float] = None,
) -> list[dict[str, Any]]:
    """Group runnable tests into shards no slower than the slowest single test."""
    tests = runnable_tests(summary)
    if not tests:
        raise PlanError("no runnable integration tests were discovered")

    unknown = max(weights.values()) if weights else HEAVY_SECS

    def weight(binary: str, test: str) -> float:
        return weights.get(f"{binary}::{test}", unknown)

    def weights_of(items: list[Item]) -> list[float]:
        out: list[float] = []
        for binary, test in items:
            if test is None:
                out.extend(weight(binary, name) for name in tests[binary])
            else:
                out.append(weight(binary, test))
        return out

    if cap_secs is None:
        cap_secs = CAP_SECS

    candidates: list[tuple[float, list[Item], bool]] = []
    for binary, names in sorted(tests.items()):
        if binary in NEEDS_CARGO_FETCH:
            whole: list[Item] = [(binary, None)]
            candidates.append((wall_secs(weights_of(whole)), whole, True))
            continue
        if binary in SERIALIZED_BINARIES:
            serial = sum(weight(binary, test) for test in names)
            if serial <= cap_secs:
                candidates.append((serial, [(binary, None)], True))
            else:
                for test in names:
                    candidates.append((weight(binary, test), [(binary, test)], True))
            continue
        whole = [(binary, None)]
        if wall_secs(weights_of(whole)) <= cap_secs:
            candidates.append((wall_secs(weights_of(whole)), whole, False))
            continue
        for test in names:
            candidates.append((weight(binary, test), [(binary, test)], False))

    candidates.sort(key=lambda candidate: -candidate[0])

    shards: list[dict[str, Any]] = []
    for _, items, exclusive in candidates:
        binary = items[0][0]
        placed = False
        if not exclusive:
            for shard in shards:
                if shard["exclusive"]:
                    continue
                merged = shard["items"] + items
                if wall_secs(weights_of(merged)) > cap_secs:
                    continue
                shard["items"] = merged
                placed = True
                break
        if not placed:
            shards.append(
                {
                    "items": list(items),
                    "exclusive": exclusive,
                    "needs_cargo_fetch": binary in NEEDS_CARGO_FETCH,
                }
            )

    planned = [
        {
            "name": _name_for(shard["items"]),
            "filter": _filter_for(shard["items"]),
            "needs_cargo_fetch": shard["needs_cargo_fetch"],
        }
        for shard in shards
    ]

    seen: dict[str, int] = {}
    for shard in planned:
        seen[shard["name"]] = seen.get(shard["name"], 0) + 1
    repeated = {name for name, count in seen.items() if count > 1}
    used = {shard["name"] for shard in planned}
    for shard in planned:
        if shard["name"] not in repeated:
            continue
        suffix = 1
        while f"{shard['name']}-{suffix}" in used:
            suffix += 1
        shard["name"] = f"{shard['name']}-{suffix}"
        used.add(shard["name"])

    unknown_tests = sum(
        1
        for binary, names in tests.items()
        for test in names
        if f"{binary}::{test}" not in weights
    )
    if unknown_tests:
        print(
            f"{unknown_tests} test(s) have no measured weight; refresh "
            ".github/integration-shard-weights.json",
            file=sys.stderr,
        )

    return planned


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("summary", type=Path, help="nextest JSON test listing")
    parser.add_argument("weights", type=Path, help="measured per-test seconds")
    args = parser.parse_args()

    try:
        summary = json.loads(args.summary.read_text(encoding="utf-8"))
        weights = json.loads(args.weights.read_text(encoding="utf-8")).get("tests", {})
        if not isinstance(summary, dict) or not isinstance(weights, dict):
            raise PlanError("summary and weights must both be JSON objects")
        shards = plan_shards(summary, weights)
    except (OSError, json.JSONDecodeError, PlanError) as error:
        print(f"Unable to plan integration shards: {error}", file=sys.stderr)
        return 1

    print(json.dumps(shards, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
