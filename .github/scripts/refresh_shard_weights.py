#!/usr/bin/env python3
"""Rewrite the shard weights from the per-test timings in a CI run's logs."""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
from pathlib import Path

WEIGHTS = Path(__file__).resolve().parents[1] / "integration-shard-weights.json"
REPO = "logos-blockchain/logos-execution-zone"

# nextest prints `PASS [  12.345s] (1/4) integration_tests::binary test_name`.
RESULT = re.compile(
    r"(?:PASS|FAIL) \[\s*([0-9.]+)s\]\s+\(\s*\d+/\d+\)\s+integration_tests::(\S+)\s+(\S+)"
)


def jobs(run_id: str) -> list[dict]:
    out = subprocess.run(
        [
            "gh",
            "api",
            "--paginate",
            "--slurp",
            f"repos/{REPO}/actions/runs/{run_id}/jobs?per_page=100",
        ],
        capture_output=True,
        text=True,
        check=True,
    ).stdout
    # `--slurp` wraps the pages in an array, so each page keeps its own `jobs`.
    return [job for page in json.loads(out) for job in page["jobs"]]


def log(job_id: int) -> str:
    return subprocess.run(
        [
            "gh",
            "api",
            "--allow-escape-sequences",
            f"repos/{REPO}/actions/jobs/{job_id}/logs",
        ],
        capture_output=True,
        text=True,
    ).stdout


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("run_id", help="a completed `General` run on dev")
    args = parser.parse_args()

    found: dict[str, float] = {}
    shards = [j for j in jobs(args.run_id) if j["name"].startswith("integration-tests (")]
    if not shards:
        print(f"run {args.run_id} has no integration shards", file=sys.stderr)
        return 1

    missing: list[str] = []
    shared: list[str] = []
    for job in shards:
        text = log(job["id"])
        results = RESULT.findall(text) if text else []
        if not results:
            missing.append(job["name"])
            continue
        for secs, binary, test in results:
            found[f"{binary}::{test}"] = float(secs)
        if len(results) > 1:
            shared.append(f"{job['name']} ({len(results)} tests)")

    if missing:
        print(f"no log for: {', '.join(missing)}", file=sys.stderr)
        return 1

    WEIGHTS.write_text(
        json.dumps(
            {
                "comment": json.loads(WEIGHTS.read_text())["comment"],
                "tests": dict(sorted(found.items())),
            },
            indent=2,
        )
        + "\n"
    )
    print(f"{len(found)} test weights from run {args.run_id}")
    if shared:
        print(
            "these shards ran several tests at once, so their weights read high: "
            + ", ".join(shared),
            file=sys.stderr,
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
