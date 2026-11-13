#!/usr/bin/env python3
"""Per-test first-attempt failure rates over recent CI runs.

`--retries` hides a flake behind a green check, so the signal is the FIRST
attempt. Reads shard logs through `gh` and ranks what fails on attempt one.
"""

from __future__ import annotations

import argparse
import re
import subprocess
import sys
from collections import defaultdict
from typing import Iterable

# `TRY 1 FAIL [ 231.733s] (───) integration_tests::binary test_name`, and the
# retry-free `PASS [ 144.515s] (1/1) integration_tests::binary test_name`.
_OUTCOME = re.compile(
    r"(?:TRY (?P<try>\d+) )?(?P<outcome>PASS|FAIL) \[ *[\d.]+s\] \([^)]*\) "
    r"\S+::(?P<binary>\S+) (?P<test>\S+)"
)
_ERROR = re.compile(r"^\s*Error: (?P<message>.+)$")


class Tally:
    def __init__(self) -> None:
        self.seen = 0
        self.first_attempt_failures = 0
        self.last_error = ""


def parse_log(text: str, tallies: dict[str, Tally]) -> None:
    """Fold one shard log into `tallies`, keyed `binary::test`."""
    # nextest prints the outcome line before the captured stderr, so an error
    # belongs to the failure above it.
    failed: Tally | None = None
    for line in text.splitlines():
        if found := _ERROR.match(line.split("Z ", 1)[-1]):
            if failed is not None and not failed.last_error:
                failed.last_error = found.group("message")
            continue

        outcome = _OUTCOME.search(line)
        if not outcome:
            continue

        attempt = int(outcome.group("try") or 1)
        if attempt != 1:
            continue

        name = f"{outcome.group('binary')}::{outcome.group('test')}"
        tally = tallies.setdefault(name, Tally())
        tally.seen += 1
        if outcome.group("outcome") == "FAIL":
            tally.first_attempt_failures += 1
            tally.last_error = ""
            failed = tally
        else:
            failed = None


def _gh(*args: str) -> str:
    return subprocess.run(
        ("gh", *args), check=True, capture_output=True, text=True
    ).stdout


def _job_log(repo: str, job_id: str, token: str) -> str:
    # `gh api` returns the redirect to blob storage rather than following it,
    # and the signed URL rejects the auth header, which curl drops on redirect.
    return subprocess.run(
        (
            "curl", "-sL", "-H", f"Authorization: Bearer {token}",
            f"https://api.github.com/repos/{repo}/actions/jobs/{job_id}/logs",
        ),
        check=True, capture_output=True, text=True, errors="replace",
    ).stdout


def _run_ids(repo: str, branch: str, workflow: str, runs: int) -> list[str]:
    out = _gh(
        "run", "list", "--repo", repo, "--branch", branch, "--workflow", workflow,
        "--limit", str(runs), "--json", "databaseId", "--jq", ".[].databaseId",
    )
    return out.split()


def _shard_job_ids(repo: str, run_id: str) -> Iterable[str]:
    for page in (1, 2, 3, 4):
        out = _gh(
            "api", f"repos/{repo}/actions/runs/{run_id}/jobs?per_page=25&page={page}",
            "--jq", '.jobs[] | select(.name | startswith("integration-tests (")) | .id',
        )
        if not out.strip():
            return
        yield from out.split()


def collect(repo: str, branch: str, workflow: str, runs: int) -> dict[str, Tally]:
    token = _gh("auth", "token").strip()
    tallies: dict[str, Tally] = defaultdict(Tally)
    for run_id in _run_ids(repo, branch, workflow, runs):
        for job_id in _shard_job_ids(repo, run_id):
            try:
                log = _job_log(repo, job_id, token)
            except subprocess.CalledProcessError:
                continue
            parse_log(log, tallies)
    return tallies


def report(tallies: dict[str, Tally]) -> str:
    rows = sorted(
        tallies.items(),
        key=lambda item: (-item[1].first_attempt_failures, item[0]),
    )
    width = max((len(name) for name, _ in rows), default=4)
    lines = [f"{'test':<{width}} {'runs':>5} {'fails':>6} {'rate':>6}  last error"]
    for name, tally in rows:
        if not tally.first_attempt_failures:
            continue
        rate = tally.first_attempt_failures / tally.seen * 100
        lines.append(
            f"{name:<{width}} {tally.seen:>5} {tally.first_attempt_failures:>6} "
            f"{rate:>5.0f}%  {tally.last_error[:70]}"
        )
    if len(lines) == 1:
        lines.append("(no first-attempt failures)")
    return "\n".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repo", default="logos-blockchain/logos-execution-zone")
    parser.add_argument("--branch", default="dev")
    parser.add_argument("--workflow", default="General")
    parser.add_argument("--runs", type=int, default=10)
    args = parser.parse_args()

    tallies = collect(args.repo, args.branch, args.workflow, args.runs)
    print(report(tallies))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
