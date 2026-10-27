import json
import unittest
from pathlib import Path

from plan_integration_shards import (
    NEEDS_CARGO_FETCH,
    SERIALIZED_BINARIES,
    PlanError,
    plan_shards,
    runnable_tests,
    wall_secs,
)

WEIGHTS = Path(__file__).resolve().parents[1] / "integration-shard-weights.json"


def suite(binary: str, *names: str) -> dict:
    return {
        "kind": "test",
        "binary-name": binary,
        "testcases": {
            name: {
                "kind": "test",
                "ignored": False,
                "filter-match": {"status": "matches"},
            }
            for name in names
        },
    }


def listing(*suites: dict) -> dict:
    return {"rust-suites": {f"integration_tests::{s['binary-name']}": s for s in suites}}


def members(shards: list[dict]) -> list[str]:
    """Every (binary, test) a plan schedules, via its filter expressions."""
    found = []
    for shard in shards:
        for part in shard["filter"].split(" or "):
            part = part.strip()
            if part.startswith("(") and part.endswith(")"):
                part = part[1:-1]
            found.append(part)
    return found


class PlanIntegrationShardsTests(unittest.TestCase):
    def test_places_every_runnable_test_exactly_once(self) -> None:
        weights = json.loads(WEIGHTS.read_text())["tests"]
        suites = {}
        for key in weights:
            binary, _, test = key.partition("::")
            suites.setdefault(binary, []).append(test)
        plan = plan_shards(
            listing(*(suite(b, *sorted(t)) for b, t in suites.items())), weights
        )

        scheduled = []
        for shard in plan:
            for part in shard["filter"].split(" or "):
                part = part.strip().lstrip("(").rstrip(")")
                scheduled.append(part)
        self.assertEqual(len(scheduled), len(set(scheduled)), "a shard was duplicated")
        covered = {p.split("binary(=")[1].split(")")[0] for p in scheduled}
        self.assertEqual(covered, set(suites))

    def test_keeps_serialized_binaries_in_separate_shards(self) -> None:
        binary = sorted(SERIALIZED_BINARIES)[0]
        weights = {f"{binary}::one": 600.0, f"{binary}::two": 600.0}
        plan = plan_shards(listing(suite(binary, "one", "two")), weights)
        self.assertEqual(len(plan), 2, "serialized tests must not share a shard")

    def test_keeps_a_serialized_binary_whole_when_its_serial_cost_fits(self) -> None:
        binary = sorted(SERIALIZED_BINARIES)[0]
        weights = {f"{binary}::one": 60.0, f"{binary}::two": 60.0, "heavy::big": 600.0}
        plan = plan_shards(
            listing(suite(binary, "one", "two"), suite("heavy", "big")), weights
        )
        mine = [s for s in plan if binary in s["filter"]]
        self.assertEqual(len(mine), 1, "its tests run back to back, so one shard")
        self.assertEqual(mine[0]["filter"], f"binary(={binary})")

    def test_isolates_binaries_that_need_cargo_fetch(self) -> None:
        fetch = sorted(NEEDS_CARGO_FETCH)[0]
        weights = {f"{fetch}::only": 10.0, "light::only": 10.0}
        plan = plan_shards(listing(suite(fetch, "only"), suite("light", "only")), weights)
        flagged = [s for s in plan if s["needs_cargo_fetch"]]
        self.assertEqual(len(flagged), 1)
        self.assertEqual(flagged[0]["filter"], f"binary(={fetch})")

    def test_excludes_tps_and_ignored_tests(self) -> None:
        ignored = suite("quiet", "skipped")
        ignored["testcases"]["skipped"]["ignored"] = True
        found = runnable_tests(listing(suite("tps", "bench"), ignored, suite("real", "go")))
        self.assertEqual(found, {"real": ["go"]})

    def test_splits_a_binary_that_cannot_fit_whole(self) -> None:
        weights = {f"big::t{i}": 600.0 for i in range(4)}
        plan = plan_shards(listing(suite("big", *weights and [f"t{i}" for i in range(4)])), weights)
        self.assertEqual(len(plan), 4)
        self.assertTrue(all("test(=" in s["filter"] for s in plan))

    def test_unknown_test_is_weighted_as_the_slowest(self) -> None:
        weights = {"light::a": 10.0, "heavy::b": 600.0}
        plan = plan_shards(
            listing(suite("light", "a"), suite("heavy", "b"), suite("fresh", "c")),
            weights,
        )
        together = [s for s in plan if "heavy" in s["filter"] and "fresh" in s["filter"]]
        self.assertEqual(together, [], "a new test was packed with a heavy one")

    def test_rejects_a_listing_without_suites(self) -> None:
        with self.assertRaises(PlanError):
            plan_shards({}, {})

    def test_wall_matches_the_measured_four_up_cost(self) -> None:
        self.assertAlmostEqual(wall_secs([390.0] * 4), 1300.0, delta=1.0)


if __name__ == "__main__":
    unittest.main()
