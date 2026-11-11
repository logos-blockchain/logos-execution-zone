import unittest
from pathlib import Path

from discover_integration_test_targets import (
    GROUP_COUNT,
    DiscoveryError,
    assign_groups,
    discover_targets,
    group_filters,
)


def suite(binary_name: str, *testcases: tuple[str, bool, str]) -> dict:
    return {
        "kind": "test",
        "binary-name": binary_name,
        "testcases": {
            name: {
                "kind": "test",
                "ignored": ignored,
                "filter-match": {"status": status},
            }
            for name, ignored, status in testcases
        },
    }


class DiscoverIntegrationTestTargetsTests(unittest.TestCase):
    def test_excludes_suites_without_runnable_tests(self) -> None:
        summary = {
            "rust-suites": {
                "integration_tests::tf_app_deployments": suite(
                    "tf_app_deployments",
                    ("complete_stack", True, "mismatch"),
                    ("individual_apps", True, "mismatch"),
                ),
                "integration_tests::filtered": suite(
                    "filtered",
                    ("not_in_profile", False, "mismatch"),
                ),
            }
        }

        self.assertEqual(discover_targets(summary), [])

    def test_keeps_runnable_suites_and_excludes_tps(self) -> None:
        summary = {
            "rust-suites": {
                "integration_tests::auth_transfer": suite(
                    "auth_transfer",
                    ("successful_transfer", False, "matches"),
                    ("ignored_case", True, "mismatch"),
                ),
                "integration_tests::tps": suite(
                    "tps",
                    ("throughput", False, "matches"),
                ),
                "integration_tests": {"kind": "lib"},
            }
        }

        self.assertEqual(discover_targets(summary), ["auth_transfer"])

    def test_splits_configured_binaries_into_one_entry_per_test(self) -> None:
        summary = {
            "rust-suites": {
                "integration_tests::scoped_reads": suite(
                    "scoped_reads",
                    ("first_offence", False, "matches"),
                    ("second_offence", False, "matches"),
                    ("blocked_on_finality", True, "mismatch"),
                ),
                "integration_tests::gossip": suite(
                    "gossip",
                    ("peers_converge", False, "matches"),
                    ("peers_recover", False, "matches"),
                ),
            }
        }

        self.assertEqual(
            discover_targets(summary),
            [
                "gossip",
                "scoped_reads::first_offence",
                "scoped_reads::second_offence",
            ],
        )

    def test_drops_a_split_binary_with_no_runnable_tests(self) -> None:
        summary = {
            "rust-suites": {
                "integration_tests::slashing": suite(
                    "slashing",
                    ("blocked_on_finality", True, "mismatch"),
                ),
            }
        }

        self.assertEqual(discover_targets(summary), [])

    def test_group_count_matches_the_upload_steps_in_ci(self) -> None:
        """A group with no upload step leaves its shards nothing to download."""
        workflow = (
            Path(__file__).parent.parent / "workflows" / "ci.yml"
        ).read_text(encoding="utf-8")
        uploads = {
            f"integration-tests-archive-g{index + 1}" for index in range(GROUP_COUNT)
        }

        for name in uploads:
            self.assertIn(name, workflow, f"ci.yml has no upload step for {name}")
        self.assertNotIn(
            f"integration-tests-archive-g{GROUP_COUNT + 1}",
            workflow,
            "ci.yml uploads more groups than GROUP_COUNT assigns",
        )

    def test_groups_a_split_binary_as_one_unit(self) -> None:
        grouped = assign_groups(["slashing::a", "slashing::b", "gossip"])
        by_name = {entry["name"]: entry["group"] for entry in grouped}

        self.assertEqual(by_name["slashing::a"], by_name["slashing::b"])
        self.assertEqual(len(grouped), 3)

    def test_spreads_binaries_over_the_group_count(self) -> None:
        names = [f"binary_{index:02}" for index in range(GROUP_COUNT * 2)]
        groups = {entry["group"] for entry in assign_groups(names)}

        self.assertEqual(len(groups), GROUP_COUNT)

    def test_group_filters_name_every_binary_once(self) -> None:
        grouped = assign_groups(["slashing::a", "slashing::b", "gossip"])
        lines = group_filters(grouped)

        joined = " ".join(lines)
        self.assertEqual(joined.count("binary(slashing)"), 1)
        self.assertEqual(joined.count("binary(gossip)"), 1)
        for line in lines:
            group, _, filterset = line.partition("\t")
            self.assertTrue(group.startswith("g"))
            self.assertTrue(filterset.startswith("binary("))

    def test_rejects_binary_only_listing(self) -> None:
        with self.assertRaises(DiscoveryError):
            discover_targets(
                {
                    "rust-binaries": {
                        "integration_tests::auth_transfer": {
                            "kind": "test",
                            "binary-name": "auth_transfer",
                        }
                    }
                }
            )


if __name__ == "__main__":
    unittest.main()
