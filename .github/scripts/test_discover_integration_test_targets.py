import unittest

from discover_integration_test_targets import DiscoveryError, discover_targets


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
