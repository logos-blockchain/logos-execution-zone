import hashlib
from http.client import IncompleteRead
import io
import os
import tarfile
import tempfile
import unittest
from pathlib import Path
from urllib.error import HTTPError, URLError
from unittest.mock import MagicMock, call, patch

from resolve_bedrock_node import (
    ResolverError,
    build_source_node,
    download_bytes,
    extract_node,
    api_json,
    matching_release,
    release_commit,
    published_releases,
    resolved_logos_revision,
)


def fixture_revision(label: str) -> str:
    return hashlib.sha256(label.encode()).hexdigest()[:40]


def response_with(payload: bytes) -> MagicMock:
    response = MagicMock()
    response.__enter__.return_value = response
    response.read.return_value = payload
    return response


class HttpRequestTests(unittest.TestCase):
    def test_api_json_retries_an_incomplete_read(self) -> None:
        with (
            patch(
                "resolve_bedrock_node.urlopen",
                side_effect=[IncompleteRead(b"partial", 1), response_with(b"[]")],
            ) as urlopen,
            patch("resolve_bedrock_node.time.sleep") as sleep,
        ):
            self.assertEqual(api_json("https://example.invalid/releases"), [])

        self.assertEqual(urlopen.call_count, 2)
        sleep.assert_called_once_with(1)

    def test_transient_failures_exhaust_all_attempts(self) -> None:
        url = "https://example.invalid/node.tar.gz"
        with (
            patch(
                "resolve_bedrock_node.urlopen",
                side_effect=[
                    URLError("temporary failure"),
                    OSError("connection reset"),
                    IncompleteRead(b"partial", 1),
                ],
            ) as urlopen,
            patch("resolve_bedrock_node.time.sleep") as sleep,
        ):
            with self.assertRaises(ResolverError) as raised:
                download_bytes(url)

        self.assertEqual(urlopen.call_count, 3)
        self.assertEqual(sleep.call_args_list, [call(1), call(2)])
        self.assertIn(url, str(raised.exception))
        self.assertIn("3 attempts", str(raised.exception))
        self.assertIn("IncompleteRead", str(raised.exception))

    def test_http_404_is_not_retried(self) -> None:
        url = "https://example.invalid/missing.tar.gz"
        not_found = HTTPError(url, 404, "not found", hdrs=None, fp=None)
        with (
            patch("resolve_bedrock_node.urlopen", side_effect=not_found) as urlopen,
            patch("resolve_bedrock_node.time.sleep") as sleep,
        ):
            with self.assertRaises(ResolverError) as raised:
                download_bytes(url)

        self.assertEqual(urlopen.call_count, 1)
        sleep.assert_not_called()
        self.assertIn("404", str(raised.exception))

    def test_download_bytes_uses_the_shared_retry_path(self) -> None:
        url = "https://example.invalid/node.tar.gz"
        with (
            patch(
                "resolve_bedrock_node.urlopen",
                side_effect=[IncompleteRead(b"partial", 1), response_with(b"archive")],
            ) as urlopen,
            patch("resolve_bedrock_node.time.sleep") as sleep,
        ):
            self.assertEqual(download_bytes(url), b"archive")

        self.assertEqual(urlopen.call_count, 2)
        sleep.assert_called_once_with(1)


class ReleaseMatchingTests(unittest.TestCase):
    def test_matches_exact_release_commit_and_asset(self) -> None:
        # Keep the unit test independent of a historical Logos release commit.
        revision = fixture_revision("matching revision")
        digest = hashlib.sha256(b"fixture archive").hexdigest()
        release = {
            "tag_name": "fixture-release",
            "published_at": "2026-01-01T00:00:00Z",
            "draft": False,
            "assets": [
                {
                    "name": "logos-blockchain-node-linux-x86_64-fixture-release.tar.gz",
                    "browser_download_url": "https://example.invalid/node.tar.gz",
                    "digest": "sha256:" + digest,
                }
            ],
        }

        result = matching_release(
            revision,
            [release],
            lambda tag: revision if tag == "fixture-release" else fixture_revision("other"),
            "linux-x86_64",
        )

        self.assertIsNotNone(result)
        assert result is not None
        self.assertEqual(result["tag"], "fixture-release")
        self.assertEqual(
            result["asset"],
            "logos-blockchain-node-linux-x86_64-fixture-release.tar.gz",
        )

    def test_rejects_release_at_a_different_commit(self) -> None:
        digest = hashlib.sha256(b"fixture archive").hexdigest()
        release = {
            "tag_name": "fixture-release",
            "published_at": "2026-01-01T00:00:00Z",
            "draft": False,
            "assets": [
                {
                    "name": "logos-blockchain-node-linux-x86_64-fixture-release.tar.gz",
                    "browser_download_url": "https://example.invalid/node.tar.gz",
                    "digest": "sha256:" + digest,
                }
            ],
        }

        self.assertIsNone(
            matching_release(
                fixture_revision("matching revision"),
                [release],
                lambda _: fixture_revision("different revision"),
                "linux-x86_64",
            )
        )

    def test_does_not_resolve_tag_without_the_expected_asset(self) -> None:
        revision = fixture_revision("matching revision")
        release = {
            "tag_name": "fixture-release",
            "published_at": "2026-01-01T00:00:00Z",
            "draft": False,
            "assets": [
                {
                    "name": "logos-blockchain-node-linux-aarch64-fixture-release.tar.gz",
                    "browser_download_url": "https://example.invalid/node.tar.gz",
                    "digest": "sha256:" + hashlib.sha256(b"fixture archive").hexdigest(),
                }
            ],
        }
        commit_resolver = MagicMock(return_value=revision)

        self.assertIsNone(
            matching_release(
                revision,
                [release],
                commit_resolver,
                "linux-x86_64",
            )
        )
        commit_resolver.assert_not_called()

    def test_rejects_an_unverifiable_asset_digest(self) -> None:
        revision = fixture_revision("matching revision")
        release = {
            "tag_name": "fixture-release",
            "published_at": "2026-01-01T00:00:00Z",
            "draft": False,
            "assets": [
                {
                    "name": "logos-blockchain-node-linux-x86_64-fixture-release.tar.gz",
                    "browser_download_url": "https://example.invalid/node.tar.gz",
                    "digest": "sha256:not-a-digest",
                }
            ],
        }

        self.assertIsNone(
            matching_release(
                revision,
                [release],
                lambda _: revision,
                "linux-x86_64",
            )
        )

    def test_extracts_only_the_node_file(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            archive_path = Path(directory) / "node.tar.gz"
            output_path = Path(directory) / "logos-blockchain-node"
            with tarfile.open(archive_path, "w:gz") as archive:
                contents = b"fixture node"
                entry = tarfile.TarInfo("nested/logos-blockchain-node")
                entry.size = len(contents)
                archive.addfile(entry, io.BytesIO(contents))

            extract_node(archive_path, output_path)

            self.assertEqual(output_path.read_bytes(), b"fixture node")

    def test_rejects_multiple_cargo_logos_revisions(self) -> None:
        first = fixture_revision("first revision")
        second = fixture_revision("second revision")
        metadata = {
            "packages": [
                {
                    "source": "git+https://github.com/logos-blockchain/logos-blockchain.git#"
                    + first
                },
                {
                    "source": "git+https://github.com/logos-blockchain/logos-blockchain.git#"
                    + second
                },
            ]
        }

        with self.assertRaises(ResolverError):
            resolved_logos_revision(metadata)

    def test_rejects_a_source_checkout_at_a_different_revision(self) -> None:
        with patch(
            "resolve_bedrock_node.source_checkout_revision",
            return_value=fixture_revision("actual checkout"),
        ):
            with self.assertRaises(ResolverError):
                build_source_node(
                    Path("/tmp/logos-checkout"),
                    Path("/tmp/target"),
                    Path("/tmp/logos-blockchain-node"),
                    fixture_revision("resolved revision"),
                )

    def test_rejects_ambiguous_exact_assets(self) -> None:
        revision = fixture_revision("ambiguous revision")
        digest = hashlib.sha256(b"fixture archive").hexdigest()
        asset = {
            "name": "logos-blockchain-node-linux-x86_64-fixture-release.tar.gz",
            "browser_download_url": "https://example.invalid/node.tar.gz",
            "digest": "sha256:" + digest,
        }
        release = {
            "tag_name": "fixture-release",
            "published_at": "2026-01-01T00:00:00Z",
            "draft": False,
            "assets": [asset, asset.copy()],
        }

        self.assertIsNone(
            matching_release(
                revision,
                [release],
                lambda _: revision,
                "linux-x86_64",
            )
        )


@unittest.skipUnless(
    os.environ.get("RUN_LIVE_RELEASE_TESTS") == "1",
    "set RUN_LIVE_RELEASE_TESTS=1 to exercise the published release path",
)
class PublishedReleaseTests(unittest.TestCase):
    def test_matches_a_published_release_without_pinning_its_commit(self) -> None:
        tag = os.environ.get("LOGOS_KNOWN_RELEASE_TAG", "0.2.1-rc.3")
        release = next(
            release
            for release in published_releases()
            if release.get("tag_name") == tag
        )
        revision = release_commit(tag)
        result = matching_release(
            revision,
            [release],
            release_commit,
            "linux-x86_64",
        )

        self.assertIsNotNone(result)
        self.assertEqual(result["tag"], tag)


if __name__ == "__main__":
    unittest.main()
