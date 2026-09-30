#!/usr/bin/env python3
"""Resolve the Bedrock node for the revision selected by LEZ's Cargo.lock."""

from __future__ import annotations

import argparse
import hashlib
from http.client import HTTPException
import json
import os
import platform
import re
import shutil
import subprocess
import sys
import tarfile
import tempfile
import time
from pathlib import Path
from typing import Any, Callable
from urllib.error import HTTPError, URLError
from urllib.parse import quote, urlparse
from urllib.request import Request, urlopen


LOGOS_REPOSITORY = "https://github.com/logos-blockchain/logos-blockchain.git"
GITHUB_API = "https://api.github.com/repos/logos-blockchain/logos-blockchain"
NODE_BINARY = "logos-blockchain-node"
RESOLVED_DIRECTORY = Path("bedrock/.resolved")
TARGET_PLATFORMS = {"linux-x86_64", "linux-aarch64", "macos-aarch64"}
SHA256_PATTERN = re.compile(r"^[0-9a-f]{64}$")
REVISION_PATTERN = re.compile(r"^[0-9a-f]{40}$")
HTTP_REQUEST_ATTEMPTS = 3
HTTP_RETRY_DELAYS = (1, 2)


class ResolverError(RuntimeError):
    """An actionable Bedrock resolution error."""


def log(message: str) -> None:
    print(f"[bedrock] {message}", file=sys.stderr)


def run_command(
    command: list[str],
    *,
    cwd: Path | None = None,
    capture_output: bool = False,
    environment: dict[str, str] | None = None,
) -> subprocess.CompletedProcess[str]:
    log(f"$ {' '.join(command)}")
    try:
        return subprocess.run(
            command,
            cwd=cwd,
            check=True,
            text=True,
            capture_output=capture_output,
            env=environment,
        )
    except FileNotFoundError as error:
        raise ResolverError(f"required command is not installed: {command[0]}") from error
    except subprocess.CalledProcessError as error:
        output = (error.stderr or error.stdout or "").strip()
        detail = f": {output}" if output else ""
        raise ResolverError(f"command failed ({error.returncode}){detail}") from error


def cargo_metadata(manifest_path: Path | None = None) -> dict[str, Any]:
    command = ["cargo", "metadata", "--locked", "--format-version", "1"]
    if manifest_path is not None:
        command.extend(["--manifest-path", str(manifest_path)])

    result = run_command(command, capture_output=True)
    try:
        return json.loads(result.stdout)
    except json.JSONDecodeError as error:
        raise ResolverError("cargo metadata returned invalid JSON") from error


def logos_revision_from_source(source: str | None) -> str | None:
    if not source or not source.startswith("git+"):
        return None

    parsed = urlparse(source[4:])
    if (
        parsed.scheme != "https"
        or parsed.netloc != "github.com"
        or parsed.path.rstrip("/") != "/logos-blockchain/logos-blockchain.git"
    ):
        return None

    revision = parsed.fragment.lower()
    if not REVISION_PATTERN.fullmatch(revision):
        raise ResolverError(f"Cargo reported an invalid Logos git revision: {source}")
    return revision


def resolved_logos_revision(metadata: dict[str, Any]) -> str:
    revisions = {
        revision
        for package in metadata["packages"]
        if (revision := logos_revision_from_source(package.get("source"))) is not None
    }

    if not revisions:
        raise ResolverError(
            "Cargo metadata contains no packages sourced from "
            f"{LOGOS_REPOSITORY}"
        )
    if len(revisions) != 1:
        formatted = ", ".join(sorted(revisions))
        raise ResolverError(
            "Cargo resolved multiple Logos revisions; refusing to choose a node "
            f"arbitrarily: {formatted}"
        )

    revision = next(iter(revisions))
    log(f"Cargo-authoritative Logos revision: {revision}")
    return revision


def logos_workspace_root(metadata: dict[str, Any], revision: str) -> Path:
    matching_packages = [
        package
        for package in metadata["packages"]
        if package["name"] == "testing-framework"
        and logos_revision_from_source(package.get("source")) == revision
    ]
    if not matching_packages:
        matching_packages = [
            package
            for package in metadata["packages"]
            if logos_revision_from_source(package.get("source")) == revision
        ]
    if not matching_packages:
        raise ResolverError(
            "Cargo metadata did not expose a manifest path inside the resolved "
            f"Logos checkout ({revision})"
        )

    logos_metadata = cargo_metadata(Path(matching_packages[0]["manifest_path"]))
    node_packages = [
        package
        for package in logos_metadata["packages"]
        if package["name"] == NODE_BINARY
    ]
    if len(node_packages) != 1:
        raise ResolverError(
            f"expected one {NODE_BINARY} package in the resolved Logos workspace, "
            f"found {len(node_packages)}"
        )

    workspace_root = Path(logos_metadata["workspace_root"])
    if not (workspace_root / "Cargo.toml").is_file():
        raise ResolverError(
            f"Cargo reported an invalid Logos workspace root: {workspace_root}"
        )
    return workspace_root


def host_platform_asset_prefix() -> str:
    system = platform.system().lower()
    machine = platform.machine().lower()
    if system == "linux" and machine in {"x86_64", "amd64"}:
        return "linux-x86_64"
    if system == "linux" and machine in {"aarch64", "arm64"}:
        return "linux-aarch64"
    if system == "darwin" and machine in {"aarch64", "arm64"}:
        return "macos-aarch64"
    raise ResolverError(
        "no published Logos node asset mapping for "
        f"{platform.system()} {platform.machine()}; source-build fallback is required"
    )


def target_platform_asset_prefix(target_platform: str) -> str:
    if target_platform == "host":
        return host_platform_asset_prefix()
    if target_platform not in TARGET_PLATFORMS:
        supported = ", ".join(sorted(TARGET_PLATFORMS))
        raise ResolverError(
            f"unsupported target platform {target_platform!r}; choose host or {supported}"
        )
    return target_platform


def request_bytes(request: Request | str, *, timeout: int) -> bytes:
    url = request.full_url if isinstance(request, Request) else request
    last_error: Exception | None = None

    for attempt in range(1, HTTP_REQUEST_ATTEMPTS + 1):
        try:
            with urlopen(request, timeout=timeout) as response:
                return response.read()
        except HTTPError as error:
            if error.code != 408 and not 500 <= error.code <= 599:
                raise ResolverError(
                    f"HTTP request failed for {url} after {attempt} attempt(s): {error}"
                ) from error
            last_error = error
        except (HTTPException, URLError, OSError) as error:
            last_error = error

        if attempt < HTTP_REQUEST_ATTEMPTS:
            time.sleep(HTTP_RETRY_DELAYS[attempt - 1])

    assert last_error is not None
    raise ResolverError(
        f"HTTP request failed for {url} after {HTTP_REQUEST_ATTEMPTS} attempts: "
        f"{last_error}"
    ) from last_error


def api_json(url: str) -> Any:
    headers = {
        "Accept": "application/vnd.github+json",
        "User-Agent": "logos-execution-zone-bedrock-resolver",
    }
    token = os.environ.get("GITHUB_TOKEN")
    if token:
        headers["Authorization"] = f"Bearer {token}"

    request = Request(url, headers=headers)
    try:
        return json.loads(request_bytes(request, timeout=30))
    except json.JSONDecodeError as error:
        raise ResolverError(f"GitHub release lookup failed for {url}: {error}") from error


def published_releases() -> list[dict[str, Any]]:
    releases: list[dict[str, Any]] = []
    for page in range(1, 100):
        payload = api_json(f"{GITHUB_API}/releases?per_page=100&page={page}")
        if not isinstance(payload, list):
            raise ResolverError("GitHub returned an unexpected release list")
        if not payload:
            break
        releases.extend(payload)
        if len(payload) < 100:
            break
    return releases


def release_commit(tag: str) -> str:
    payload = api_json(f"{GITHUB_API}/commits/{quote(tag, safe='')}")
    commit = payload.get("sha") if isinstance(payload, dict) else None
    if not isinstance(commit, str) or not REVISION_PATTERN.fullmatch(commit.lower()):
        raise ResolverError(f"GitHub returned no full commit SHA for release tag {tag}")
    return commit.lower()


def asset_digest(asset: dict[str, Any]) -> str | None:
    digest = asset.get("digest")
    if not isinstance(digest, str) or not digest.startswith("sha256:"):
        return None

    digest = digest.removeprefix("sha256:").lower()
    return digest if SHA256_PATTERN.fullmatch(digest) else None


def matching_release(
    revision: str,
    releases: list[dict[str, Any]],
    commit_resolver: Callable[[str], str],
    asset_prefix: str,
) -> dict[str, str] | None:
    for release in releases:
        if release.get("draft") or not release.get("published_at"):
            continue

        tag = release.get("tag_name")
        if not isinstance(tag, str):
            continue
        assets = release.get("assets", [])
        expected_asset = f"{NODE_BINARY}-{asset_prefix}-{tag}.tar.gz"
        matching_assets = [
            asset
            for asset in assets
            if asset.get("name") == expected_asset
        ]
        if len(matching_assets) != 1:
            if matching_assets:
                log(
                    f"release {tag} has {len(matching_assets)} assets named "
                    f"{expected_asset}; refusing ambiguous selection"
                )
            continue

        asset = matching_assets[0]
        try:
            commit = commit_resolver(tag).lower()
        except ResolverError as error:
            log(f"could not resolve release tag {tag}; skipping it ({error})")
            continue
        if commit != revision:
            continue

        digest = asset_digest(asset)
        if digest is None:
            log(f"release {tag} has no published SHA-256 digest for {expected_asset}")
            continue
        return {
            "tag": tag,
            "asset": expected_asset,
            "url": asset["browser_download_url"],
            "sha256": digest,
            "commit": commit,
        }
    return None


def download_bytes(url: str) -> bytes:
    headers = {"User-Agent": "logos-execution-zone-bedrock-resolver"}
    token = os.environ.get("GITHUB_TOKEN")
    if token:
        headers["Authorization"] = f"Bearer {token}"
    request = Request(url, headers=headers)
    return request_bytes(request, timeout=120)


def extract_node(archive: Path, output: Path) -> None:
    try:
        with tarfile.open(archive, mode="r:gz") as tar:
            candidates = [
                member
                for member in tar.getmembers()
                if Path(member.name).name == NODE_BINARY and member.isfile()
            ]
            if len(candidates) != 1:
                raise ResolverError(
                    f"release archive must contain exactly one {NODE_BINARY}, "
                    f"found {len(candidates)}"
                )
            extracted = tar.extractfile(candidates[0])
            if extracted is None:
                raise ResolverError(f"could not read {NODE_BINARY} from release archive")
            output.write_bytes(extracted.read())
    except tarfile.TarError as error:
        raise ResolverError(f"invalid Logos node release archive: {error}") from error
    output.chmod(0o755)


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as file:
        for chunk in iter(lambda: file.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def source_checkout_revision(workspace_root: Path) -> str:
    return run_command(
        ["git", "-C", str(workspace_root), "rev-parse", "HEAD"], capture_output=True
    ).stdout.strip().lower()


def verify_source_checkout(workspace_root: Path, revision: str) -> None:
    actual_revision = source_checkout_revision(workspace_root)
    if actual_revision != revision:
        raise ResolverError(
            "Cargo's Logos checkout is not at the resolved revision: "
            f"expected {revision}, found {actual_revision}"
        )


def build_source_node(
    workspace_root: Path, target_directory: Path, output: Path, revision: str
) -> None:
    verify_source_checkout(workspace_root, revision)

    environment = os.environ.copy()
    environment["CARGO_TARGET_DIR"] = str(target_directory)
    run_command(
        [
            "cargo",
            "build",
            "--locked",
            "--release",
            "-p",
            NODE_BINARY,
            "--features",
            "testing",
        ],
        cwd=workspace_root,
        environment=environment,
    )
    built_binary = target_directory / "release" / NODE_BINARY
    if not built_binary.is_file():
        raise ResolverError(f"Cargo did not produce {built_binary}")
    shutil.copy2(built_binary, output)
    output.chmod(0o755)


def materialize(
    repo_root: Path,
    *,
    output_directory: Path = RESOLVED_DIRECTORY,
    target_platform: str = "host",
    target_directory: Path | None = None,
) -> None:
    if not output_directory.is_absolute():
        output_directory = repo_root / output_directory
    output_directory = output_directory.resolve()
    target_platform = target_platform_asset_prefix(target_platform)
    output_directory.parent.mkdir(parents=True, exist_ok=True)
    staging = Path(tempfile.mkdtemp(prefix=".resolved-", dir=output_directory.parent))
    binary = staging / NODE_BINARY
    if target_directory is None:
        target_directory = repo_root / "target" / "bedrock-node"
    elif not target_directory.is_absolute():
        target_directory = repo_root / target_directory
    target_directory = target_directory.resolve()
    metadata: dict[str, Any] = {
        "resolved_sha": None,
        "resolution": None,
        "target_platform": target_platform,
        "release_tag": None,
        "release_asset": None,
        "release_commit": None,
    }

    try:
        cargo = cargo_metadata()
        revision = resolved_logos_revision(cargo)
        metadata["resolved_sha"] = revision
        release: dict[str, str] | None = None
        try:
            release = matching_release(
                revision,
                published_releases(),
                release_commit,
                target_platform,
            )
        except ResolverError as error:
            log(f"release lookup unavailable; using source build ({error})")

        if release is not None:
            log(
                f"using exact Logos release {release['tag']} ({release['asset']}) "
                f"for {revision}"
            )
            archive = staging / release["asset"]
            archive.write_bytes(download_bytes(release["url"]))
            actual_digest = sha256(archive)
            if actual_digest != release["sha256"]:
                raise ResolverError(
                    f"SHA-256 mismatch for {release['asset']}: "
                    f"expected {release['sha256']}, found {actual_digest}"
                )
            extract_node(archive, binary)
            metadata.update(
                {
                    "resolution": "release",
                    "release_tag": release["tag"],
                    "release_asset": release["asset"],
                    "release_commit": release["commit"],
                }
            )
            archive.unlink()
        else:
            log(f"no exact published node release for {revision}; source-building")
            actual_platform = host_platform_asset_prefix()
            if target_platform != actual_platform:
                raise ResolverError(
                    f"source-building {target_platform} requires a controlled builder "
                    f"for that platform; this resolver is running on {actual_platform}"
                )
            workspace_root = logos_workspace_root(cargo, revision)
            build_source_node(
                workspace_root,
                target_directory,
                binary,
                revision,
            )
            metadata["resolution"] = "source-build"

        metadata["binary_sha256"] = sha256(binary)
        metadata_file = staging / "metadata.json"
        metadata_file.write_text(
            json.dumps(metadata, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )
        metadata_file.chmod(0o644)
        staging.chmod(0o755)

        if output_directory.exists():
            shutil.rmtree(output_directory)
        staging.rename(output_directory)
        log(
            f"resolved {revision} via {metadata['resolution']}; "
            f"binary SHA-256 {metadata['binary_sha256']}"
        )
    except BaseException:
        shutil.rmtree(staging, ignore_errors=True)
        raise


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--repo-root",
        type=Path,
        default=Path(__file__).resolve().parents[2],
        help="LEZ repository root (defaults to the repository containing this script)",
    )
    parser.add_argument(
        "--target-platform",
        choices=["host", *sorted(TARGET_PLATFORMS)],
        default="host",
        help="Platform of the binary to resolve (default: host)",
    )
    parser.add_argument(
        "--output-directory",
        type=Path,
        default=RESOLVED_DIRECTORY,
        help="Directory for the resolved binary and metadata",
    )
    parser.add_argument(
        "--target-directory",
        type=Path,
        help="Cargo target directory for a source build",
    )
    args = parser.parse_args()
    try:
        materialize(
            args.repo_root.resolve(),
            output_directory=args.output_directory,
            target_platform=args.target_platform,
            target_directory=args.target_directory,
        )
    except ResolverError as error:
        print(f"error: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
