#!/usr/bin/env python3
"""Post a pull request comment explaining why each code owner was requested.

Usage: codeowners_comment.py <CODEOWNERS path>

Reads REPO, PR_NUMBER, PR_AUTHOR and BASE_REF from the environment and
talks to GitHub through the `gh` CLI.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import subprocess
import sys
from dataclasses import dataclass, field
from pathlib import Path


MARKER = "<!-- codeowners-comment -->"
AREA_PREFIX = "## "
NO_AREA = "Other"
COLLAPSE_AFTER = 5
MAX_FILES_PER_AREA = 50


@dataclass
class Rule:
    pattern: str
    owners: list[str]
    area: str
    regex: re.Pattern[str] = field(repr=False)


def _split_unescaped(line: str) -> list[str]:
    """Split on whitespace, honouring `\\ ` and `\\#`, and drop trailing comments."""
    tokens: list[str] = []
    current = ""
    i = 0
    while i < len(line):
        char = line[i]
        if char == "\\" and i + 1 < len(line):
            current += line[i : i + 2]
            i += 2
            continue
        if char == "#" and not current:
            break
        if char.isspace():
            if current:
                tokens.append(current)
                current = ""
        else:
            current += char
        i += 1
    if current:
        tokens.append(current)
    return tokens


def _segment_regex(segment: str) -> str:
    out = ""
    i = 0
    while i < len(segment):
        char = segment[i]
        if char == "\\" and i + 1 < len(segment):
            out += re.escape(segment[i + 1])
            i += 2
            continue
        if char == "*":
            out += "[^/]*"
        elif char == "?":
            out += "[^/]"
        else:
            out += re.escape(char)
        i += 1
    return out


def pattern_regex(pattern: str) -> re.Pattern[str]:
    """Compile a CODEOWNERS pattern into a regex matching repository file paths."""
    directory_only = pattern.endswith("/")
    trimmed = pattern.strip("/")
    anchored = pattern.startswith("/") or "/" in trimmed
    segments = trimmed.split("/")

    out = "^" if anchored else "^(?:.*/)?"
    for index, segment in enumerate(segments):
        last = index == len(segments) - 1
        if segment == "**":
            out += ".+" if last else "(?:.*/)?"
            continue
        out += _segment_regex(segment)
        if not last:
            out += "/"

    if segments[-1] == "**":
        out += "$"
    elif directory_only:
        out += "/.+$"
    elif segments[-1] == "*" and len(segments) > 1:
        # `docs/*` owns files directly in `docs/` but not in its subdirectories.
        out += "$"
    else:
        out += "(?:/.+)?$"
    return re.compile(out)


def parse_codeowners(text: str) -> list[Rule]:
    rules: list[Rule] = []
    area = NO_AREA
    for raw in text.splitlines():
        line = raw.strip()
        if line.startswith(AREA_PREFIX):
            area = line[len(AREA_PREFIX) :].strip() or NO_AREA
            continue
        tokens = _split_unescaped(line)
        if not tokens:
            continue
        pattern, owners = tokens[0], tokens[1:]
        rules.append(Rule(pattern, owners, area, pattern_regex(pattern)))
    return rules


def matching_rule(path: str, rules: list[Rule]) -> Rule | None:
    """Return the rule GitHub applies to `path`: the last one that matches."""
    for rule in reversed(rules):
        if rule.regex.match(path):
            return rule
    return None


def _owner_key(owner: str) -> str:
    return owner.lstrip("@").lower()


def _owner_link(owner: str, server: str) -> str:
    """Link to an owner without @-mentioning them: the review request already notifies."""
    name = owner.lstrip("@")
    if "@" in name:
        return f"`{name}`"
    if "/" in name:
        org, team = name.split("/", 1)
        return f"[{name}]({server}/orgs/{org}/teams/{team})"
    return f"[{name}]({server}/{name})"


def _file_item(path: str, pr_url: str | None) -> str:
    """List item for `path`, linked to its diff in the pull request when `pr_url` is set."""
    if pr_url is None:
        return f"- `{path}`"
    anchor = hashlib.sha256(path.encode("utf-8")).hexdigest()
    return f"- [`{path}`]({pr_url}/files#diff-{anchor})"


def _file_list(files: list[str], pr_url: str | None) -> str:
    shown = files[:MAX_FILES_PER_AREA]
    lines = [_file_item(path, pr_url) for path in shown]
    if len(files) > len(shown):
        lines.append(f"- … and {len(files) - len(shown)} more")
    body = "\n".join(lines)
    if len(files) > COLLAPSE_AFTER:
        return f"<details><summary>{len(files)} files</summary>\n\n{body}\n\n</details>"
    return body


def build_comment(
    files: list[str],
    rules: list[Rule],
    author: str,
    codeowners_url: str,
    server: str = "https://github.com",
    pr_url: str | None = None,
) -> str | None:
    """Render the comment body, or None when no one besides the author owns the changes."""
    # owner -> area -> (patterns, files), in first-seen order.
    by_owner: dict[str, dict[str, tuple[list[str], list[str]]]] = {}
    display: dict[str, str] = {}
    unowned: list[str] = []

    for path in files:
        rule = matching_rule(path, rules)
        owners = [o for o in (rule.owners if rule else []) if _owner_key(o) != author.lower()]
        if not owners:
            unowned.append(path)
            continue
        for owner in owners:
            key = _owner_key(owner)
            display.setdefault(key, owner)
            patterns, area_files = by_owner.setdefault(key, {}).setdefault(rule.area, ([], []))
            if rule.pattern not in patterns:
                patterns.append(rule.pattern)
            area_files.append(path)

    if not by_owner:
        return None

    lines = [
        MARKER,
        "### Suggested reviewers",
        "",
        f"These code owners were requested because this pull request touches areas "
        f"they know best (see [`CODEOWNERS`]({codeowners_url})). "
        f"Each is asked to focus on the files listed under their name.",
        "",
        "| Reviewer | Why | Files |",
        "| --- | --- | --- |",
    ]
    for key, areas in by_owner.items():
        why = ", ".join(areas)
        count = sum(len(area_files) for _, area_files in areas.values())
        lines.append(f"| {_owner_link(display[key], server)} | {why} | {count} |")

    for key, areas in by_owner.items():
        lines += ["", f"#### {_owner_link(display[key], server)}"]
        for area, (patterns, area_files) in areas.items():
            rules_text = ", ".join(f"`{p}`" for p in patterns)
            lines += ["", f"**{area}** ({rules_text})", "", _file_list(area_files, pr_url)]

    if unowned:
        lines += [
            "",
            f"<details><summary>Files without another code owner ({len(unowned)})</summary>",
            "",
            "\n".join(_file_item(path, pr_url) for path in unowned[:MAX_FILES_PER_AREA]),
            "",
            "</details>",
        ]
    return "\n".join(lines) + "\n"


def _gh(*args: str, payload: dict | None = None) -> str:
    result = subprocess.run(
        ["gh", "api", *args],
        input=json.dumps(payload) if payload is not None else None,
        capture_output=True,
        text=True,
        check=True,
    )
    return result.stdout


def main() -> int:
    if len(sys.argv) != 2:
        print(__doc__, file=sys.stderr)
        return 2

    repo = os.environ["REPO"]
    pr = os.environ["PR_NUMBER"]
    author = os.environ["PR_AUTHOR"]
    base_ref = os.environ["BASE_REF"]
    server = os.environ.get("GITHUB_SERVER_URL", "https://github.com")
    codeowners_path = sys.argv[1]

    rules = parse_codeowners(Path(codeowners_path).read_text(encoding="utf-8"))
    files = _gh("--paginate", f"repos/{repo}/pulls/{pr}/files", "--jq", ".[].filename").splitlines()
    codeowners_url = f"{server}/{repo}/blob/{base_ref}/{codeowners_path}"
    body = build_comment(files, rules, author, codeowners_url, server, f"{server}/{repo}/pull/{pr}")

    existing = _gh(
        "--paginate",
        f"repos/{repo}/issues/{pr}/comments",
        "--jq",
        f'.[] | select(.user.login == "github-actions[bot]") '
        f'| select(.body | startswith("{MARKER}")) | .id',
    ).split()

    if body is None:
        if not existing:
            print("No code owners besides the author; nothing to post.")
            return 0
        body = f"{MARKER}\n### Suggested reviewers\n\nNo code owners besides the author own the files in this pull request.\n"

    if existing:
        _gh("-X", "PATCH", f"repos/{repo}/issues/comments/{existing[0]}", "--input", "-", payload={"body": body})
        print(f"Updated comment {existing[0]}.")
    else:
        _gh("-X", "POST", f"repos/{repo}/issues/{pr}/comments", "--input", "-", payload={"body": body})
        print("Created comment.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
