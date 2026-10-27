#!/usr/bin/env python3
"""Checks that every repository path cited in the developer books exists.

A chapter that cites a path which has moved or been deleted sends its reader to
nothing. This catches that the day it happens rather than months later.

Run from the repository root: `python3 docs/ci/check_book_paths.py`.
Exits non-zero for any missing path that is not listed in KNOWN below.
"""

import os
import re
import sys

BOOKS = ("docs/lez-guide", "docs/program-development-book")

# Prefixes that make a backticked span a repository path rather than prose.
TOP = (
    "lee/", "lez/", "bedrock/", "integration_tests/", "test_programs/", "examples/",
    "docs/", "tools/", "test_fixtures/", "test_guest_core/", "build_utils/", "artifacts/",
)

# Paths that are known not to resolve in this tree, each with the reason it is
# tolerated. Anything not listed here fails the build. Shrink this, never grow it
# without a reason worth reading. Code in another repository is cited as
# `<org>/<repo>: <path>` and skipped entirely rather than listed here.
KNOWN = {
    # Created at runtime by `sequencer_service setup`, so it is a real path a
    # reader will have and not one this repository ships.
    "lez/sequencer/service/sequencer_home": "runtime directory, created by setup",
    # `docs/program-development-book` documents the plan/apply interface as
    # released in v0.3.1. These two do not resolve here for reasons that are not
    # breakage, so listing them keeps that book's other 92 citations under watch
    # instead of excluding it wholesale.
    "lee/state_machine/core/src/account/data.rs": "exists at v0.3.1, replaced on dev",
    "lee/state_machine/core/src/validation.rs": "deleted by PR 912, cited as history",
}

# Known and accepted limits:
#   - A second path after a gloss, as `a.rs: see also b.rs`, is dropped. A
#     whitespace tokeniser would catch it and would also split
#     `docs/LEZ testnet v0.1 tutorials`, which cost ten false positives when
#     tried. No live instance, so not worth that trade.
#   - Link anchors are not validated, only the file a link points at.
#   - A citation is only checked when it starts with a TOP prefix, so a
#     top-level file like `Justfile` and a path under a directory not listed
#     above, as `target/` and `completions/`, go unchecked. Both have live
#     instances. Widening TOP to bare filenames would match ordinary prose.
BRACE = re.compile(r"\{([^{}]*)\}")


def expand(path):
    """Expands `a/{b.rs,c.rs}` into one path per alternative."""
    match = BRACE.search(path)
    if not match:
        return [path]
    out = []
    for alternative in match.group(1).split(","):
        out += expand(path[: match.start()] + alternative.strip() + path[match.end() :])
    return out


# `logos-blockchain/lez-programs: programs/token/` cites another repository and
# cannot be resolved here. Anchored at the start so it only skips a real
# `<org>/<repo>: <path>` citation, not any path that happens to carry a gloss.
CROSS_REPO = re.compile(r"^[\w.-]+/[\w.-]+:\s")

# Splits a span that names several paths at once, as `a.rs and b.rs`.
SEPARATORS = re.compile(r"\s+and\s+|,\s+|;\s+")


def candidates(span):
    """Yields each repository path a backticked span names, or nothing."""
    # An in-repo path can carry a gloss too, and `lez/indexer: the indexer
    # service` matches the org/repo shape. Only skip when it is not one of ours.
    if CROSS_REPO.match(span) and not span.startswith(TOP):
        return
    # A trailing gloss, as `lee/.../data.rs: the account payload`. Keep the path.
    if ": " in span:
        span = span.split(": ", 1)[0]
    # Braces expand before the split, or `, ` cuts `{nullifier, commitment}.rs` in two.
    for part in (p for whole in expand(span) for p in SEPARATORS.split(whole)):
        part = part.strip()
        if not part or not part.startswith(TOP):
            continue
        # A glob or a `<placeholder>` cannot be resolved to one path, so there
        # is nothing to check: `lez/indexer/service/rocksdb-<channel id>`.
        if "*" in part or "<" in part or ">" in part:
            continue
        # `lee/.../mod.rs::Symbol` names a file and a symbol in it; check the file.
        # A bare Rust path like `lee_core::account` never starts with a TOP prefix.
        path = part.split("::", 1)[0].strip().rstrip(".,;:").rstrip("/")
        if path:
            yield path


def cited_paths(src):
    """Yields (path, "chapter:line") for every repository path cited under src."""
    for root, _, files in os.walk(src):
        for name in sorted(files):
            if not name.endswith(".md"):
                continue
            full = os.path.join(root, name)
            chapter = os.path.relpath(full, src)
            with open(full, encoding="utf-8") as handle:
                for number, line in enumerate(handle, 1):
                    for span in re.findall(r"`([^`]+)`", line):
                        for path in candidates(span.strip()):
                            yield path, "%s:%d" % (chapter, number)


LINK = re.compile(r"\]\((\.{0,2}[^)\s:]*\.(?:md|svg|png))(?:#[^)]*)?\)")
# mdbook allows `{{#include path:1:5}}` and `{{#include path:anchor}}`, so the
# path stops at the first colon.
INCLUDE = re.compile(r"\{\{#include\s+([^}\s:]+)")


def broken_links(book):
    """Yields (target, "chapter:line") for links mdbook itself does not check.

    `create-missing = false` catches a SUMMARY entry with no file, but a dead
    relative link inside a chapter, or a missing `{{#include}}` target, builds
    green and ships a dead href.
    """
    src = os.path.join(book, "src")
    for root, _, files in os.walk(src):
        for name in sorted(files):
            if not name.endswith(".md"):
                continue
            full = os.path.join(root, name)
            for number, line in enumerate(open(full, encoding="utf-8"), 1):
                for pattern in (LINK, INCLUDE):
                    for match in pattern.finditer(line):
                        target = match.group(1)
                        if not os.path.exists(os.path.join(root, target)):
                            yield target, "%s:%d" % (os.path.relpath(full, src), number)


def main():
    failures, tolerated, checked = {}, 0, 0
    links = 0
    dead = {}
    for book in BOOKS:
        for target, where in broken_links(book):
            dead.setdefault(target, []).append("%s %s" % (book, where))
    for book in BOOKS:
        for path, where in cited_paths(os.path.join(book, "src")):
            checked += 1
            if os.path.exists(path):
                continue
            if path in KNOWN:
                tolerated += 1
                continue
            failures.setdefault(path, []).append("%s %s" % (book, where))

    print("checked %d citations, %d tolerated by KNOWN" % (checked, tolerated))
    if dead:
        print("\n%d dead intra-book link(s) or include(s):" % len(dead))
        for target in sorted(dead):
            print("  %s" % target)
            for where in dead[target]:
                print("      at %s" % where)
    if not failures and not dead:
        print("no unexpected missing paths, no dead links")
        return 0
    if not failures:
        return 1

    print("\n%d cited path(s) do not exist:" % len(failures))
    for path in sorted(failures):
        print("  %s" % path)
        for where in failures[path]:
            print("      cited at %s" % where)
    print("\nFix the citation, or add the path to KNOWN with a reason.")
    return 1


if __name__ == "__main__":
    sys.exit(main())
