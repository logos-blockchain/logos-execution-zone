import subprocess
import unittest
from pathlib import Path

from codeowners_comment import MARKER, build_comment, matching_rule, parse_codeowners, pattern_regex


REPO_ROOT = Path(__file__).resolve().parents[2]


def matches(pattern: str, path: str) -> bool:
    return pattern_regex(pattern).match(path) is not None


class PatternTests(unittest.TestCase):
    # Cases follow GitHub's CODEOWNERS documentation examples.
    def test_wildcard_matches_everything(self) -> None:
        self.assertTrue(matches("*", "README.md"))
        self.assertTrue(matches("*", "a/b/c.rs"))

    def test_extension_matches_at_any_depth(self) -> None:
        self.assertTrue(matches("*.js", "app.js"))
        self.assertTrue(matches("*.js", "src/deep/app.js"))
        self.assertFalse(matches("*.js", "src/app.jsx"))

    def test_trailing_slash_matches_directory_anywhere(self) -> None:
        self.assertTrue(matches("apps/", "apps/x.rs"))
        self.assertTrue(matches("apps/", "src/apps/nested/x.rs"))
        self.assertFalse(matches("apps/", "apps"))
        self.assertFalse(matches("apps/", "myapps/x.rs"))

    def test_leading_slash_anchors_to_root(self) -> None:
        self.assertTrue(matches("/docs/", "docs/a/b.md"))
        self.assertFalse(matches("/docs/", "src/docs/b.md"))

    def test_middle_slash_anchors_to_root(self) -> None:
        self.assertTrue(matches("docs/guide", "docs/guide/a.md"))
        self.assertFalse(matches("docs/guide", "x/docs/guide/a.md"))

    def test_single_star_does_not_descend(self) -> None:
        self.assertTrue(matches("docs/*", "docs/getting-started.md"))
        self.assertFalse(matches("docs/*", "docs/build-app/troubleshooting.md"))

    def test_double_star(self) -> None:
        self.assertTrue(matches("**/logs", "build/logs/x.log"))
        self.assertTrue(matches("**/logs", "logs/x.log"))
        self.assertTrue(matches("/docs/**", "docs/a/b/c.md"))
        self.assertTrue(matches("a/**/b.rs", "a/b.rs"))
        self.assertTrue(matches("a/**/b.rs", "a/x/y/b.rs"))

    def test_bare_name_matches_file_or_directory(self) -> None:
        self.assertTrue(matches("/flake.nix", "flake.nix"))
        self.assertFalse(matches("/flake.nix", "flake.nix.bak"))
        self.assertTrue(matches("/lez/src", "lez/src/main.rs"))

    def test_wildcard_segment_in_directory(self) -> None:
        self.assertTrue(matches("/lez/programs/ping_*/", "lez/programs/ping_core/src/lib.rs"))
        self.assertTrue(matches("/tests/indexer_*", "tests/indexer_helpers/mod.rs"))
        self.assertFalse(matches("/tests/indexer_*", "tests/sub/indexer_x.rs"))

    def test_escaped_space(self) -> None:
        rules = parse_codeowners("/docs/my\\ guide/ @a\n")
        self.assertEqual(rules[0].owners, ["@a"])
        self.assertTrue(rules[0].regex.match("docs/my guide/x.md"))


class ParseTests(unittest.TestCase):
    def test_areas_comments_and_last_match_wins(self) -> None:
        rules = parse_codeowners(
            "# comment\n"
            "/loose @x\n"
            "## Sequencer\n"
            "/seq/ @a @b  # trailing comment\n"
            "\n"
            "## Gossip\n"
            "/seq/gossip/ @c\n"
            "/seq/gossip/legacy.rs\n"
        )
        self.assertEqual([r.area for r in rules], ["Other", "Sequencer", "Gossip", "Gossip"])
        self.assertEqual(rules[1].owners, ["@a", "@b"])
        self.assertIs(matching_rule("seq/core.rs", rules), rules[1])
        self.assertIs(matching_rule("seq/gossip/x.rs", rules), rules[2])
        self.assertEqual(matching_rule("seq/gossip/legacy.rs", rules).owners, [])
        self.assertIsNone(matching_rule("other.rs", rules))


class CommentTests(unittest.TestCase):
    RULES = parse_codeowners(
        "## Sequencer\n/seq/ @alice @Bob\n## Gossip\n/seq/gossip/ @bob\n## Docs\n/docs/ @alice\n"
    )

    def build(self, files: list[str], author: str = "carol") -> str | None:
        return build_comment(files, self.RULES, author, "https://example/CODEOWNERS")

    def test_groups_files_by_owner_and_area(self) -> None:
        body = self.build(["seq/a.rs", "seq/gossip/b.rs", "docs/c.md", "Cargo.lock"])
        assert body is not None
        self.assertTrue(body.startswith(MARKER))
        self.assertIn("| [alice](https://github.com/alice) | Sequencer, Docs | 2 |", body)
        self.assertIn("| [Bob](https://github.com/Bob) | Sequencer, Gossip | 2 |", body)
        self.assertIn("**Gossip** (`/seq/gossip/`)\n\n- `seq/gossip/b.rs`", body)
        self.assertIn("Files without another code owner (1)", body)
        self.assertNotIn("@alice", body)

    def test_excludes_author_case_insensitively(self) -> None:
        body = self.build(["seq/gossip/b.rs", "docs/c.md"], author="BOB")
        assert body is not None
        self.assertNotIn("[Bob]", body)
        self.assertIn("- `seq/gossip/b.rs`", body.split("Files without another code owner")[1])

    def test_none_when_only_author_owns(self) -> None:
        self.assertIsNone(self.build(["docs/c.md", "Cargo.lock"], author="alice"))

    def test_links_files_to_their_diff(self) -> None:
        body = build_comment(
            ["seq/a.rs"], self.RULES, "carol", "https://example/CODEOWNERS", pr_url="https://gh/o/r/pull/7"
        )
        assert body is not None
        self.assertIn(
            "- [`seq/a.rs`](https://gh/o/r/pull/7/files"
            "#diff-b9744b2eb98bc9debfb033e02061bbe5f18d7dae4aa074fca17ac5c8afd2fcdf)",
            body,
        )

    def test_collapses_long_lists(self) -> None:
        body = self.build([f"docs/{i}.md" for i in range(10)])
        assert body is not None
        self.assertIn("<details><summary>10 files</summary>", body)


class RepositoryCodeownersTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.rules = parse_codeowners((REPO_ROOT / ".github/CODEOWNERS").read_text(encoding="utf-8"))
        cls.files = subprocess.run(
            ["git", "ls-files", "--cached", "--others", "--exclude-standard"],
            cwd=REPO_ROOT,
            capture_output=True,
            text=True,
            check=True,
        ).stdout.splitlines()

    def test_every_rule_matches_a_tracked_file(self) -> None:
        stale = [r.pattern for r in self.rules if not any(r.regex.match(path) for path in self.files)]
        self.assertEqual(
            stale, [], "CODEOWNERS rules match no existing file: fix or remove them"
        )

    def test_every_file_matches_a_rule(self) -> None:
        uncovered = [path for path in self.files if matching_rule(path, self.rules) is None]
        self.assertEqual(
            uncovered,
            [],
            "Files missing from CODEOWNERS: give them owners, or list them in the "
            "'Unowned' section if they intentionally have none",
        )


if __name__ == "__main__":
    unittest.main()
