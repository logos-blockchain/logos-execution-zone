#!/usr/bin/env python3
from __future__ import annotations

import unittest

from prune_superseded_caches import superseded


def cache(cache_id: int, key: str, created_at: str, ref: str = "refs/heads/dev") -> dict:
    return {"id": cache_id, "key": key, "created_at": created_at, "ref": ref}


class SupersededTests(unittest.TestCase):
    def test_keeps_the_newest_generation_per_family(self) -> None:
        caches = [
            cache(1, "v0-rust-ci-container-tests-Linux-x64-274b8d8d-dafdd865", "2026-11-01T00:00:00Z"),
            cache(2, "v0-rust-ci-container-tests-Linux-x64-274b8d8d-34bf7786", "2026-11-04T00:00:00Z"),
            cache(3, "v0-rust-ci-host-prebuild-nodebug-Linux-x64-5d4fabd5-34bf7786", "2026-11-04T00:00:00Z"),
        ]
        self.assertEqual(superseded(caches), [1])

    def test_order_of_input_does_not_matter(self) -> None:
        newer = cache(2, "v0-rust-a-11111111", "2026-11-04T00:00:00Z")
        older = cache(1, "v0-rust-a-22222222", "2026-11-01T00:00:00Z")
        self.assertEqual(superseded([newer, older]), [1])
        self.assertEqual(superseded([older, newer]), [1])

    def test_distinct_families_never_prune_each_other(self) -> None:
        caches = [
            cache(1, "v0-rust-a-11111111", "2026-11-01T00:00:00Z"),
            cache(2, "v0-rust-b-22222222", "2026-11-04T00:00:00Z"),
        ]
        self.assertEqual(superseded(caches), [])

    def test_the_same_family_on_another_ref_is_never_pruned(self) -> None:
        caches = [
            cache(1, "v0-rust-a-11111111", "2026-11-01T00:00:00Z", ref="refs/heads/dev"),
            cache(2, "v0-rust-a-22222222", "2026-11-04T00:00:00Z", ref="refs/heads/main"),
        ]
        self.assertEqual(superseded(caches), [])

    def test_a_duplicated_listing_entry_counts_once(self) -> None:
        newest = cache(2, "v0-rust-a-11111111", "2026-11-04T00:00:00Z")
        caches = [
            cache(1, "v0-rust-a-22222222", "2026-11-01T00:00:00Z"),
            newest,
            dict(newest),
        ]
        self.assertEqual(superseded(caches), [1])

    def test_a_key_without_hash_suffix_is_its_own_family(self) -> None:
        caches = [
            cache(1, "some-plain-key", "2026-11-01T00:00:00Z"),
            cache(2, "some-plain-key", "2026-11-04T00:00:00Z"),
        ]
        self.assertEqual(superseded(caches), [1])


if __name__ == "__main__":
    unittest.main()
