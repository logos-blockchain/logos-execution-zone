#!/usr/bin/env python3
from __future__ import annotations

import json
import re
import sys

# Trailing content hashes: what precedes them names the family.
_GENERATION_SUFFIX = re.compile(r"(-[0-9a-f]{8,})+$")


def superseded(caches: list[dict]) -> list[int]:
    """Per ref because main and dev write the same families; deduplicated
    because pagination can list an entry twice."""
    newest: dict[tuple[str, str], dict] = {}
    stale: list[int] = []
    seen: set[int] = set()
    for cache in caches:
        if cache["id"] in seen:
            continue
        seen.add(cache["id"])
        family = (_GENERATION_SUFFIX.sub("", cache["key"]), cache.get("ref", ""))
        held = newest.get(family)
        if held is None:
            newest[family] = cache
        elif cache["created_at"] > held["created_at"]:
            stale.append(held["id"])
            newest[family] = cache
        else:
            stale.append(cache["id"])
    return sorted(stale)


def main() -> int:
    caches = [json.loads(line) for line in sys.stdin if line.strip()]
    for cache_id in superseded(caches):
        print(cache_id)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
