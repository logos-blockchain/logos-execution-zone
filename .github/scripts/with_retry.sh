#!/usr/bin/env bash
set -uo pipefail

with_retry() {
  local command="$1"
  local max_attempts="${2:-3}"
  local attempt=1

  while (( attempt <= max_attempts )); do
    if eval "$command"; then
      return 0
    fi

    if (( attempt < max_attempts )); then
      echo "::warning:: Attempt $attempt failed, cleaning up and retrying..." >&2
      rm -rf target/debug/deps/*.o target/debug/incremental 2>/dev/null || true
      cargo clean -p integration_tests 2>/dev/null || true
      sleep 5
    fi

    (( attempt++ ))
  done

  echo "::error:: Command failed after $max_attempts attempts: $command" >&2
  return 1
}