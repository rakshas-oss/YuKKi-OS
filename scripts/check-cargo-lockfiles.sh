#!/usr/bin/env bash
# Validate every checked-in, independently resolved Cargo lockfile without
# allowing Cargo to rewrite it. Run from any working directory.
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
manifests=(
  "Cargo.toml"
  "guest-worker/Cargo.toml"
  "browser-wasm/Cargo.toml"
)

for relative_manifest in "${manifests[@]}"; do
  manifest="${repo_root}/${relative_manifest}"
  lockfile="$(dirname "${manifest}")/Cargo.lock"

  if [[ ! -f "${manifest}" ]]; then
    echo "Missing expected Cargo manifest: ${relative_manifest}" >&2
    exit 1
  fi
  if [[ ! -f "${lockfile}" ]]; then
    echo "Missing checked-in lockfile for ${relative_manifest}" >&2
    exit 1
  fi

  echo "Validating ${relative_manifest} against its checked-in Cargo.lock"
  cargo metadata \
    --manifest-path "${manifest}" \
    --format-version 1 \
    --locked \
    >/dev/null
done

echo "All checked-in Cargo lockfiles resolve without modification."
