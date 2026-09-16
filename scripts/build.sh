#!/usr/bin/env bash
# Fetch build tooling only, never provider runtime data. Same exact pin as CI.
set -euo pipefail
cd "$(dirname "$0")/.."
shared=target/shared
ref=4cb9276ca166bee05c04e4c40ad9bca4b1f1065c
mkdir -p "$shared/.github/workflows"
for file in build.sh .github/workflows/ci.yml; do
  curl --fail --silent --show-error --location --proto '=https' --tlsv1.2 \
    "https://raw.githubusercontent.com/dekopon-agents/provider-workflows/$ref/$file" \
    --output "$shared/$file"
done
exec bash "$shared/build.sh" "$@"
