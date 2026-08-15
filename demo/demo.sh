#!/usr/bin/env bash
set -euo pipefail

demo_dir="${TMPDIR:-/tmp}/roelint-demo"
mkdir -p "$demo_dir"

roelint import-roe examples/roe-source.txt \
  --output "$demo_dir/roe.draft.yml" \
  --report "$demo_dir/roe.review.json"

roelint approve-policy "$demo_dir/roe.draft.yml" \
  --output "$demo_dir/roe.yml" \
  --reviewed-by "Demo Analyst"

roelint check-command --policy "$demo_dir/roe.yml" -- nmap -sV 10.20.10.50 || true
