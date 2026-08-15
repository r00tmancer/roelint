# feat: ship ROE-Lint v0.1 pre-flight policy engine

## What changed

This PR introduces the first usable ROE-Lint release: a local, vendor-neutral policy firewall for authorized red-team commands, playbooks, CI pipelines, and AI agents. It checks targets and operations against an approved Rules of Engagement policy before anything reaches an execution tool.

The MVP includes local PDF/DOCX/TXT/Markdown ROE import with cited evidence and mandatory review; single-command and playbook checks; an optional MCP policy server; scope/exclusion matching for IPs, CIDRs, URLs, exact domains, and wildcard domains; authorization expiry; tool and technique policy; explicit approval gates; destructive-operation and plaintext-secret checks; text/JSON/SARIF output; a reusable GitHub Action; Docker packaging; and release automation.

## Why

Engagement boundaries usually live in documents while operational plans live in shell history and automation. Reviewers currently have to compare them by eye. This creates a preventable class of operational incidents, especially when broad CIDRs, runtime variables, and narrow production exclusions overlap.

ROE-Lint makes the boundary reviewable in the same pull request as the playbook, while remaining intentionally incapable of executing it.

## Safety impact

- [x] No command execution behavior was added
- [x] Exclusion precedence is preserved and tested
- [x] Detection logic includes positive, negative, and boundary tests
- [x] Examples use reserved/synthetic targets and no live credentials

## Verification

```text
ruff check .
mypy src
pytest
bandit -q -r src
pip-audit --skip-editable
python benchmarks/run.py
roelint check examples/playbook.safe.yml -p examples/roe.yml
roelint check examples/playbook.blocked.yml -p examples/roe.yml
roelint import-roe examples/roe-source.txt -o roe.draft.yml --report roe.review.json
python -m build
twine check dist/*
```

## Review focus

1. Scope matching semantics, especially wildcard apex behavior and CIDR containment
2. False positives around command target extraction
3. Stability of rule IDs and exit codes before the first public release
4. MCP's deliberately narrow allow/block contract and no-execution boundary
5. Whether the v1 interchange schema is small enough for external adapters

## Follow-ups

- Publish JSON Schemas and editor hints
- Add signed policy/approval envelopes
- Prototype Atomic Red Team and VECTR exporters
- Upload SARIF in the example workflow
