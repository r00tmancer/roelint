# feat: ship ROE-Lint v0.1 pre-flight policy engine

## What changed

This PR introduces the first usable ROE-Lint release: a static, vendor-neutral policy gate for authorized red-team playbooks. It checks targets and operations against a machine-readable Rules of Engagement file before anything reaches an execution tool.

The MVP includes scope/exclusion matching for IPs, CIDRs, URLs, exact domains, and wildcard domains; authorization expiry; tool and technique policy; explicit approval gates; destructive-operation and plaintext-secret checks; unresolved-target warnings; text/JSON/SARIF output; and a reusable GitHub Action.

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
roelint check examples/playbook.safe.yml -p examples/roe.yml
roelint check examples/playbook.blocked.yml -p examples/roe.yml
```

## Review focus

1. Scope matching semantics, especially wildcard apex behavior and CIDR containment
2. False positives around command target extraction
3. Stability of rule IDs and exit codes before the first public release
4. Whether the v1 interchange schema is small enough for external adapters

## Follow-ups

- Publish JSON Schemas and editor hints
- Add signed policy/approval envelopes
- Prototype Atomic Red Team and VECTR exporters
- Upload SARIF in the example workflow
