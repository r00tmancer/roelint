<div align="center">
  <img src="docs/roelint.svg" alt="ROE-Lint logo" width="560">
  <p><strong>Stop out-of-scope commands before they run.</strong></p>
  <p>
    <a href="https://github.com/YOUR_GITHUB_USERNAME/roelint/actions/workflows/ci.yml"><img alt="CI" src="https://github.com/YOUR_GITHUB_USERNAME/roelint/actions/workflows/ci.yml/badge.svg"></a>
    <a href="LICENSE"><img alt="License: MIT" src="https://img.shields.io/badge/license-MIT-blue.svg"></a>
    <img alt="Python 3.10+" src="https://img.shields.io/badge/python-3.10%2B-3776AB.svg">
    <img alt="SARIF" src="https://img.shields.io/badge/output-SARIF-7B42BC.svg">
  </p>
</div>

ROE-Lint is a pre-flight policy engine for authorized red-team and penetration-test playbooks. It compares every declared command and target with a machine-readable Rules of Engagement (ROE) file. Violations fail locally or in CI **before any security tool is executed**.

> [!IMPORTANT]
> ROE-Lint performs static analysis only. It never scans a target, executes a playbook, or grants authorization. Written permission from the system owner remains mandatory.

## Why this exists

Rules of Engagement usually live in a PDF while operations live in terminals, scripts, and agent tool calls. That gap makes simple mistakes expensive: an excluded production host gets swept, an approval expires, or a runtime variable resolves outside the client boundary.

ROE-Lint turns the relevant boundaries into reviewable policy-as-code:

- CIDR, IP, exact-domain, and wildcard-domain scope checks
- Exclusions that always override inclusions
- Authorization expiry checks
- Tool and technique allow/deny policy
- Approval gates for sensitive techniques
- Detection of unresolved shell targets, plaintext secrets, and destructive operations
- Human-readable, JSON, and SARIF output
- A reusable GitHub Action for pull-request gates

## 30-second demo

```bash
pipx install roelint

roelint check examples/playbook.safe.yml --policy examples/roe.yml
# ROE-Lint: PASS — no policy violations found

roelint check examples/playbook.blocked.yml --policy examples/roe.yml
# ERROR ROE002 [excluded-host] target '10.20.10.50' is explicitly excluded
# ERROR ROE002 [outside-scope] target 'example.org' is outside engagement scope
# ERROR ROE005 [unapproved-technique] technique 'credential-access' requires a valid approval
```

To try the repository version:

```bash
python -m pip install -e ".[dev]"
pytest
```

## Policy

```yaml
version: 1

engagement:
  id: ACME-2026-08

authorization:
  owner: security@acme.example
  expires: "2099-12-31"

scope:
  include:
    - 10.20.0.0/16
    - "*.lab.acme.example"
  exclude:
    - 10.20.10.50
    - payments.lab.acme.example

rules:
  allowed_tools: [nmap, curl, nuclei]
  prohibited_techniques: [denial-of-service, data-destruction]
  approval_required: [credential-access, phishing]

approvals:
  CHANGE-4821:
    approved: true
    approver: security@acme.example
```

## Playbook

ROE-Lint consumes a deliberately small, vendor-neutral format. Existing orchestrators can export it without giving ROE-Lint execution privileges.

```yaml
name: ACME lab validation
steps:
  - id: discovery
    technique: network-service-scanning
    command: nmap -sV --max-rate 25 10.20.4.0/24
    targets: [10.20.4.0/24]

  - id: approved-validation
    technique: credential-access
    approval: CHANGE-4821
    command: nuclei -u https://api.lab.acme.example
```

Declare `targets` when a command builds its destination dynamically. ROE-Lint still emits `ROE008` for shell expansion because declared intent and runtime behavior can diverge.

## GitHub Actions

```yaml
name: ROE policy gate
on: [pull_request]

jobs:
  roe:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: YOUR_GITHUB_USERNAME/roelint@v1
        with:
          playbook: ops/playbook.yml
          policy: ops/roe.yml
          fail-on: warning
```

For GitHub Code Scanning, generate SARIF and upload it:

```bash
roelint check ops/playbook.yml -p ops/roe.yml --format sarif -o roelint.sarif
```

## Rules

| ID | Default | What it catches |
|---|---:|---|
| `ROE001` | Error | Invalid or expired authorization |
| `ROE002` | Error | Excluded or out-of-scope target |
| `ROE003` | Error | Tool missing from the reviewed allow-list |
| `ROE004` | Error | Prohibited technique |
| `ROE005` | Error | Missing or invalid approval |
| `ROE006` | Error | Potentially destructive operation |
| `ROE007` | Error | Possible plaintext credential or token |
| `ROE008` | Warning | Missing or dynamically constructed target |
| `ROE009` | Error | Command that cannot be parsed |

## Design boundaries

- **No execution:** static input in, findings out.
- **Exclusion wins:** a broad include can never override a narrow exclusion.
- **No DNS resolution:** lint results do not depend on mutable network state.
- **No implied authorization:** a passing result means the file matches the policy, not that an engagement is legally authorized.
- **Fail closed where it matters:** invalid policies, expired authorization, and unknown tools produce errors.

## Roadmap

- JSON Schema editor hints and schema validation
- Adapters for Prelude, VECTR, Atomic Red Team, and custom pipelines
- Signed policy/approval envelopes with Sigstore
- Optional OPA/Rego policy backend
- Rate and blackout-window validation
- A stable v1 playbook interchange specification

See [CONTRIBUTING.md](CONTRIBUTING.md) for extension points. Security issues belong in the private channel described in [SECURITY.md](SECURITY.md).

## License

MIT. Use it for lawful, explicitly authorized security work.
