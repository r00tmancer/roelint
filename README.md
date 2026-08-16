<div align="center">
  <img src="docs/roelint.svg" alt="ROE-Lint logo" width="560">
  <p><strong>Stop out-of-scope commands before they run.</strong></p>
  <p>
    <a href="https://github.com/r00tmancer/roelint/actions/workflows/ci.yml"><img alt="CI" src="https://github.com/r00tmancer/roelint/actions/workflows/ci.yml/badge.svg"></a>
    <a href="LICENSE"><img alt="License: MIT" src="https://img.shields.io/badge/license-MIT-blue.svg"></a>
    <img alt="Python 3.10+" src="https://img.shields.io/badge/python-3.10%2B-3776AB.svg">
    <img alt="SARIF" src="https://img.shields.io/badge/output-SARIF-7B42BC.svg">
  </p>
</div>

ROE-Lint turns an existing Rules of Engagement document into a local policy firewall for human operators, CI pipelines, and AI red-team agents. It blocks out-of-scope commands **before any security tool is executed**.

> [!IMPORTANT]
> ROE-Lint performs static analysis only. It never scans a target, executes a playbook, or grants authorization. Written permission from the system owner remains mandatory.

## Why this exists

Rules of Engagement usually live in a PDF while operations live in terminals, scripts, and agent tool calls. That gap makes simple mistakes expensive: an excluded production host gets swept, an approval expires, or a runtime variable resolves outside the client boundary.

ROE-Lint turns the relevant boundaries into reviewable policy-as-code:

- Local PDF, DOCX, TXT, and Markdown ROE import with no API key
- Source evidence, confidence scores, and an explicit human approval gate
- CIDR, IP, exact-domain, and wildcard-domain scope checks
- Exclusions that always override inclusions
- Authorization expiry checks
- Tool and technique allow/deny policy
- Approval gates for sensitive techniques
- Detection of unresolved shell targets, plaintext secrets, and destructive operations
- Human-readable, JSON, and SARIF output
- A reusable GitHub Action for pull-request gates
- An optional MCP server for AI agents

## 30-second demo

```bash
pipx install roelint

# Convert the client's existing ROE document into a cited, reviewable draft.
roelint import-roe client-roe.pdf -o roe.draft.yml --report roe.review.json

# Review the draft and evidence, then explicitly approve it.
roelint approve-policy roe.draft.yml -o roe.yml --reviewed-by "Analyst Name"

# Check one proposed command. It is inspected, never executed.
roelint check-command --policy roe.yml -- nmap -sV 10.20.10.50
# ERROR ROE002 [command] target '10.20.10.50' is explicitly excluded
#       help: Source: client-roe.pdf, page 4, line 18 — "Payment systems must not be tested."
```

To try the repository version:

```bash
python -m pip install -e ".[dev]"
pytest
```

Or run the zero-persistence CLI container with the current directory mounted read-only:

```bash
docker build -t roelint .
docker run --rm -v "$PWD:/workspace:ro" roelint \
  check examples/playbook.safe.yml -p examples/roe.yml
```

## Import an existing ROE document

You do not have to write YAML from scratch. Give ROE-Lint the customer's existing text-based PDF, DOCX, TXT, or Markdown file:

```bash
roelint import-roe ACME-Rules-of-Engagement.pdf \
  --output roe.draft.yml \
  --report roe.review.json
```

The importer detects:

- in-scope and excluded IPs, CIDRs, URLs, exact domains, and wildcard domains;
- authorization owner and expiry dates;
- permitted tools;
- prohibited techniques and techniques requiring prior approval;
- common English and Turkish ROE wording.

`roe.draft.yml` contains the extracted policy. `roe.review.json` records each decision's source page, line, excerpt, and confidence score. Targets without clear “in scope” or “out of scope” context remain under `scope.unresolved`; they are never silently authorized.

Imported policies are deliberately marked `review.status: draft`. ROE-Lint refuses to use a draft for operational checks. After comparing it with the evidence report:

```bash
roelint approve-policy roe.draft.yml \
  --output roe.yml \
  --reviewed-by "Analyst Name"
```

If owner or expiry wording is unusual, provide those values without editing YAML:

```bash
roelint import-roe client.pdf \
  --owner security@client.example \
  --expires 2026-12-31
```

Scanned/image-only PDFs need OCR before import. Complex or contradictory legal language remains a human review task; ROE-Lint automates transcription and evidence gathering, not authorization.

## Check a command

Use `check-command` in a terminal, shell integration, or agent approval hook. Everything after `--` is treated as data and statically inspected; ROE-Lint never runs it.

```bash
roelint check-command -p roe.yml -- nmap -sV 10.20.4.10
# ROE-Lint: PASS — no policy violations found

roelint check-command -p roe.yml -- nmap -sV 10.20.10.50
# ERROR ROE002 [command] target '10.20.10.50' is explicitly excluded
```

Exit code `0` means allow, `1` means block, and `2` means the input or policy is invalid. Add `--format json` for machine-readable decisions.

## AI agent policy firewall (MCP)

Install the optional MCP integration:

```bash
pipx install "roelint[agent]"
```

Add the local stdio server to any MCP-compatible host:

```json
{
  "mcpServers": {
    "roelint": {
      "command": "roelint-mcp",
      "args": ["--policy", "/absolute/path/to/roe.yml"]
    }
  }
}
```

The server exposes one deliberately narrow tool: `authorize_command(command, targets?)`. It returns `allow` or `block`, findings, engagement ID, and `executed: false`. Agent instructions should require this tool before every security command and treat a block decision as final.

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
      - uses: r00tmancer/roelint@v1
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

## Validation

The parser is covered by English/Turkish scope regression cases and unit tests for wildcard domains, CIDR containment, exclusion precedence, approvals, destructive operations, secret detection, document import, source citations, CLI exit codes, and agent decisions. The synthetic corpus is intentionally described as regression coverage—not a real-world extraction accuracy claim. See [`benchmarks/`](benchmarks/) and run:

```bash
python benchmarks/run.py
```

## Roadmap

- OCR for scanned ROE documents
- Optional local/hosted LLM extraction for complex prose, with deterministic validation
- JSON Schema editor hints and schema validation
- Adapters for Prelude, VECTR, Atomic Red Team, and custom pipelines
- Signed policy/approval envelopes with Sigstore
- Optional OPA/Rego policy backend
- Rate and blackout-window validation
- A stable v1 playbook interchange specification

See [CONTRIBUTING.md](CONTRIBUTING.md) for extension points. Security issues belong in the private channel described in [SECURITY.md](SECURITY.md).

## License

MIT. Use it for lawful, explicitly authorized security work.
