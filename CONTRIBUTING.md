# Contributing to ROE-Lint

ROE-Lint should make authorized operations safer without becoming an execution framework. Contributions that preserve that boundary are welcome.

## Development

```bash
python -m venv .venv
source .venv/bin/activate  # Windows: .venv\Scripts\activate
python -m pip install -e ".[dev]"
ruff check .
mypy src
pytest
```

## Adding a rule

1. Start with the operational failure the rule prevents.
2. Assign a stable rule ID only after maintainers accept the proposal.
3. Add positive, negative, and boundary tests.
4. Prefer parsing over broad regular expressions.
5. Give the user a concrete remediation in `help`.
6. Update the rules table and SARIF metadata.

False positives erode trust in a policy gate. A new detector must include at least one nearby safe case that remains unflagged.

## Safety boundary

Pull requests must not add payload generation, exploitation, credential collection, evasion, persistence, command execution, or target discovery. Integrations should transform an existing plan into ROE-Lint's static playbook format.

Use only RFC 5737, RFC 3849, `.example`, `.test`, or clearly isolated lab targets in tests and documentation.

## Pull requests

Keep changes focused. Explain schema and exit-code compatibility, paste verification output, and complete the safety checklist. Maintainers may request a short threat-model note for parser or policy changes.
