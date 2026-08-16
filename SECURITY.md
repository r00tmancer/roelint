# Security policy

## Supported versions

Until 1.0, only the latest release receives security fixes.

## Reporting a vulnerability

Do not open a public issue for bypasses, parser differentials, secret leakage, or scope-validation flaws. Use GitHub Private Vulnerability Reporting in the repository's **Security → Advisories → Report a vulnerability** flow.

Include a sanitized reproducer, affected version, impact, and suggested mitigation. Do not test against systems you do not own or have explicit permission to assess. Expect acknowledgement within 3 business days and an initial assessment within 7 business days.

## Security model

ROE-Lint is a pre-flight aid, not a sandbox or authorization service. Its inputs are untrusted. It never intentionally executes playbook commands, resolves targets over DNS, or contacts targets. A passing result only means the parsed input matched the supplied policy at lint time.
