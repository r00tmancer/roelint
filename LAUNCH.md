# ROE-Lint launch checklist

## Before publishing

- [x] Create the public repository as `roelint`.
- [x] Enable Issues and Discussions.
- [x] Enable private vulnerability reporting and Dependabot security updates.
- [x] Protect `main` with required CI, linear history, and resolved conversations.
- [x] Push the repository and open the first draft PR using `PR_BODY.md`.
- [x] Upload `docs/social-preview.png` in the repository's Social preview settings.
- [x] Review and merge PR #2 through CI.
- [x] Tag `v0.1.0` and create a GitHub Release.
- [ ] Reserve the `roelint` name on PyPI and publish with trusted publishing.
- [ ] Move the `v1` tag to the release commit for Action users.

## Launch post angle

**Title:** I built a linter that stops red-team commands when they violate the Rules of Engagement

Lead with the 20-second document-to-policy-to-blocked-PR demo, not a feature list. Drop in a customer's existing sanitized ROE PDF, show the cited draft, then show one narrow production exclusion failing the pull request. The memorable sentence is: “Drop in the ROE you already have; get a policy gate you can review.”

## Distribution

- Submit a concise Show HN post with the design-boundary discussion.
- Share the demo in r/netsec's monthly tool thread after establishing repository history.
- Open adapter issues labeled `good first issue` for Atomic Red Team, VECTR, Prelude, and OPA.
- Ask 3–5 working red-team operators for rule false-positive feedback before announcing 1.0.
- Publish one technical article on exclusion precedence, CIDR containment, and why DNS is intentionally disabled.

Stars cannot be guaranteed. The best levers are a one-command demo, a clear problem statement, trustworthy safety boundaries, fast issue response, and integrations that let existing teams adopt the tool without changing their execution stack.
