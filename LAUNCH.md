# ROE-Lint launch checklist

## Before publishing

1. Create the public repository as `roelint` and enable:
   - Issues and Discussions
   - Private vulnerability reporting
   - Dependabot security updates
   - Branch protection requiring CI
2. Push this repository and open the first PR using `PR_BODY.md`.
3. Merge through CI, then tag `v0.1.0` and create a GitHub Release.
4. Reserve the `roelint` name on PyPI and publish with trusted publishing.
5. Move the `v1` tag to the release commit for Action users.

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
