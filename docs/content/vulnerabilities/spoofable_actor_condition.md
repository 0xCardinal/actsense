# Spoofable Actor Condition

## Description

Workflows sometimes gate privileged behaviour on the actor context — for example `if: github.actor == 'dependabot[bot]'` — to "only run for a trusted user or bot." The `github.actor` and `github.triggering_actor` contexts are **not a reliable trust boundary**: across chained events (`workflow_run`), re-runs, and certain automation flows the effective actor can be influenced, so a check based on it can be bypassed to run the protected path. [^gh_contexts] Actor gates are also a common way people *think* they have restricted a dangerous trigger when they have not.

## Vulnerable Instance

- A job- or step-level `if:` condition compares `github.actor` / `github.triggering_actor` to a specific user or bot to gate sensitive behaviour.

```yaml
on:
  workflow_run:
    workflows: [build]
jobs:
  deploy:
    if: github.actor == 'dependabot[bot]'   # spoofable trust gate
    runs-on: ubuntu-latest
    steps:
      - run: ./deploy.sh
```

## Mitigation Strategies

1. **Do not use the actor as a security control.** Treat `github.actor` as informational only.
2. **Verify the event payload.** For Dependabot, check `github.event.pull_request.user.login` and the event source rather than the actor string.
3. **Use real controls.** Enforce trust with least-privilege `permissions`, environment protection rules with required reviewers, or a GitHub App identity — not a string comparison.
4. **Avoid privileged triggers** where an actor check is your only guard (see [Dangerous Event](/vulnerabilities/dangerous_event/)).

### Secure Version

```diff
 jobs:
   deploy:
-    if: github.actor == 'dependabot[bot]'
     runs-on: ubuntu-latest
+    environment: production   # required reviewers enforce the real gate
     steps:
       - run: ./deploy.sh
```

## Impact

| Dimension | Severity | Notes |
| --- | --- | --- |
| Likelihood | ![Medium](https://img.shields.io/badge/-Medium-yellow?style=flat-square) | Actor-based gates are a common misconception. |
| Risk | ![Medium](https://img.shields.io/badge/-Medium-orange?style=flat-square) | A bypassable gate can expose the protected path to unauthorized triggers. |
| Blast radius | ![Moderate](https://img.shields.io/badge/-Moderate-yellow?style=flat-square) | Depends on what the gated job does — often deploys or privileged automation. |

## References

- GitHub Docs, "Contexts — github context," https://docs.github.com/en/actions/learn-github-actions/contexts#github-context [^gh_contexts]
- GitHub Docs, "Security hardening for GitHub Actions," https://docs.github.com/en/actions/security-guides/security-hardening-for-github-actions [^gh_actions_security]

---

[^gh_contexts]: GitHub Docs, "Contexts," https://docs.github.com/en/actions/learn-github-actions/contexts#github-context
[^gh_actions_security]: GitHub Docs, "Security hardening for GitHub Actions," https://docs.github.com/en/actions/security-guides/security-hardening-for-github-actions
