# Deprecated Action

## Description

Running outdated versions of community actions leaves workflows exposed to known vulnerabilities—GitHub often revs `v1` actions multiple times to address security flaws. Attackers monitor repositories for old versions to exploit published advisories. GitHub’s security guides recommend tracking releases and pinning to a secure SHA or major version with security commitments. [^gh_actions_security]

## Vulnerable Instance

- Workflow references a major version that has been retired, such as `actions/upload-artifact@v3`, or an action from an archived repository.
- Or an action in the dependency graph still runs on the removed `node12` / `node16` runtime.
- Action executes with elevated permissions (e.g., `actions/checkout@v1` with `persist-credentials`).

```yaml
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v1
      - uses: actions/setup-node@v1
      - run: npm ci && npm test
```

## How actsense detects this

actsense reports:

- **Known-retired majors**: `actions/upload-artifact` and `actions/download-artifact` below v4 (shut down on GitHub.com in January 2025), `actions/cache` below v3, `actions/checkout` v1, and the v1 majors of `actions/setup-*`.
- **Archived repositories**: any action whose repository is archived.
- **Deprecated runtimes**: any action in the dependency graph whose `action.yml` declares `using: node12` or `using: node16`.

Earlier versions also flagged every `@v1` reference. That heuristic was removed: `v1` is the current major of many maintained actions, and staleness is covered by [older action version](/vulnerabilities/older_action_version/). All findings are **medium**.

## Mitigation Strategies

1. **Audit action versions**  
   Review `uses:` entries for stale majors; subscribe to release feeds.
2. **Upgrade to supported majors**  
   Prefer `v3`/`v4` or later when maintainers announce deprecations.
3. **Pin to SHAs**  
   For third-party actions, pin to a reviewed commit SHA to avoid tag hijacking.
4. **Track security advisories**  
   Enable Dependabot alerts for GitHub Actions or monitor the action repo’s advisories tab.
5. **Document upgrade cadence**  
   Record when action versions were last reviewed and plan periodic updates.

### Secure Version

```diff
 jobs:
   build:
     runs-on: ubuntu-latest
     steps:
-      - uses: actions/checkout@v1
-      - uses: actions/setup-node@v1
+      - uses: actions/checkout@v4
+        with:
+          persist-credentials: false
+      - uses: actions/setup-node@v4
+        with:
+          node-version: 20
       - run: npm ci && npm test
```

## Impact

| Dimension | Severity | Notes |
| --- | --- | --- |
| Likelihood | ![High](https://img.shields.io/badge/-High-orange?style=flat-square) | Many repos pin to default `v1` releases and forget to update. |
| Risk | ![Medium](https://img.shields.io/badge/-High-orange?style=flat-square) | Exploitable vulnerabilities in old action versions give attackers repo or cloud access. |
| Blast radius | ![Wide](https://img.shields.io/badge/-Wide-yellow?style=flat-square) | Every workflow using the deprecated action inherits the risk; builds, releases, deploys all affected. |

## References

- GitHub Docs, “Security hardening for GitHub Actions,” https://docs.github.com/actions/security-guides/security-hardening-for-github-actions [^gh_actions_security]
- GitHub Docs, “Keeping your actions up to date with Dependabot,” https://docs.github.com/code-security/dependabot/working-with-dependabot/keeping-your-actions-up-to-date-with-dependabot

---

[^gh_actions_security]: GitHub Docs, “Security hardening for GitHub Actions,” https://docs.github.com/actions/security-guides/security-hardening-for-github-actions