# Older Action Version

## Description

Workflows using older major versions of actions (v1, v2) when newer versions (v3+, v4+) are available expose themselves to known security vulnerabilities that have been patched in later releases. Newer major versions typically include security hardening, improved defaults, better error handling, and compatibility fixes. Staying on outdated versions increases attack surface and may violate security policies requiring up-to-date dependencies. [^gh_actions_security]

## Vulnerable Instance

- Workflow uses `actions/checkout@v2` when `v4` is available with security improvements.
- Older versions may have known CVEs or security advisories.
- Missing security patches and hardened defaults from newer releases.

```yaml
name: Build with Old Action
on: [push]
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v2  # Outdated - v4 available
      - run: npm test
```

## Mitigation Strategies

1. **Check for latest releases**  
   Visit the action repository's releases page (e.g., `https://github.com/{owner}/{repo}/releases`) and look for v3+ or v4+ versions.

2. **Review changelogs**  
   Check release notes for security fixes, patches, breaking changes between major versions, and migration guides.

3. **Update to latest stable version**  
   Upgrade to the latest stable major version. For maximum security, pin to the commit SHA from that release rather than the tag.

4. **Test in non-production first**  
   Test the updated action in a development or staging environment before deploying to production workflows.

5. **Automate version updates**  
   Use Dependabot or Renovate to automatically suggest action version updates, but require review before merging.

6. **Audit all workflows**  
   Periodically scan all workflows for outdated action versions and create a migration plan for critical actions.

### Secure Version

```diff
 name: Build with Latest Action
 on: [push]
 jobs:
   build:
     runs-on: ubuntu-latest
     steps:
-      - uses: actions/checkout@v2  # Outdated - v4 available
+      - uses: actions/checkout@8f4b7f84884ec3e152e95e913f196d7a537752ca  # Latest v4 SHA
       - run: npm test
```

## Impact

| Dimension | Severity | Notes |
| --- | --- | --- |
| Likelihood | ![High](https://img.shields.io/badge/-High-orange?style=flat-square) | Many workflows still use older action versions, and known vulnerabilities in those versions are publicly documented. |
| Risk | ![Medium](https://img.shields.io/badge/-High-orange?style=flat-square) | Older versions may have unpatched CVEs that allow secret leakage, code injection, or privilege escalation. |
| Blast radius | ![Medium](https://img.shields.io/badge/-Medium-yellow?style=flat-square) | Impact depends on the specific vulnerability, but can affect all workflows using the outdated action. |

## References

- GitHub Docs, "Security hardening for GitHub Actions - Using actions," https://docs.github.com/en/actions/security-guides/security-hardening-for-github-actions#using-actions [^gh_actions_security]

---

[^gh_actions_security]: GitHub Docs, "Security hardening for GitHub Actions - Using actions," https://docs.github.com/en/actions/security-guides/security-hardening-for-github-actions#using-actions
