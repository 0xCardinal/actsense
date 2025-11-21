# Missing Action Repository

## Description

Workflows that reference actions from repositories that don't exist or are inaccessible will fail at runtime, disrupting CI/CD pipelines and potentially causing production outages. While this may seem like a configuration error, missing action repositories indicate supply-chain risks: if an action was deleted due to security concerns, workflows fail unexpectedly, and poor dependency management can hide other vulnerabilities. [^gh_actions_syntax]

## Vulnerable Instance

- Workflow references an action from a repository that was deleted, made private, moved, or never existed.
- Typo in the action reference (owner, repository name, or path).
- Workflow fails immediately when GitHub Actions tries to resolve the missing action.

```yaml
name: Build with Missing Action
on: [push]
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: non-existent-org/missing-action@v1  # Repository doesn't exist
        with:
          input: value
      - run: npm test
```

## Mitigation Strategies

1. **Verify action references**  
   Check for typos in owner, repository name, or subdirectory paths. Visit `https://github.com/{owner}/{repo}` to confirm the repository exists and is accessible.

2. **Pin to specific versions**  
   Use commit SHAs instead of tags for maximum security and to prevent breakage if repositories are renamed or moved.

3. **Audit dependencies regularly**  
   Periodically scan workflows for missing or deprecated actions. Monitor for repository deletions or security advisories.

4. **Use trusted, well-maintained actions**  
   Prefer actions from official organizations (e.g., `actions/*`) or verified publishers. Consider forking critical actions to your organization.

5. **Test workflows after updates**  
   After changing action references, run workflows in a test environment to catch resolution failures before production.

6. **Have fallback plans**  
   Document alternative actions for critical workflows. If a repository is intentionally deleted, migrate to replacements immediately.

### Secure Version

```diff
 name: Build with Verified Action
 on: [push]
 jobs:
   build:
     runs-on: ubuntu-latest
     steps:
       - uses: actions/checkout@v4
-      - uses: non-existent-org/missing-action@v1  # Repository doesn't exist
+      - uses: actions/setup-node@v4  # Verified, well-maintained action
         with:
-          input: value
+          node-version: '20'
       - run: npm test
```

## Impact

| Dimension | Severity | Notes |
| --- | --- | --- |
| Likelihood | ![Medium](https://img.shields.io/badge/-Medium-yellow?style=flat-square) | Typos and repository deletions are common, but most workflows use verified actions. |
| Risk | ![High](https://img.shields.io/badge/-High-orange?style=flat-square) | Workflow failures disrupt CI/CD, cause deployment delays, and can impact production availability. |
| Blast radius | ![Narrow](https://img.shields.io/badge/-Narrow-green?style=flat-square) | Impact is limited to workflows using the missing action, but cascading failures can affect dependent jobs. |

## References

- GitHub Docs, "Workflow syntax for GitHub Actions," https://docs.github.com/en/actions/using-workflows/workflow-syntax-for-github-actions#jobsjob_idstepsuses [^gh_actions_syntax]

---

[^gh_actions_syntax]: GitHub Docs, "Workflow syntax for GitHub Actions," https://docs.github.com/en/actions/using-workflows/workflow-syntax-for-github-actions#jobsjob_idstepsuses
