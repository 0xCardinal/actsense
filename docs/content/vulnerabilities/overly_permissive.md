# Overly Permissive

## Description

Workflows with write permissions to GitHub Actions can create, modify, or delete actions in the repository. This is extremely dangerous: if the workflow is compromised, an attacker can inject malicious actions that run in other workflows, persist access through backdoors, or escalate privileges by creating actions with higher permissions. Write access to actions should almost never be granted, as it creates a significant security risk that can affect all workflows in the repository. [^gh_permissions]

## Vulnerable Instance

- Workflow has `permissions: actions: write` or `permissions: write-all`.
- Compromised workflow can create malicious actions that other workflows use.
- Actions can be modified to include backdoors that persist even after the initial compromise.

```yaml
name: Dangerous Workflow
on: [push]
permissions:
  actions: write  # Extremely dangerous!
jobs:
  deploy:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - run: echo "Deploying..."
```

## Mitigation Strategies

1. **Remove write permissions immediately**  
   Change `actions: write` to `actions: read` or remove the permission entirely if not needed. Most workflows do NOT need to modify actions.

2. **Review if truly necessary**  
   Action creation/modification should be done through pull requests with code review, not through workflows. If programmatic action management is required, use a separate, highly restricted workflow with manual approval.

3. **Use branch protection**  
   If you must create/modify actions programmatically, require branch protection rules, manual approval gates, and implement additional security controls.

4. **Consider GitHub Apps**  
   Use GitHub Apps with limited, scoped permissions instead of broad workflow permissions for action management tasks.

5. **Regularly audit permissions**  
   Periodically scan all workflows for unnecessary permissions, especially write access to actions, contents, or packages.

6. **Isolate high-risk workflows**  
   If action modification is absolutely required, isolate it in a separate workflow with minimal permissions, require manual triggers, and implement extensive logging and monitoring.

### Secure Version

```yaml
name: Secure Workflow
on: [push]
permissions:
  contents: read
  actions: read  # Read-only or omit entirely
jobs:
  deploy:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - run: echo "Deploying..."
```

## Impact

| Dimension | Severity | Notes |
| --- | --- | --- |
| Likelihood | ![Low](https://img.shields.io/badge/-Low-green?style=flat-square) | Most workflows don't need action write permissions, but when granted, the risk is extreme. |
| Risk | ![Critical](https://img.shields.io/badge/-Critical-red?style=flat-square) | Compromised workflows can inject persistent backdoors into actions, affecting all workflows that use them. |
| Blast radius | ![Wide](https://img.shields.io/badge/-Wide-yellow?style=flat-square) | Malicious actions can be used by all workflows in the repository, potentially compromising the entire CI/CD pipeline and codebase. |

## References

- GitHub Docs, "Permissions for the GITHUB_TOKEN," https://docs.github.com/en/actions/security-guides/automatic-token-authentication#permissions-for-the-github_token [^gh_permissions]

---

[^gh_permissions]: GitHub Docs, "Permissions for the GITHUB_TOKEN," https://docs.github.com/en/actions/security-guides/automatic-token-authentication#permissions-for-the-github_token
