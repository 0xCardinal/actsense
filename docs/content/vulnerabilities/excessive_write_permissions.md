# Excessive Write Permissions

## Description

GitHub Actions defaults the `GITHUB_TOKEN` to `contents: read` / `packages: write`, but many workflows override `permissions: write-all` even when they only run tests or lint. If an attacker compromises that workflow (e.g., via dependency injection), they gain repository write access, allowing them to push malicious commits. GitHub recommends the principle of least privilege: grant only the scopes required per job. [^gh_permissions]

## Vulnerable Instance

- Workflow sets `permissions: write-all`.
- Jobs run read-only operations like linting or tests.
- Tokens unnecessarily grant push permissions.

```yaml
name: CI
on: pull_request
permissions: write-all
jobs:
  lint:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - run: npm run lint
```

If a malicious dependency escapes the lint job, it can use the token to push commits or create releases.

## Mitigation Strategies

1. **Set minimal global permissions**  
   Start workflows with `permissions: read-all` or specify exact read scopes.
2. **Grant write per job**  
   Only jobs that publish artifacts or tag releases should request write scopes.
3. **Audit third-party actions**  
   Ensure actions you use don’t require elevated permissions; update or replace if they do.
4. **Split workflows**  
   Keep read-only CI separate from deployment workflows requiring write access.
5. **Monitor token use**  
   Add logging around `git push`/`gh` commands to detect unexpected writes.

### Secure Version

- Global permissions set to read.
- Deployment job elevates to `contents: write` only when needed.
- Comments explain why elevated permissions exist. [^gh_permissions]

```yaml
name: CI
on: pull_request
permissions:
  contents: read
  pull-requests: write
jobs:
  lint:
    runs-on: ubuntu-latest
    permissions:
      contents: read
    steps:
      - uses: actions/checkout@v4
      - run: npm run lint
  deploy:
    needs: lint
    if: github.ref == 'refs/heads/main'
    permissions:
      contents: write
    steps:
      - run: ./scripts/deploy.sh
```

## Impact

| Dimension | Severity | Notes |
| --- | --- | --- |
| Likelihood | ![High](https://img.shields.io/badge/-High-orange?style=flat-square) | Many workflows inherit `write-all` from templates or tutorials. |
| Risk | ![High](https://img.shields.io/badge/-High-orange?style=flat-square) | Excess permissions let attackers overwrite code, create releases, or leak secrets. |
| Blast radius | ![Wide](https://img.shields.io/badge/-Wide-yellow?style=flat-square) | A single compromised job threatens the entire repository and dependent deployments. |

## References

- GitHub Docs, “Assigning permissions to jobs,” https://docs.github.com/actions/using-jobs/assigning-permissions-to-jobs [^gh_permissions]
- GitHub Docs, “Security hardening for GitHub Actions,” https://docs.github.com/actions/security-guides/security-hardening-for-github-actions

---

[^gh_permissions]: GitHub Docs, “Assigning permissions to jobs,” https://docs.github.com/actions/using-jobs/assigning-permissions-to-jobs