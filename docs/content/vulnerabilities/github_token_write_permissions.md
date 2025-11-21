# GitHub Token Write Permissions

## Description

Even when you avoid `write-all`, a workflow can still enumerate multiple write scopes (`contents`, `issues`, `pull-requests`, `packages`) that the jobs never use. Those scopes persist for the entire workflow run, so any compromised step can still modify branches, PRs, or packages. GitHub’s least-privilege guidance applies here: only request the scopes the job truly needs. [^gh_permissions]

## Vulnerable Instance

- Workflow declares several write scopes even though it just runs tests.

```yaml
permissions:
  contents: write
  pull-requests: write
  issues: write
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - run: npm test
```

## Mitigation Strategies

1. **Inventory scopes**  
   For each `permissions` entry, list the steps that actually need it.
2. **Downgrade unused scopes**  
   Change `write` to `read` if there’s no corresponding `git push`/`gh` usage.
3. **Job-level overrides**  
   Keep workflow-level permissions read-only and grant write only to specific jobs.
4. **Use deployment tokens**  
   For publishing steps, consider GitHub Apps or PATs limited to the target repo.
5. **Document rationale**  
   Leave comments explaining why a write scope exists and when it was reviewed.

### Secure Version

- Workflow defaults to read scopes.
- Only the `deploy` job elevates to `contents: write`. [^gh_permissions]

```yaml
permissions:
  contents: read
  pull-requests: read
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - run: npm test
  deploy:
    needs: test
    if: github.ref == 'refs/heads/main'
    permissions:
      contents: write
    steps:
      - run: ./scripts/deploy.sh
```

## Impact

| Dimension | Severity | Notes |
| --- | --- | --- |
| Likelihood | ![High](https://img.shields.io/badge/-High-orange?style=flat-square) | Workflows often copy permission blocks without pruning scopes. |
| Risk | ![High](https://img.shields.io/badge/-High-orange?style=flat-square) | Extra write scopes let attackers tamper with code, PRs, or issues. |
| Blast radius | ![Wide](https://img.shields.io/badge/-Wide-yellow?style=flat-square) | All repository areas covered by the granted scopes are exposed. |

## References

- GitHub Docs, “Assigning permissions to jobs,” https://docs.github.com/actions/using-jobs/assigning-permissions-to-jobs [^gh_permissions]
- GitHub Docs, “Security hardening for GitHub Actions,” https://docs.github.com/actions/security-guides/security-hardening-for-github-actions

---

[^gh_permissions]: GitHub Docs, “Assigning permissions to jobs,” https://docs.github.com/actions/using-jobs/assigning-permissions-to-jobs