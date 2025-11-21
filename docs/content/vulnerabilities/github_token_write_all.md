# GitHub Token Write-All

## Description

Setting `permissions: write-all` grants the workflow token write access to every API scope (contents, issues, packages, etc.). Attackers who compromise a single job can use that token to push malicious commits, publish packages, or tamper with releases. GitHub recommends explicitly enumerating only the scopes you need and defaulting to read. [^gh_token_permissions]

## Vulnerable Instance

- Workflow-level `permissions: write-all`.
- Jobs perform read-only checks (tests, lint) but inherit full write scopes.

```yaml
name: Test
on: pull_request
permissions: write-all
jobs:
  unit:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - run: npm test
```

Compromising `npm test` yields a token with repository-wide write privileges.

## Mitigation Strategies

1. **Set explicit read-only defaults**  
   Use `permissions: read-all` or list only the required read scopes.
2. **Grant write per job**  
   Only deployment/publish jobs should request write scopes.
3. **Review third-party actions**  
   Ensure they do not require `write-all`; replace or fork if necessary.
4. **Monitor token usage**  
   Log `git push` and `gh` commands; alert on unexpected writes.
5. **Adopt branch protection**  
   Combine least privilege with reviews so even if a token is abused, merges still need approval.

### Secure Version

- Global permissions limited to read.
- Deployment job elevates to `contents: write` only when pushing tags. [^gh_token_permissions]

```yaml
name: Test and Release
on:
  pull_request:
  push:
    tags: ["v*"]
permissions:
  contents: read
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - run: npm test
  release:
    if: startsWith(github.ref, 'refs/tags/')
    permissions:
      contents: write
    runs-on: ubuntu-latest
    steps:
      - run: ./scripts/publish.sh
```

## Impact

| Dimension | Severity | Notes |
| --- | --- | --- |
| Likelihood | ![High](https://img.shields.io/badge/-High-orange?style=flat-square) | Many workflow templates still use `write-all`. |
| Risk | ![Critical](https://img.shields.io/badge/-Critical-red?style=flat-square) | Token abuse lets attackers rewrite history or publish trojans. |
| Blast radius | ![Wide](https://img.shields.io/badge/-Wide-yellow?style=flat-square) | Every repository resource accessible via the token is exposed. |

## References

- GitHub Docs, “Assigning permissions to jobs,” https://docs.github.com/actions/using-jobs/assigning-permissions-to-jobs [^gh_token_permissions]
- GitHub Docs, “Security hardening for GitHub Actions,” https://docs.github.com/actions/security-guides/security-hardening-for-github-actions

---

[^gh_token_permissions]: GitHub Docs, “Assigning permissions to jobs,” https://docs.github.com/actions/using-jobs/assigning-permissions-to-jobs