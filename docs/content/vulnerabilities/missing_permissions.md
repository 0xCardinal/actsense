# Missing Permissions Block

## Description

When a workflow does not declare a `permissions` block — and not every job sets its own — the `GITHUB_TOKEN` falls back to the repository or organization **default** permissions. Depending on repository settings, that default can be the permissive read/write token, granting the workflow far more access than it needs. [^gh_token_permissions] Declaring an explicit, least-privilege `permissions` block at the workflow level (and widening it per job only where required) shrinks the attack surface if the workflow is ever compromised through a malicious dependency, action, or injected command. Related permission findings include [Overly Permissive](/vulnerabilities/overly_permissive/) and [Excessive Write Permissions](/vulnerabilities/excessive_write_permissions/).

## Vulnerable Instance

- The workflow has no top-level `permissions` key.
- At least one job also omits a job-level `permissions` key, so its `GITHUB_TOKEN` uses the repository default.

```yaml
name: CI
on: [push]
jobs:
  test:
    runs-on: ubuntu-latest
    # No permissions declared anywhere — GITHUB_TOKEN uses the repo default,
    # which may include write access to contents, packages, deployments, etc.
    steps:
      - uses: actions/checkout@v4
      - run: make test
```

## Mitigation Strategies

1. **Set a least-privilege default at the workflow level**
   Start from read-only and grant only what is required.

   ```yaml
   permissions:
     contents: read
   ```

2. **Widen per job, not globally**
   If a single job needs to write (for example, to publish a release or push a comment), grant that scope on the job rather than the whole workflow.

   ```yaml
   jobs:
     release:
       permissions:
         contents: write
   ```

3. **Set the organization/repository default to read-only**
   Configure the default `GITHUB_TOKEN` permissions to read-only so workflows must opt in to write access explicitly.

4. **Review token scopes regularly**
   Audit workflows to confirm each declared permission is still required.

### Secure Version

```diff
 name: CI
 on: [push]
+permissions:
+  contents: read
 jobs:
   test:
     runs-on: ubuntu-latest
     steps:
       - uses: actions/checkout@v4
       - run: make test
```

## Impact

| Dimension | Severity | Notes |
| --- | --- | --- |
| Likelihood | ![High](https://img.shields.io/badge/-High-orange?style=flat-square) | Many workflows omit an explicit `permissions` block and silently inherit the repository default. |
| Risk | ![Low](https://img.shields.io/badge/-Low-green?style=flat-square) | Not directly exploitable on its own, but it removes a key mitigation: a compromised step inherits broader token access than necessary. |
| Blast radius | ![Moderate](https://img.shields.io/badge/-Moderate-yellow?style=flat-square) | Depends on the repository default; a write-capable token reachable by a compromised step can modify repository contents and other resources. |

## References

- GitHub Docs, "Assigning permissions to jobs," https://docs.github.com/en/actions/using-jobs/assigning-permissions-to-jobs [^gh_token_permissions]
- GitHub Docs, "Security hardening for GitHub Actions — Using the GITHUB_TOKEN," https://docs.github.com/en/actions/security-guides/security-hardening-for-github-actions#using-the-github_token-in-a-workflow [^gh_actions_security]

---

[^gh_token_permissions]: GitHub Docs, "Assigning permissions to jobs," https://docs.github.com/en/actions/using-jobs/assigning-permissions-to-jobs
[^gh_actions_security]: GitHub Docs, "Security hardening for GitHub Actions," https://docs.github.com/en/actions/security-guides/security-hardening-for-github-actions#using-the-github_token-in-a-workflow
