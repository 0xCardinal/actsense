# Hardcoded Container Credentials

## Description

Jobs can run inside a container or spin up service containers that pull from a private registry, authenticating with `container.credentials` / `services.*.credentials`. When the `password` is written as a literal string instead of a secret reference, the registry credential is committed to the workflow file — visible to anyone with read access and preserved permanently in git history. [^gh_container] This is the container-registry equivalent of any other [hardcoded secret](/vulnerabilities/potential_hardcoded_secret/).

## Vulnerable Instance

- A job's `container.credentials.password` or a service's `credentials.password` is a literal value rather than `${{ secrets.* }}`.

```yaml
jobs:
  build:
    runs-on: ubuntu-latest
    container:
      image: ghcr.io/acme/build
      credentials:
        username: ci-bot
        password: ghp_hardcodedTokenValue123456      # hardcoded registry secret
```

## Mitigation Strategies

1. **Reference a secret.** Store the registry token in GitHub Secrets and use `password: ${{ secrets.REGISTRY_TOKEN }}`.
2. **Rotate exposed credentials.** Any password committed to the file (even if removed later) must be rotated, since it remains in history.
3. **Prefer least-privilege tokens** scoped to pull access only.

### Secure Version

```diff
     container:
       image: ghcr.io/acme/build
       credentials:
         username: ci-bot
-        password: ghp_hardcodedTokenValue123456
+        password: ${{ secrets.REGISTRY_TOKEN }}
```

## Impact

| Dimension | Severity | Notes |
| --- | --- | --- |
| Likelihood | ![Low](https://img.shields.io/badge/-Low-green?style=flat-square) | Less common than other secret patterns, but easy to introduce when copying registry logins. |
| Risk | ![High](https://img.shields.io/badge/-High-orange?style=flat-square) | Exposes a working registry credential to anyone with read access and to git history. |
| Blast radius | ![Moderate](https://img.shields.io/badge/-Moderate-yellow?style=flat-square) | Grants access to the container registry and any images/packages it protects. |

## References

- GitHub Docs, "Workflow syntax — jobs.<job_id>.container.credentials," https://docs.github.com/en/actions/using-workflows/workflow-syntax-for-github-actions#jobsjob_idcontainercredentials [^gh_container]
- GitHub Docs, "Using secrets in GitHub Actions," https://docs.github.com/en/actions/security-guides/using-secrets-in-github-actions [^gh_using_secrets]

---

[^gh_container]: GitHub Docs, "Workflow syntax for GitHub Actions," https://docs.github.com/en/actions/using-workflows/workflow-syntax-for-github-actions#jobsjob_idcontainercredentials
[^gh_using_secrets]: GitHub Docs, "Using secrets in GitHub Actions," https://docs.github.com/en/actions/security-guides/using-secrets-in-github-actions
