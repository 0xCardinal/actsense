# Excessive Secret Exposure

## Description

The `secrets` context can be serialized in bulk with the `toJson(secrets)` expression. Doing so passes **every** secret available to the workflow into a single value, exposing credentials to a step that should only ever need one or two. [^gh_actions_security] If that step runs a third-party action, logs verbosely, crashes with a stack trace, or is itself compromised, the entire secret store is at risk instead of a single credential. This pattern also defeats GitHub's per-value log masking, because a serialized blob may be transformed (encoded, split, or reformatted) before it reaches the log. Related issues are covered in [Secret in Environment](/vulnerabilities/secret_in_environment/) and [Secrets Access Untrusted](/vulnerabilities/secrets_access_untrusted/).

## Vulnerable Instance

- A step uses `${{ toJson(secrets) }}` in a `run` command, an `env:` value, or a `with:` parameter.
- All repository, environment, and organization secrets visible to the workflow are exposed to that step.

```yaml
name: Deploy
on: [push]
jobs:
  deploy:
    runs-on: ubuntu-latest
    steps:
      - name: Configure
        uses: third-party/configure@v1
        env:
          ALL_SECRETS: ${{ toJson(secrets) }}   # exposes every secret at once
```

## Mitigation Strategies

1. **Pass only the secrets a step needs, by name**
   Reference individual secrets explicitly so each step receives the minimum set of credentials.

   ```yaml
   - name: Configure
     uses: third-party/configure@v1
     env:
       API_TOKEN: ${{ secrets.API_TOKEN }}
   ```

2. **Never use `toJson(secrets)`**
   There is no safe production use for serializing the whole secrets context. If you are tempted to use it for debugging, do not — it will leak credentials into logs and artifacts.

3. **Prefer short-lived credentials**
   Use OpenID Connect (OIDC) to obtain short-lived, identity-bound tokens instead of storing and forwarding long-lived secrets. See [Long Term Cloud Credentials](/vulnerabilities/long_term_cloud_credentials/).

4. **Scope secrets to environments**
   Store sensitive secrets at the environment level with required reviewers so they are only available to protected deployment jobs.

### Secure Version

```diff
 name: Deploy
 on: [push]
 jobs:
   deploy:
     runs-on: ubuntu-latest
     steps:
       - name: Configure
         uses: third-party/configure@v1
         env:
-          ALL_SECRETS: ${{ toJson(secrets) }}
+          API_TOKEN: ${{ secrets.API_TOKEN }}
```

## Impact

| Dimension | Severity | Notes |
| --- | --- | --- |
| Likelihood | ![Medium](https://img.shields.io/badge/-Medium-yellow?style=flat-square) | Usually introduced as a debugging shortcut or a misunderstanding of how to pass secrets to an action. |
| Risk | ![High](https://img.shields.io/badge/-High-orange?style=flat-square) | A single leak, crash, or compromised action exposes the workflow's entire secret store rather than one credential. |
| Blast radius | ![Wide](https://img.shields.io/badge/-Wide-yellow?style=flat-square) | All repository, environment, and accessible organization secrets are exposed simultaneously. |

## References

- GitHub Docs, "Security hardening for GitHub Actions — Using secrets," https://docs.github.com/en/actions/security-guides/security-hardening-for-github-actions#using-secrets [^gh_actions_security]
- GitHub Docs, "Using secrets in GitHub Actions," https://docs.github.com/en/actions/security-guides/using-secrets-in-github-actions [^gh_using_secrets]

---

[^gh_actions_security]: GitHub Docs, "Security hardening for GitHub Actions," https://docs.github.com/en/actions/security-guides/security-hardening-for-github-actions
[^gh_using_secrets]: GitHub Docs, "Using secrets in GitHub Actions," https://docs.github.com/en/actions/security-guides/using-secrets-in-github-actions
