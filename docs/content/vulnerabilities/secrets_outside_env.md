# Secrets Used Outside Environment Variables

## Description

Interpolating a secret directly into a `run:` command — `deploy --token ${{ secrets.TOKEN }}` — places the plaintext value on the command line, where it can leak through process listings (`ps`), shell traces (`set -x`), error output, or logs that are not perfectly masked. [^gh_using_secrets] The recommended pattern is to pass the secret through a step `env:` variable and reference the environment variable in the command, which keeps the value out of the command line. Self-hosted runners have an even higher-impact variant covered by [Self Hosted Runner Secrets in Run](/vulnerabilities/self_hosted_runner_secrets_in_run/).

## Vulnerable Instance

- A `run:` step interpolates `${{ secrets.* }}` directly into the command text.

```yaml
jobs:
  deploy:
    runs-on: ubuntu-latest
    steps:
      - run: curl -H "Authorization: Bearer ${{ secrets.API_TOKEN }}" https://api.example.com
        # token appears on the command line / process list
```

## Mitigation Strategies

1. **Pass secrets via `env:`.** Bind the secret to a step environment variable and reference `$VAR` in the command.

   ```yaml
   - env:
       API_TOKEN: ${{ secrets.API_TOKEN }}
     run: curl -H "Authorization: Bearer $API_TOKEN" https://api.example.com
   ```

2. **Quote the variable** (`"$API_TOKEN"`) and avoid echoing it.
3. **Disable command tracing** around secret usage (avoid `set -x` where secrets are handled).

### Secure Version

```diff
     steps:
-      - run: curl -H "Authorization: Bearer ${{ secrets.API_TOKEN }}" https://api.example.com
+      - env:
+          API_TOKEN: ${{ secrets.API_TOKEN }}
+        run: curl -H "Authorization: Bearer $API_TOKEN" https://api.example.com
```

## Impact

| Dimension | Severity | Notes |
| --- | --- | --- |
| Likelihood | ![Medium](https://img.shields.io/badge/-Medium-yellow?style=flat-square) | A very common shortcut when wiring up API calls in run steps. |
| Risk | ![Medium](https://img.shields.io/badge/-Medium-orange?style=flat-square) | Increases the chance a secret leaks via process listings, traces, or imperfectly masked logs. |
| Blast radius | ![Moderate](https://img.shields.io/badge/-Moderate-yellow?style=flat-square) | Limited to the exposed credential, but that credential may be high value. |

## References

- GitHub Docs, "Using secrets in GitHub Actions," https://docs.github.com/en/actions/security-guides/using-secrets-in-github-actions [^gh_using_secrets]
- GitHub Docs, "Security hardening for GitHub Actions," https://docs.github.com/en/actions/security-guides/security-hardening-for-github-actions [^gh_actions_security]

---

[^gh_using_secrets]: GitHub Docs, "Using secrets in GitHub Actions," https://docs.github.com/en/actions/security-guides/using-secrets-in-github-actions
[^gh_actions_security]: GitHub Docs, "Security hardening for GitHub Actions," https://docs.github.com/en/actions/security-guides/security-hardening-for-github-actions
