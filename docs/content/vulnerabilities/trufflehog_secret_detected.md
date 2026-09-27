# Secret Detected by TruffleHog

## Description

[TruffleHog](https://github.com/trufflesecurity/trufflehog) matched a known credential format (a cloud key, API token, private key, etc.) in the workflow file. Workflow files are readable by anyone with read access to the repository, and every committed value stays in git history even after it is removed. [^gh_secrets] When TruffleHog can confirm the credential against its provider, the finding is **verified** and reported as critical; otherwise it is reported as high until someone confirms it.

## Vulnerable Instance

- A literal credential is written into the workflow instead of being referenced from GitHub Secrets.

```yaml
name: Deploy
on: [push]
jobs:
  deploy:
    runs-on: ubuntu-latest
    steps:
      - run: ./deploy.sh
        env:
          API_TOKEN: EXAMPLE-NOT-A-REAL-TOKEN
```

## Mitigation Strategies

1. **Revoke and rotate first**
   Treat the credential as compromised. Revoke it at the provider and issue a new one before doing anything else.

2. **Move it to GitHub Secrets**
   Store the new value as a repository or environment secret and reference it with `${{ secrets.NAME }}`.

3. **Clean history if required**
   Removing the line does not remove it from git history. Rewrite history (for example with `git filter-repo`) if your policy requires it; rotation is what actually closes the exposure.

4. **Prefer short-lived credentials**
   Where the provider supports OIDC, drop the static secret entirely.

### Secure Version

```diff
       - run: ./deploy.sh
         env:
-          API_TOKEN: EXAMPLE-NOT-A-REAL-TOKEN
+          API_TOKEN: ${{ secrets.API_TOKEN }}
```

## Impact

| Dimension | Severity | Notes |
| --- | --- | --- |
| Likelihood | ![High](https://img.shields.io/badge/-High-orange?style=flat-square) | Public workflow files are scraped for credentials continuously. |
| Risk | ![Critical](https://img.shields.io/badge/-Critical-red?style=flat-square) | A verified credential can be used immediately by anyone who reads the file. |
| Blast radius | ![Wide](https://img.shields.io/badge/-Wide-yellow?style=flat-square) | Whatever the credential can reach, outside of GitHub's control. |

## References

- GitHub Docs, "Using secrets in GitHub Actions," https://docs.github.com/en/actions/security-for-github-actions/security-guides/using-secrets-in-github-actions [^gh_secrets]
- TruffleHog, https://github.com/trufflesecurity/trufflehog

---

[^gh_secrets]: GitHub Docs, "Using secrets in GitHub Actions," https://docs.github.com/en/actions/security-for-github-actions/security-guides/using-secrets-in-github-actions
