# No Hash Pinning

## Description

Workflows that pin actions to version tags (e.g., `@v1`, `@v2.0.0`) instead of commit SHAs are vulnerable to supply-chain attacks: tags are mutable—maintainers can move them to different commits, delete and recreate them, or attackers who compromise a repository can redirect tags to malicious code. Your workflow would then automatically use the compromised version on the next run. Commit SHA hashes are immutable and provide guaranteed integrity. [^gh_actions_pinning]

## Vulnerable Instance

- Workflow uses a version tag like `actions/checkout@v4` instead of a commit SHA.
- If the repository is compromised, an attacker could move the `v4` tag to point to malicious code.
- The workflow would automatically pull the malicious version on the next run.

```yaml
name: Build with Tag
on: [push]
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4  # Mutable tag - can be moved
      - run: npm test
```

## Mitigation Strategies

1. **Pin to full commit SHA**  
   Replace tags with the full 40-character commit SHA (e.g., `actions/checkout@8f4b7f84884ec3e152e95e913f196d7a537752ca`). SHAs are immutable and cannot be changed.

2. **Find the SHA for a tag**  
   Visit `https://github.com/{owner}/{repo}/releases/tag/{tag}` or use GitHub CLI: `gh api repos/{owner}/{repo}/git/refs/tags/{tag} | jq -r .object.sha`

3. **Verify SHA correctness**  
   Ensure the SHA is exactly 40 hexadecimal characters. Verify by visiting `https://github.com/{owner}/{repo}/commit/{sha}`.

4. **Automate SHA updates**  
   Use tools like Dependabot or Renovate to suggest SHA updates when new releases are available, but review changes before merging.

5. **Audit existing workflows**  
   Periodically scan all workflows for tag-based pinning and migrate to SHAs. Consider using automated tooling to detect and report unpinned actions.

6. **Document pinning policy**  
   Establish team guidelines requiring SHA pinning for all third-party actions, especially those with write permissions or access to secrets.

### Secure Version

```diff
 name: Build with SHA
 on: [push]
 jobs:
   build:
     runs-on: ubuntu-latest
     steps:
-      - uses: actions/checkout@v4  # Mutable tag - can be moved
+      - uses: actions/checkout@8f4b7f84884ec3e152e95e913f196d7a537752ca  # Immutable SHA
       - run: npm test
```

## Impact

| Dimension | Severity | Notes |
| --- | --- | --- |
| Likelihood | ![High](https://img.shields.io/badge/-High-orange?style=flat-square) | Tag-based pinning is extremely common, and repository compromises or maintainer mistakes can redirect tags. |
| Risk | ![Critical](https://img.shields.io/badge/-Critical-red?style=flat-square) | Compromised actions can steal secrets, modify code, or deploy backdoors with the workflow's permissions. |
| Blast radius | ![Wide](https://img.shields.io/badge/-Wide-yellow?style=flat-square) | All workflows using the compromised action are affected, potentially impacting all CI/CD pipelines and deployments. |

## References

- GitHub Docs, "Security hardening for GitHub Actions - Using actions," https://docs.github.com/en/actions/security-guides/security-hardening-for-github-actions#using-actions [^gh_actions_pinning]

---

[^gh_actions_pinning]: GitHub Docs, "Security hardening for GitHub Actions - Using actions," https://docs.github.com/en/actions/security-guides/security-hardening-for-github-actions#using-actions
