# Unpinned Version

## Description

Workflows that use actions with references that don't match standard pinning formats (version tags, commit SHAs, or branches) create security risks: unpinned or incorrectly formatted references can be updated unexpectedly, making it difficult to verify which version is being used. Actions should be pinned to specific version tags or commit SHAs for security and reproducibility. [^gh_actions_pinning]

## Vulnerable Instance

- Workflow uses an action with an unpinned or incorrectly formatted reference.
- Reference doesn't match standard formats (version tag, commit SHA, or branch).
- Action version can change unexpectedly.

```yaml
name: Build
on: [push]
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout  # Unpinned - no version specified
      - run: npm test
```

## Mitigation Strategies

1. **Check the action repository for valid versions**  
   Visit `https://github.com/{owner}/{repo}/releases` to see available version tags and commit SHAs.

2. **Use secure pinning formats**  
   Use one of these formats:
   - Version tag: `actions/checkout@v4`
   - Full commit SHA: `actions/checkout@8f4b7f84884ec3e152e95e913f196d7a537752ca`
   - Short SHA (minimum 7 characters): `actions/checkout@8f4b7f8`

3. **Prefer commit SHAs for maximum security**  
   For maximum security, pin to full 40-character commit SHAs instead of tags. SHAs are immutable and cannot be changed.

4. **Verify reference format**  
   Ensure references follow semantic versioning (v1.2.3) for tags or are valid commit SHAs. Reject invalid formats.

5. **Audit all action references**  
   Periodically scan all workflows for unpinned actions. Use automated tools to detect and report unpinned references.

6. **Document pinning policy**  
   Establish team guidelines requiring action pinning. Require code review for any workflow changes involving action references.

### Secure Version

```diff
 name: Build
 on: [push]
 jobs:
   build:
     runs-on: ubuntu-latest
     steps:
-      - uses: actions/checkout  # Unpinned - no version specified
+      - uses: actions/checkout@8f4b7f84884ec3e152e95e913f196d7a537752ca  # Pinned SHA
       - run: npm test
```

## Impact

| Dimension | Severity | Notes |
| --- | --- | --- |
| Likelihood | ![High](https://img.shields.io/badge/-High-orange?style=flat-square) | Unpinned actions are common, especially in new workflows or during rapid development. |
| Risk | ![High](https://img.shields.io/badge/-High-orange?style=flat-square) | Unpinned actions can be updated to malicious versions, enabling supply-chain attacks and system compromise. |
| Blast radius | ![Wide](https://img.shields.io/badge/-Wide-yellow?style=flat-square) | Compromised actions can affect all workflows that use them, potentially compromising entire CI/CD pipelines. |

## References

- GitHub Docs, "Security hardening for GitHub Actions - Using actions," https://docs.github.com/en/actions/security-guides/security-hardening-for-github-actions#using-actions [^gh_actions_pinning]

---

[^gh_actions_pinning]: GitHub Docs, "Security hardening for GitHub Actions - Using actions," https://docs.github.com/en/actions/security-guides/security-hardening-for-github-actions#using-actions
