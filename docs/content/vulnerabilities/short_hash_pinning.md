# Short Hash Pinning

## Description

Workflows that pin actions to short commit SHAs (less than 40 characters) instead of full 40-character SHAs create ambiguity risks: short SHAs can collide with other commits, making it difficult to verify you're using the exact commit intended. While short SHAs are technically acceptable and GitHub resolves them, full 40-character SHAs provide guaranteed uniqueness and are recommended for maximum security and immutability. [^gh_actions_pinning]

## Vulnerable Instance

- Workflow uses a short SHA like `actions/checkout@8f4b7f8` instead of the full 40-character SHA.
- Short SHA may collide with other commits, creating ambiguity.
- Difficult to verify the exact commit being used.

```yaml
name: Build with Short SHA
on: [push]
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@8f4b7f8  # Short SHA - ambiguous
      - run: npm test
```

## Mitigation Strategies

1. **Upgrade to full 40-character SHA**  
   Find the full SHA for the short reference by visiting `https://github.com/{owner}/{repo}/commit/{short-sha}` or using `git rev-parse {short-sha}`.

2. **Copy the full SHA**  
   Use the complete 40-character hexadecimal SHA (e.g., `8f4b7f84884ec3e152e95e913f196d7a537752ca`) instead of short versions.

3. **Verify the full SHA**  
   Ensure the SHA is exactly 40 hexadecimal characters. Verify at `https://github.com/{owner}/{repo}/commit/{full-sha}`.

4. **Automate SHA updates**  
   Use tools like Dependabot or Renovate to suggest SHA updates, but always use full SHAs in workflows.

5. **Audit existing workflows**  
   Periodically scan all workflows for short SHA pinning and migrate to full SHAs for maximum security.

6. **Document pinning policy**  
   Establish team guidelines requiring full 40-character SHA pinning for all third-party actions.

### Secure Version

```yaml
name: Build with Full SHA
on: [push]
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@8f4b7f84884ec3e152e95e913f196d7a537752ca  # Full SHA
      - run: npm test
```

## Impact

| Dimension | Severity | Notes |
| --- | --- | --- |
| Likelihood | ![Medium](https://img.shields.io/badge/-Medium-yellow?style=flat-square) | Short SHA pinning is less common but creates ambiguity risks. Full SHAs are recommended for maximum security. |
| Risk | ![Low](https://img.shields.io/badge/-Low-green?style=flat-square) | Short SHAs are technically acceptable but full SHAs provide guaranteed uniqueness and are recommended for maximum security. |
| Blast radius | ![Narrow](https://img.shields.io/badge/-Narrow-green?style=flat-square) | Impact is limited to potential ambiguity, but full SHAs eliminate any risk of collision or confusion. |

## References

- GitHub Docs, "Security hardening for GitHub Actions - Using actions," https://docs.github.com/en/actions/security-guides/security-hardening-for-github-actions#using-actions [^gh_actions_pinning]

---

[^gh_actions_pinning]: GitHub Docs, "Security hardening for GitHub Actions - Using actions," https://docs.github.com/en/actions/security-guides/security-hardening-for-github-actions#using-actions
