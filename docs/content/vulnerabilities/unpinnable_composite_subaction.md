# Unpinnable Composite Subaction

## Description

Composite actions that use sub-actions with tags or branches instead of commit SHAs create transitive dependency risks: tags and branches can be moved or updated, sub-actions can be updated with malicious code, and security vulnerabilities can be introduced through sub-actions. This makes builds non-reproducible and difficult to audit. Supply-chain attacks can compromise composite actions through their unpinned sub-actions. [^gh_actions_security]

## Vulnerable Instance

- Composite action uses a sub-action with a tag or branch reference instead of a commit SHA.
- Sub-action can be updated with malicious code without the composite action changing.
- Builds are not reproducible and difficult to audit.

```yaml
# action.yml
name: 'My Composite Action'
runs:
  using: 'composite'
  steps:
    - uses: actions/checkout@v4  # Unpinned - can be moved
      with:
        path: src
```

## Mitigation Strategies

1. **Pin all sub-actions to full 40-character commit SHA**  
   Find the commit SHA for the sub-action by visiting the repository's releases page or checking the specific tag/branch. Copy the full 40-character commit SHA.

2. **Update the composite action**  
   Replace tag/branch references with full commit SHAs: `actions/checkout@8f4b7f84884ec3e152e95e913f196d7a537752ca` instead of `actions/checkout@v4`.

3. **Verify the SHA is correct**  
   Ensure the SHA is exactly 40 hexadecimal characters. Verify at `https://github.com/{owner}/{repo}/commit/{sha}`.

4. **Review all sub-actions**  
   Audit all sub-actions in composite actions. Document which sub-actions are used and why.

5. **Regularly update and audit**  
   Periodically review and update sub-action SHAs. Use automated tools to detect outdated or vulnerable sub-actions.

6. **Use dependency scanning**  
   Use tools like Dependabot to monitor sub-actions for security updates, but always pin to specific SHAs.

### Secure Version

```diff
 # action.yml
 name: 'My Composite Action'
 runs:
   using: 'composite'
   steps:
-    - uses: actions/checkout@v4  # Unpinned - can be moved
+    - uses: actions/checkout@8f4b7f84884ec3e152e95e913f196d7a537752ca  # Pinned SHA
       with:
         path: src
```

## Impact

| Dimension | Severity | Notes |
| --- | --- | --- |
| Likelihood | ![High](https://img.shields.io/badge/-High-orange?style=flat-square) | Many composite actions use unpinned sub-actions, creating transitive dependency risks. |
| Risk | ![High](https://img.shields.io/badge/-High-orange?style=flat-square) | Compromised sub-actions can inject malicious code into composite actions, affecting all workflows that use them. |
| Blast radius | ![Wide](https://img.shields.io/badge/-Wide-yellow?style=flat-square) | Compromised composite actions can affect all workflows that use them, potentially compromising entire CI/CD pipelines. |

## References

- GitHub Docs, "Security hardening for GitHub Actions," https://docs.github.com/en/actions/security-guides/security-hardening-for-github-actions [^gh_actions_security]

---

[^gh_actions_security]: GitHub Docs, "Security hardening for GitHub Actions," https://docs.github.com/en/actions/security-guides/security-hardening-for-github-actions
