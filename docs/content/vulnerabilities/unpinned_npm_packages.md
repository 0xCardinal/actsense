# Unpinned Npm Packages

## Description

Composite actions that install NPM packages without version locking create security and reproducibility risks: package versions can change between runs, newer versions may introduce security vulnerabilities, and builds are not reproducible. This makes it difficult to track and fix security issues and enables supply-chain attacks through compromised packages. [^gh_actions_security]

## Vulnerable Instance

- Composite action installs NPM packages without version locking (e.g., `npm install` without `package-lock.json`).
- Package versions can change between runs, introducing vulnerabilities.
- Builds are not reproducible and difficult to audit.

```yaml
# action.yml
name: 'My Action'
runs:
  using: 'composite'
  steps:
    - run: npm install  # Unpinned - versions can change
      shell: bash
```

## Mitigation Strategies

1. **Use package-lock.json**  
   Commit `package-lock.json` to the repository and use `npm ci` instead of `npm install`. This ensures exact versions are installed.

2. **Specify exact versions in package.json**  
   Use exact versions (e.g., `"package": "1.2.3"`) instead of ranges (e.g., `"package": "^1.2.3"`) in `package.json`.

3. **Use npm ci for CI/CD**  
   Use `npm ci` instead of `npm install` in workflows. `npm ci` uses `package-lock.json` for exact versions and fails if versions don't match.

4. **Regularly update and review**  
   Periodically review package versions for security updates. Use automated tools like Dependabot to suggest updates.

5. **Use security scanning tools**  
   Scan `package-lock.json` for known vulnerabilities. Use tools like `npm audit` or Snyk to detect security issues.

6. **Document dependency management**  
   Establish team guidelines for dependency management. Require `package-lock.json` for all NPM-based actions.

### Secure Version

```yaml
# action.yml
name: 'My Action'
runs:
  using: 'composite'
  steps:
    - run: npm ci  # Uses package-lock.json for exact versions
      shell: bash
```

## Impact

| Dimension | Severity | Notes |
| --- | --- | --- |
| Likelihood | ![High](https://img.shields.io/badge/-High-orange?style=flat-square) | Unpinned NPM packages are common, and package updates can introduce vulnerabilities. |
| Risk | ![High](https://img.shields.io/badge/-High-orange?style=flat-square) | Compromised or vulnerable packages can introduce backdoors, exfiltrate secrets, or enable system compromise. |
| Blast radius | ![Medium](https://img.shields.io/badge/-Medium-yellow?style=flat-square) | Impact depends on what the action does, but can affect all workflows that use the composite action. |

## References

- GitHub Docs, "Security hardening for GitHub Actions," https://docs.github.com/en/actions/security-guides/security-hardening-for-github-actions [^gh_actions_security]

---

[^gh_actions_security]: GitHub Docs, "Security hardening for GitHub Actions," https://docs.github.com/en/actions/security-guides/security-hardening-for-github-actions
