# Unpinned Python Packages

## Description

Composite actions that install Python packages without version pinning create security and reproducibility risks: package versions can change between runs, newer versions may introduce security vulnerabilities, and builds are not reproducible. This makes it difficult to track and fix security issues and enables supply-chain attacks through compromised packages. [^gh_actions_security]

## Vulnerable Instance

- Composite action installs Python packages without version pinning (e.g., `pip install requests`).
- Package versions can change between runs, introducing vulnerabilities.
- Builds are not reproducible and difficult to audit.

```yaml
# action.yml
name: 'My Action'
runs:
  using: 'composite'
  steps:
    - run: pip install requests flask  # Unpinned - versions can change
      shell: bash
```

## Mitigation Strategies

1. **Pin packages to specific versions**  
   Use exact version pinning: `pip install requests==2.31.0 flask==3.0.0` instead of `pip install requests flask`.

2. **Use requirements.txt with pinned versions**  
   Create a `requirements.txt` file with pinned versions and install from it: `pip install -r requirements.txt`.

3. **Use pip-tools to generate requirements**  
   Use `pip-compile` to generate `requirements.txt` with pinned versions from a `requirements.in` file. This ensures all transitive dependencies are also pinned.

4. **Regularly update and review**  
   Periodically review pinned versions for security updates. Use automated tools like Dependabot to suggest updates.

5. **Use security scanning tools**  
   Scan `requirements.txt` for known vulnerabilities. Use tools like `pip-audit` or Snyk to detect security issues.

6. **Document dependency management**  
   Establish team guidelines for dependency management. Require version pinning for all Python packages in actions.

### Secure Version

```yaml
# action.yml
name: 'My Action'
runs:
  using: 'composite'
  steps:
    - run: pip install -r requirements.txt  # Pinned versions
      shell: bash

# requirements.txt:
# requests==2.31.0
# flask==3.0.0
```

## Impact

| Dimension | Severity | Notes |
| --- | --- | --- |
| Likelihood | ![High](https://img.shields.io/badge/-High-orange?style=flat-square) | Unpinned Python packages are common, and package updates can introduce vulnerabilities. |
| Risk | ![High](https://img.shields.io/badge/-High-orange?style=flat-square) | Compromised or vulnerable packages can introduce backdoors, exfiltrate secrets, or enable system compromise. |
| Blast radius | ![Medium](https://img.shields.io/badge/-Medium-yellow?style=flat-square) | Impact depends on what the action does, but can affect all workflows that use the composite action. |

## References

- GitHub Docs, "Security hardening for GitHub Actions," https://docs.github.com/en/actions/security-guides/security-hardening-for-github-actions [^gh_actions_security]

---

[^gh_actions_security]: GitHub Docs, "Security hardening for GitHub Actions," https://docs.github.com/en/actions/security-guides/security-hardening-for-github-actions
