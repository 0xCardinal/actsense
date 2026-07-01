# Unpinned Npm Packages

## Description

Workflows and composite actions that install NPM packages without version locking create security and reproducibility risks: package versions can change between runs, newer versions may introduce security vulnerabilities, and builds are not reproducible. This makes it difficult to track and fix security issues and enables supply-chain attacks through compromised packages. [^gh_actions_security]

## Vulnerable Instance

- A workflow `run:` step or composite action installs NPM packages without version locking (for example, `npm install lodash express`).
- Package versions can change between runs, introducing vulnerabilities.
- Builds are not reproducible and difficult to audit.

```yaml
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - run: npm install lodash express  # Unpinned - versions can change
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
   Establish team guidelines for dependency management. Require lockfiles or exact versions for all NPM installs in workflows and actions.

### Secure Version

```diff
 jobs:
   build:
     runs-on: ubuntu-latest
     steps:
-      - run: npm install lodash express
+      - run: npm install lodash@4.17.21 express@4.18.3
```

## Impact

| Dimension | Severity | Notes |
| --- | --- | --- |
| Likelihood | ![High](https://img.shields.io/badge/-High-orange?style=flat-square) | Unpinned NPM packages are common, and package updates can introduce vulnerabilities. |
| Risk | ![High](https://img.shields.io/badge/-High-orange?style=flat-square) | Compromised or vulnerable packages can introduce backdoors, exfiltrate secrets, or enable system compromise. |
| Blast radius | ![Medium](https://img.shields.io/badge/-Medium-yellow?style=flat-square) | Impact depends on where the install runs, but can affect workflow jobs and any action consumers. |

## References

- GitHub Docs, "Security hardening for GitHub Actions," https://docs.github.com/en/actions/security-guides/security-hardening-for-github-actions [^gh_actions_security]

---

[^gh_actions_security]: GitHub Docs, "Security hardening for GitHub Actions," https://docs.github.com/en/actions/security-guides/security-hardening-for-github-actions
