# Untrusted Action Unpinned

## Description

Untrusted third-party actions that are not pinned to a specific version create critical security risks: the action can be updated by the maintainer at any time, malicious code can be introduced without your knowledge, and attackers who compromise the action repository can inject malicious code that your workflow will automatically use. This is one of the most dangerous supply-chain attack vectors. [^gh_actions_security] [^gh_actions_pinning]

## Vulnerable Instance

- Workflow uses an untrusted third-party action without version pinning.
- Action can be updated to malicious code without your knowledge.
- Workflow will automatically use the compromised version.

```yaml
name: Build
on: [push]
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: untrusted-org/some-action@main  # Unpinned, untrusted
      - run: npm test
```

## Mitigation Strategies

1. **Review the action source code**  
   Visit the action's GitHub repository and review the code for security issues. Check for recent security advisories and maintainer activity.

2. **Pin to a specific commit SHA**  
   Find a specific release or commit, copy the full 40-character commit SHA, and update the workflow to use it: `untrusted-org/some-action@8f4b7f84884ec3e152e95e913f196d7a537752ca`.

3. **Consider forking and maintaining your own copy**  
   Fork the action to your organization, review and audit the code, and use your forked version: `your-org/some-action@<sha>`.

4. **Regularly review and update pinned actions**  
   Periodically review pinned actions for security updates. Use automated tools to suggest updates, but always review before merging.

5. **Monitor for security advisories**  
   Subscribe to security advisories for actions you use. Monitor the action repository for security issues.

6. **Use minimal permissions**  
   Use minimal permissions for workflows that use untrusted actions. Don't grant write permissions unless absolutely necessary.

### Secure Version

```diff
 name: Build
 on: [push]
 jobs:
   build:
     runs-on: ubuntu-latest
+    permissions:
+      contents: read  # Minimal permissions
     steps:
-      - uses: untrusted-org/some-action@main  # Unpinned, untrusted
+      - uses: untrusted-org/some-action@8f4b7f84884ec3e152e95e913f196d7a537752ca  # Pinned SHA
       - run: npm test
```

## Impact

| Dimension | Severity | Notes |
| --- | --- | --- |
| Likelihood | ![High](https://img.shields.io/badge/-High-orange?style=flat-square) | Unpinned untrusted actions are common, and repository compromises can redirect to malicious code. |
| Risk | ![Critical](https://img.shields.io/badge/-Critical-red?style=flat-square) | Compromised actions can exfiltrate secrets, inject backdoors, or compromise entire CI/CD pipelines with minimal detection. |
| Blast radius | ![Wide](https://img.shields.io/badge/-Wide-yellow?style=flat-square) | Compromised actions can affect all workflows that use them, potentially compromising entire repositories and their secrets. |

## References

- GitHub Docs, "Security hardening for GitHub Actions," https://docs.github.com/en/actions/security-guides/security-hardening-for-github-actions [^gh_actions_security]
- GitHub Docs, "Security hardening for GitHub Actions - Using actions," https://docs.github.com/en/actions/security-guides/security-hardening-for-github-actions#using-actions [^gh_actions_pinning]

---

[^gh_actions_security]: GitHub Docs, "Security hardening for GitHub Actions," https://docs.github.com/en/actions/security-guides/security-hardening-for-github-actions
[^gh_actions_pinning]: GitHub Docs, "Security hardening for GitHub Actions - Using actions," https://docs.github.com/en/actions/security-guides/security-hardening-for-github-actions#using-actions
