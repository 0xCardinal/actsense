# Secrets Access Untrusted

## Description

Workflows that pass secrets to untrusted third-party actions create extreme supply-chain risks: untrusted actions may be malicious, compromised, or contain vulnerabilities that allow secret exfiltration. Actions have access to all secrets passed to them and can log, expose, or exfiltrate credentials. Supply-chain attacks through compromised actions are a primary vector for secret theft in CI/CD pipelines. [^gh_actions_security] [^gh_secrets]

## Vulnerable Instance

- Workflow passes secrets to a third-party action from an untrusted publisher.
- Action may be malicious, compromised, or contain vulnerabilities.
- Secrets can be exfiltrated by the action.

```yaml
name: Build with Untrusted Action
on: [push]
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: untrusted-org/some-action@v1
        with:
          api_key: ${{ secrets.API_KEY }}  # Dangerous - untrusted action
```

## Mitigation Strategies

1. **Verify action trustworthiness**  
   Review action source code, check publisher reputation, verify the action is from a trusted publisher, and review the action's security history.

2. **Use trusted actions**  
   Prefer actions from trusted publishers (`actions/*`, `github/*`) or official actions from well-known organizations. Review third-party actions thoroughly before use.

3. **Minimize secret exposure**  
   Only pass secrets to actions that absolutely need them. Use minimal permissions for actions and consider using GitHub Apps with limited scopes.

4. **Pin to commit SHA**  
   If you must use untrusted actions, pin to a specific commit SHA after reviewing the code. Monitor the action for updates and consider forking and maintaining your own copy.

5. **Review all secret usage**  
   Audit all actions that receive secrets. Document why each action needs secret access and review this regularly.

6. **Use environment secrets**  
   For sensitive operations, use environment secrets with required reviewers instead of repository secrets to add an approval gate.

### Secure Version

```diff
 name: Build with Trusted Action
 on: [push]
 jobs:
   build:
     runs-on: ubuntu-latest
     steps:
       - uses: actions/checkout@v4
-      - uses: untrusted-org/some-action@v1
+      - uses: actions/setup-node@v4  # Trusted, official action
         with:
-          api_key: ${{ secrets.API_KEY }}  # Dangerous - untrusted action
+          node-version: '20'
+      - name: Use secret
+        run: |
+          curl -H "Authorization: Bearer ${{ secrets.API_KEY }}" https://api.example.com
```

## Impact

| Dimension | Severity | Notes |
| --- | --- | --- |
| Likelihood | ![High](https://img.shields.io/badge/-High-orange?style=flat-square) | Many workflows use third-party actions, and supply-chain attacks through compromised actions are increasing. |
| Risk | ![Medium](https://img.shields.io/badge/-Critical-red?style=flat-square) | Compromised actions can exfiltrate all secrets passed to them, enabling full system compromise and persistent access. |
| Blast radius | ![Wide](https://img.shields.io/badge/-Wide-yellow?style=flat-square) | Stolen secrets can affect all systems the secrets authorize, potentially including production infrastructure, databases, and services. |

## References

- GitHub Docs, "Security hardening for GitHub Actions," https://docs.github.com/en/actions/security-guides/security-hardening-for-github-actions [^gh_actions_security]
- GitHub Docs, "Encrypted secrets," https://docs.github.com/en/actions/security-guides/encrypted-secrets [^gh_secrets]

---

[^gh_actions_security]: GitHub Docs, "Security hardening for GitHub Actions," https://docs.github.com/en/actions/security-guides/security-hardening-for-github-actions
[^gh_secrets]: GitHub Docs, "Encrypted secrets," https://docs.github.com/en/actions/security-guides/encrypted-secrets
