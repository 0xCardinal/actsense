# Typosquatting Action

## Description

Workflows using actions with suspicious naming patterns (similar to popular actions but with slight variations) may be victims of typosquatting attacks: attackers create malicious actions with names similar to legitimate ones (e.g., `actions/checkout` vs `action/checkout`, `actions/setup-node` vs `actions/setup-nodejs`) to trick users into using compromised versions. Typosquatting is a common supply-chain attack vector that can lead to secret exfiltration, code injection, or repository compromise. [^gh_actions_security]

## Vulnerable Instance

- Workflow uses an action with a name suspiciously similar to a popular action.
- Action may be a typosquatting attempt to trick users.
- Malicious action can compromise workflows and exfiltrate secrets.

```yaml
name: Build with Suspicious Action
on: [push]
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: action/checkout@v4  # Suspicious - should be actions/checkout
      - run: npm test
```

## Mitigation Strategies

1. **Review the action repository**  
   Visit the action's GitHub repository and check repository activity, maintenance, code quality, and security posture. Verify it's the legitimate action you intend to use.

2. **Verify the publisher**  
   Confirm the publisher is trusted and legitimate. Check for security advisories, review repository history, and verify the publisher matches the official organization.

3. **Compare with official action**  
   Compare the action name, repository, and publisher with the official action. Look for subtle differences in spelling, organization name, or repository structure.

4. **Use official actions**  
   Prefer actions from official organizations (e.g., `actions/*`, `github/*`) or verified publishers. Double-check action names before using them.

5. **Report suspicious actions**  
   If you identify a typosquatting attempt, report it to GitHub Security. Review all actions in your workflows for similar patterns.

6. **Pin to commit SHA**  
   Even for trusted actions, pin to specific commit SHAs rather than tags to prevent compromise if the action repository is later compromised.

### Secure Version

```yaml
name: Build with Verified Action
on: [push]
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@8f4b7f84884ec3e152e95e913f196d7a537752ca  # Official, pinned
      - run: npm test
```

## Impact

| Dimension | Severity | Notes |
| --- | --- | --- |
| Likelihood | ![Medium](https://img.shields.io/badge/-Medium-yellow?style=flat-square) | Typosquatting attacks are less common but can be effective when users don't carefully verify action names. |
| Risk | ![Critical](https://img.shields.io/badge/-Critical-red?style=flat-square) | Malicious typosquatting actions can exfiltrate secrets, inject backdoors, or compromise the entire CI/CD pipeline. |
| Blast radius | ![Wide](https://img.shields.io/badge/-Wide-yellow?style=flat-square) | Compromised actions can affect all workflows that use them, potentially compromising the entire repository and its secrets. |

## References

- GitHub Docs, "Security hardening for GitHub Actions," https://docs.github.com/en/actions/security-guides/security-hardening-for-github-actions [^gh_actions_security]

---

[^gh_actions_security]: GitHub Docs, "Security hardening for GitHub Actions," https://docs.github.com/en/actions/security-guides/security-hardening-for-github-actions
