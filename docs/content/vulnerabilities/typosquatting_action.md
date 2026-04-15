# Typosquatting Action

## Description

Workflows using actions with suspicious naming patterns (similar to popular actions but with slight variations) may be victims of typosquatting attacks: attackers create malicious actions with names similar to legitimate ones (e.g., `actions/checkout` vs `action/checkout`, `actions/setup-node` vs `actions/setup-nodejs`) to trick users into using compromised versions. Typosquatting is a common supply-chain attack vector that can lead to secret exfiltration, code injection, or repository compromise. [^gh_actions_security]

## Vulnerable Instance

- Workflow uses an action with a name suspiciously similar to a popular action.
- Action may be a typosquatting attempt to trick users.
- Malicious action can compromise workflows and exfiltrate secrets.

Common typosquatting patterns seen in the wild:

```yaml
name: Build with Suspicious Actions
on: [push]
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: action/checkout@v4        # missing 's' — should be actions/checkout
      - uses: actions/setup-nodejs@v4   # extra 'js' — should be actions/setup-node
      - uses: github/codeql-actions/analyze@v3  # extra 's' — should be github/codeql-action
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

Correct the action names to the official publishers and pin to full commit SHAs so a re-tagged or re-pointed tag can never silently swap in different code:

```diff
 name: Build with Verified Actions
 on: [push]
 jobs:
   build:
     runs-on: ubuntu-latest
     steps:
-      - uses: action/checkout@v4        # typo — wrong org
+      - uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683  # v4.2.2
-      - uses: actions/setup-nodejs@v4   # typo — wrong action name
+      - uses: actions/setup-node@49933ea5288caeca8642d1e84afbd3f7d6820020  # v4.4.0
-      - uses: github/codeql-actions/analyze@v3  # typo — wrong action name
+      - uses: github/codeql-action/analyze@28deaeda66b76a05916b6923827895f2b14ab387  # v3.28.16
       - run: npm test
```

## Impact

| Dimension | Severity | Notes |
| --- | --- | --- |
| Likelihood | ![Medium](https://img.shields.io/badge/-Medium-yellow?style=flat-square) | Typosquatting attacks are less common but can be effective when users don't carefully verify action names. |
| Risk | ![High](https://img.shields.io/badge/-Critical-red?style=flat-square) | Malicious typosquatting actions can exfiltrate secrets, inject backdoors, or compromise the entire CI/CD pipeline. |
| Blast radius | ![Wide](https://img.shields.io/badge/-Wide-yellow?style=flat-square) | Compromised actions can affect all workflows that use them, potentially compromising the entire repository and its secrets. |

## References

- GitHub Docs, "Security hardening for GitHub Actions," https://docs.github.com/en/actions/security-guides/security-hardening-for-github-actions [^gh_actions_security]

---

[^gh_actions_security]: GitHub Docs, "Security hardening for GitHub Actions," https://docs.github.com/en/actions/security-guides/security-hardening-for-github-actions
