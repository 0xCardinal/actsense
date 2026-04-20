# Untrusted Action Source

## Description

Workflows that use actions from untrusted third-party publishers create supply-chain security risks: actions can contain malicious code, run with your workflow's permissions, access secrets and sensitive data, and may have security vulnerabilities. Actions can be compromised by attackers, enabling supply-chain attacks that affect all workflows using the action. [^gh_actions_security]

## Vulnerable Instance

- Workflow uses an action from an untrusted third-party publisher.
- Action may contain malicious code or have security vulnerabilities.
- Action runs with workflow permissions and can access secrets.

```yaml
name: Build and Notify
on: [push]
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - run: npm ci && npm test
      - uses: rtCamp/action-slack-notify@v2   # Third-party, unaudited publisher
        env:
          SLACK_WEBHOOK: ${{ secrets.SLACK_WEBHOOK }}
```

## Mitigation Strategies

1. **Review the action source code**  
   Visit the action's GitHub repository and review the code for security issues. Check commit history, maintainer activity, and look for security advisories.

2. **Pin to commit SHA**  
   Ensure the action is pinned to a full 40-character commit SHA, not tags. Verify the SHA matches a trusted release.

3. **Consider forking and maintaining your own copy**  
   Fork the action to your organization, review and audit the code, and use your forked version for critical workflows.

4. **Use actions from trusted publishers**  
   Prefer GitHub official actions (`actions/*`), well-known reputable organizations, and actions with active maintenance and security practices.

5. **Regularly review and update actions**  
   Periodically review all third-party actions in your workflows. Monitor for security advisories and update when necessary.

6. **Limit action permissions**  
   Use minimal permissions for workflows that use untrusted actions. Don't grant write permissions unless absolutely necessary.

### Secure Version

Either replace with the official equivalent action (here: the Slack-maintained action) pinned to a full commit SHA, or move the notification logic inline to eliminate the third-party dependency entirely.

**Option A — use the official publisher, pin to a commit SHA:**

```diff
 name: Build and Notify
 on: [push]
 jobs:
   build:
     runs-on: ubuntu-latest
+    permissions:
+      contents: read
     steps:
       - uses: actions/checkout@v4
       - run: npm ci && npm test
-      - uses: rtCamp/action-slack-notify@v2   # Third-party, unaudited publisher
+      - uses: slackapi/slack-github-action@6c661ce58804a1a20f6dc5fbee7f0381b469e001  # Official Slack action, pinned to v2.0.0
         env:
           SLACK_WEBHOOK: ${{ secrets.SLACK_WEBHOOK }}
```

**Option B — remove the dependency by calling the Slack API directly:**

```diff
 name: Build and Notify
 on: [push]
 jobs:
   build:
     runs-on: ubuntu-latest
+    permissions:
+      contents: read
     steps:
       - uses: actions/checkout@v4
       - run: npm ci && npm test
-      - uses: rtCamp/action-slack-notify@v2
-        env:
-          SLACK_WEBHOOK: ${{ secrets.SLACK_WEBHOOK }}
+      - name: Notify Slack
+        env:
+          SLACK_WEBHOOK: ${{ secrets.SLACK_WEBHOOK }}
+        run: |
+          curl -fsSL -X POST -H 'Content-type: application/json' \
+            --data '{"text":"Build complete on ${{ github.ref_name }}"}' \
+            "$SLACK_WEBHOOK"
```

## Impact

| Dimension | Severity | Notes |
| --- | --- | --- |
| Likelihood | ![High](https://img.shields.io/badge/-High-orange?style=flat-square) | Many workflows use third-party actions, and supply-chain attacks through compromised actions are increasing. |
| Risk | ![Medium](https://img.shields.io/badge/-Critical-red?style=flat-square) | Compromised actions can exfiltrate secrets, inject backdoors, or compromise entire CI/CD pipelines. |
| Blast radius | ![Wide](https://img.shields.io/badge/-Wide-yellow?style=flat-square) | Compromised actions can affect all workflows that use them, potentially compromising entire repositories and their secrets. |

## References

- GitHub Docs, "Security hardening for GitHub Actions," https://docs.github.com/en/actions/security-guides/security-hardening-for-github-actions [^gh_actions_security]

---

[^gh_actions_security]: GitHub Docs, "Security hardening for GitHub Actions," https://docs.github.com/en/actions/security-guides/security-hardening-for-github-actions
