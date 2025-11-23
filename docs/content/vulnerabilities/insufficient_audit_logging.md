# Insufficient Audit Logging

## Description

Deploy or publishing jobs that fetch secrets, push artifacts, or touch production often run without structured logging. If a credential is abused, there’s no trace of which workflow step used it, when, or with what parameters—making incident response nearly impossible. GitHub recommends emitting explicit audit logs (to stdout or external systems) for sensitive steps and using the organization audit log for GitHub-native events. [^gh_audit_log]

## Vulnerable Instance

- Workflow publishes a package using production credentials.
- No step logs who triggered the workflow, which version was deployed, or where artifacts were pushed.

```yaml
name: Publish
on: workflow_dispatch
jobs:
  publish:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Publish package
        env:
          NPM_TOKEN: ${{ secrets.NPM_TOKEN }}
        run: npm publish
```

If the token leaks or is abused, there’s no record tying the action to a human or artifact.

## Mitigation Strategies

1. **Log sensitive steps**  
   Emit structured JSON (timestamp, actor, commit SHA, artifact metadata) before and after deployments.
2. **Store logs centrally**  
   Ship logs to CloudWatch, Stackdriver, or another SIEM with retention and tamper protection.
3. **Capture context**  
   Include workflow ID, run URL, triggering user, inputs, and exit status in each log entry.
4. **Alert on anomalies**  
   Configure rules for unexpected branches, repeated failures, or off-hours deployments.
5. **Leverage GitHub audit log**  
   Enable org-level audit logging and correlate workflow events with GitHub-generated records. [^gh_audit_log]

### Secure Version

```diff
 name: Publish
 on: workflow_dispatch
 jobs:
   publish:
     runs-on: ubuntu-latest
     steps:
       - uses: actions/checkout@v4
+      - name: Log deployment start
+        run: |
+          echo "{\"event\":\"deploy_start\",\"run\":\"${{ github.run_id }}\",\"sha\":\"${{ github.sha }}\",\"actor\":\"${{ github.actor }}\"}" >> audit.log
       - name: Publish package
         env:
           NPM_TOKEN: ${{ secrets.NPM_TOKEN }}
         run: npm publish
+      - name: Ship audit log
+        run: curl -X POST https://logging.example.com -H "Content-Type: application/json" --data-binary @audit.log
```

## Impact

| Dimension | Severity | Notes |
| --- | --- | --- |
| Likelihood | ![Medium](https://img.shields.io/badge/-Medium-yellow?style=flat-square) | Logging is often skipped to keep workflows simple. |
| Risk | ![Low](https://img.shields.io/badge/-High-orange?style=flat-square) | Lack of logs blocks incident response and compliance reporting. |
| Blast radius | ![Medium](https://img.shields.io/badge/-Medium-yellow?style=flat-square) | Any environment touched by the workflow becomes opaque to investigations. |

## References

- GitHub Docs, “Viewing your audit log,” https://docs.github.com/enterprise-cloud@latest/admin/monitoring-activity-in-your-enterprise/auditing-a-users-actions/viewing-your-audit-log [^gh_audit_log]
- GitHub Docs, “Security hardening for GitHub Actions,” https://docs.github.com/actions/security-guides/security-hardening-for-github-actions

---

[^gh_audit_log]: GitHub Docs, “Viewing your audit log,” https://docs.github.com/enterprise-cloud@latest/admin/monitoring-activity-in-your-enterprise/auditing-a-users-actions/viewing-your-audit-log