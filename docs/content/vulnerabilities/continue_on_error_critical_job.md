# Continue-on-Error Critical Job

## Description

Marking a critical deployment or verification step with `continue-on-error: true` hides failures—CI passes even when that step fails, so broken releases or incomplete security checks reach production. GitHub advises using explicit `if:` conditions for optional steps instead of swallowing errors. [^gh_continue_on_error]

## Vulnerable Instance

- Critical job (build, test, deploy) sets `continue-on-error: true` on key steps.
- Downstream jobs rely on artifacts or state from that step.
- Failure logs are ignored, so branch protection sees a green check even when the step fails.

```yaml
name: Deploy
on: workflow_dispatch
jobs:
  release:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Run database migrations
        continue-on-error: true
        run: ./scripts/migrate.sh
      - name: Deploy app
        run: ./scripts/deploy.sh
```

If `migrate.sh` fails, the job still reports success and continues with deploy, leaving databases inconsistent.

## Mitigation Strategies

1. **Remove `continue-on-error` from critical steps**  
   Fail fast so branch protection and humans see the error.
2. **Use conditional execution for optional checks**  
   Replace `continue-on-error` with `if: failure()` or dedicated jobs that can fail independently.
3. **Add retries instead of ignoring errors**  
   Wrap flaky commands with retry logic or backoff scripts.
4. **Emit explicit status artifacts**  
   If a step is optional, write clear logs/artifacts and gate downstream jobs on their presence.
5. **Document exception handling**  
   If swallowing errors is unavoidable, explain the rationale in comments and alert channels.

### Secure Version

```diff
 name: Deploy (Safe)
 on: workflow_dispatch
 jobs:
+  validate:
+    runs-on: ubuntu-latest
+    steps:
+      - uses: actions/checkout@v4
+      - name: Smoke tests
+        run: npm run test:smoke
+      - name: Optional telemetry
+        if: ${{ always() }}
+        run: ./scripts/report-telemetry.sh || echo "Telemetry failed"
+
   release:
+    needs: validate
     runs-on: ubuntu-latest
     steps:
       - uses: actions/checkout@v4
       - name: Run database migrations
-        continue-on-error: true
         run: ./scripts/migrate.sh
       - name: Deploy app
         run: ./scripts/deploy.sh
```

## Impact

| Dimension | Severity | Notes |
| --- | --- | --- |
| Likelihood | ![Medium](https://img.shields.io/badge/-Medium-yellow?style=flat-square) | Teams often enable `continue-on-error` temporarily and forget to remove it. |
| Risk | ![Medium](https://img.shields.io/badge/-High-orange?style=flat-square) | Hidden failures push broken builds or skip security gates. |
| Blast radius | ![Wide](https://img.shields.io/badge/-Wide-yellow?style=flat-square) | All downstream deployments, migrations, or releases rely on the silently failing step. |

## References

- GitHub Docs, “jobs.<job_id>.steps[].continue-on-error,” https://docs.github.com/actions/using-jobs/using-jobs-in-a-workflow#jobsjob_idstepscontinue-on-error [^gh_continue_on_error]
- GitHub Docs, “Workflow syntax for GitHub Actions,” https://docs.github.com/actions/using-workflows/workflow-syntax-for-github-actions#jobsjob_idstepscontinue-on-error

---

[^gh_continue_on_error]: GitHub Docs, “jobs.<job_id>.steps[].continue-on-error,” https://docs.github.com/actions/using-jobs/using-jobs-in-a-workflow#jobsjob_idstepscontinue-on-error