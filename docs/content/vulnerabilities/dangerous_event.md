# Dangerous Event

## Description

`workflow_run` triggers execute whenever another workflow finishes—meaning any compromised workflow can automatically launch the dependent job with its token and permissions. Without strict filtering, attackers can escalate privileges, trigger cascading deployments, or farm artifacts from trusted jobs. GitHub recommends using `workflow_call` for reusable logic and tightening filters when `workflow_run` is unavoidable. [^gh_workflow_run]

## Vulnerable Instance

- Workflow listens to `workflow_run` for any workflow in the repository.
- No filtering on branches or workflow names.
- Dependent job runs deployments or publishes packages with elevated permissions.

```yaml
name: Auto Deploy
on:
  workflow_run:
    workflows: ["CI"]
    types: [completed]
jobs:
  deploy:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - run: ./scripts/deploy.sh
```

If the upstream `CI` workflow is compromised, it can finish with `completed` and automatically trigger this deployment job.

## Mitigation Strategies

1. **Prefer `workflow_call`**  
   Convert reusable logic to callable workflows requiring explicit invocation.
2. **Strict filters**  
   Restrict `workflows`, `branches`, and require `github.event.workflow_run.conclusion == 'success'`.
3. **Limit permissions**  
   Set `permissions` per job to the minimum needed; avoid inheriting upstream scopes.
4. **Validate upstream artifacts**  
   Verify checksums or signatures before consuming artifacts produced by the triggering workflow.
5. **Audit chains**  
   Document which workflows can trigger others and review them periodically.

### Secure Version

```diff
 name: Auto Deploy (Safe)
 on:
   workflow_run:
-    workflows: ["CI"]
+    workflows: ["Release Build"]
+    branches: [main]
     types: [completed]
 jobs:
   deploy:
+    if: >
+      github.event.workflow_run.conclusion == 'success' &&
+      github.event.workflow_run.head_branch == 'main'
+    permissions:
+      contents: read
+      deployments: write
     runs-on: ubuntu-latest
     steps:
       - uses: actions/checkout@v4
+      - name: Verify artifact signature
+        run: ./scripts/verify.sh "${{ github.event.workflow_run.id }}"
       - name: Deploy
         run: ./scripts/deploy.sh
```

## Impact

| Dimension | Severity | Notes |
| --- | --- | --- |
| Likelihood | ![Medium](https://img.shields.io/badge/-Medium-yellow?style=flat-square) | Teams often chain workflows for releases without adding filters. |
| Risk | ![High](https://img.shields.io/badge/-High-orange?style=flat-square) | Compromised upstream jobs can force deployments or exfiltrate secrets. |
| Blast radius | ![Wide](https://img.shields.io/badge/-Wide-yellow?style=flat-square) | Any downstream environment or release pipeline triggered by the workflow is affected. |

## References

- GitHub Docs, “Events that trigger workflows: workflow_run,” https://docs.github.com/actions/using-workflows/events-that-trigger-workflows#workflow_run [^gh_workflow_run]
- GitHub Docs, “Reusing workflows,” https://docs.github.com/actions/using-workflows/reusing-workflows

---

[^gh_workflow_run]: GitHub Docs, “Events that trigger workflows: workflow_run,” https://docs.github.com/actions/using-workflows/events-that-trigger-workflows#workflow_run