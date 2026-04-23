# Dangerous Event

GitHub Actions runs workflow code from **trusted workflow definitions** on the default branch for most events. The security question is: who can **start a run**, what **untrusted data** (titles, bodies, branch names, artifacts) reaches the job, and what **token and secrets** it receives. Some combinations—externally controllable events plus secrets, write defaults, and unsafe use of user-controlled fields in `run:` steps or expressions—are how many public-repo compromises start.

## High-risk trigger families

| Trigger or family | Typical abuse / what to watch for | Related ActSense docs |
| --- | --- | --- |
| `pull_request_target` | Runs with the **base repo** token; checking out or executing the PR head (`pull_request.head.sha`, etc.) lets fork content run with maintainer-level access. | [Insecure Pull Request Target](/vulnerabilities/insecure_pull_request_target/), [Unsafe Checkout](/vulnerabilities/unsafe_checkout/), [Unsafe Checkout Ref](/vulnerabilities/unsafe_checkout_ref/), [Environment Bypass Risk](/vulnerabilities/environment_bypass_risk/) |
| `pull_request` | **Restricted** token for forks by default; lower secret exposure than `pull_request_target`, but branch names, titles, and bodies are still **untrusted** in expressions and shells. | [Risky Context Usage](/vulnerabilities/risky_context_usage/), [Script Injection](/vulnerabilities/script_injection/), [Shell Injection](/vulnerabilities/shell_injection/) |
| `workflow_run` | Downstream workflows run when another finishes; a **compromised upstream** can chain into deploys or jobs that trust **parent artifacts** without verification. | [Artifact Exposure Risk](/vulnerabilities/artifact_exposure_risk/) (see also sections below) |
| `issues`, `issue_comment` | Titles, bodies, and comments are **attacker-controlled** for anyone who can open or comment. | [Risky Context Usage](/vulnerabilities/risky_context_usage/), [Self Hosted Runner Issue Exposure](/vulnerabilities/self_hosted_runner_issue_exposure/) (public repo + self-hosted) |
| `discussion`, `discussion_comment` | Same as issues: **untrusted text** in discussions and replies. | [Risky Context Usage](/vulnerabilities/risky_context_usage/) |
| `fork`, `watch` (and similar) | Low cost for an attacker to trigger; dangerous if the workflow does **sensitive work** on every run. Often pairs with [Risky Context Usage](/vulnerabilities/risky_context_usage/) or `workflow_run` chains. | [Risky Context Usage](/vulnerabilities/risky_context_usage/) |
| `workflow_call` | Callers pass **inputs**; optional or unvalidated inputs can reach dangerous steps. | [Unvalidated Workflow Input](/vulnerabilities/unvalidated_workflow_input/) |

Self-hosted runners increase impact for most of the above. See [Self Hosted Runner](/vulnerabilities/self_hosted_runner/), [Self Hosted Runner PR Exposure](/vulnerabilities/self_hosted_runner_pr_exposure/), and [Self Hosted Runner Issue Exposure](/vulnerabilities/self_hosted_runner_issue_exposure/).

## General mitigation patterns

1. **Match trigger to trust** — Prefer `pull_request` to build and test **fork** code; use `pull_request_target` only in narrow patterns that never run fork code with elevated tokens ([Insecure Pull Request Target](/vulnerabilities/insecure_pull_request_target/)).
2. **Treat payloads as hostile** — Use environment variables, quoting, and allow-lists; see [Risky Context Usage](/vulnerabilities/risky_context_usage/) and [Code Injection via Input](/vulnerabilities/code_injection_via_input/).
3. **Tighten chains** — For `workflow_run`, filter by workflow, branch, and conclusion; verify artifacts (sections below and [Artifact Exposure Risk](/vulnerabilities/artifact_exposure_risk/)).
4. **Least privilege** — Default `permissions` to read-only where possible.
5. **Pin actions** — See [No Hash Pinning](/vulnerabilities/no_hash_pinning/) and related supply-chain pages.

## `workflow_run` dependency chains

### Description

`workflow_run` triggers execute whenever another workflow finishes—meaning any compromised workflow can automatically launch the dependent job with its token and permissions. Without strict filtering, attackers can escalate privileges, trigger cascading deployments, or farm artifacts from trusted jobs. GitHub recommends using `workflow_call` for reusable logic and tightening filters when `workflow_run` is unavoidable. [^gh_workflow_run]

### Vulnerable Instance

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

### Mitigation Strategies

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

#### Secure Version

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

### Impact

| Dimension | Severity | Notes |
| --- | --- | --- |
| Likelihood | ![Medium](https://img.shields.io/badge/-Medium-yellow?style=flat-square) | Teams often chain workflows for releases without adding filters. |
| Risk | ![High](https://img.shields.io/badge/-High-orange?style=flat-square) | Compromised upstream jobs can force deployments or exfiltrate secrets. |
| Blast radius | ![Wide](https://img.shields.io/badge/-Wide-yellow?style=flat-square) | Any downstream environment or release pipeline triggered by the workflow is affected. |

## References

- GitHub Security Lab, “GitHub Actions: Preventing pwn requests,” https://securitylab.github.com/resources/github-actions-preventing-pwn-requests/
- GitHub Security Lab, “Untrusted input in GitHub Actions,” https://securitylab.github.com/research/github-actions-untrusted-input/
- GitHub Docs, “Events that trigger workflows,” https://docs.github.com/actions/using-workflows/events-that-trigger-workflows
- GitHub Docs, “Events that trigger workflows: workflow_run,” https://docs.github.com/actions/using-workflows/events-that-trigger-workflows#workflow_run [^gh_workflow_run]
- GitHub Docs, “Reusing workflows,” https://docs.github.com/actions/using-workflows/reusing-workflows

---

[^gh_workflow_run]: GitHub Docs, “Events that trigger workflows: workflow_run,” https://docs.github.com/actions/using-workflows/events-that-trigger-workflows#workflow_run
