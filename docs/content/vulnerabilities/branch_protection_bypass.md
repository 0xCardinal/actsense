# Branch Protection Bypass

## Description

Workflows that auto-approve or auto-merge pull requests undermine GitHub branch protection: they short-circuit required reviewers, status checks, and manual merges. If an attacker compromises CI, or if a bug slips in, code can flow to protected branches without human oversight, voiding the controls branch protection is meant to provide. [^gh_branch_protection]

## Vulnerable Instance

- Workflow triggers on `pull_request` or `pull_request_target`.
- Uses an action (e.g., `peter-evans/enable-pull-request-merge`) or CLI command (`gh pr merge --auto`) that approves/merges PRs automatically. [^gh_auto_merge]
- Runs with default `GITHUB_TOKEN` write permissions, so the auto-merge succeeds even when branch protection expects reviewers.

```yaml
name: Auto Merge Dangerous
on:
  pull_request:
    branches: [ main ]
jobs:
  auto-approve-and-merge:
    permissions: write-all
    runs-on: ubuntu-latest
    steps:
      - name: Auto approve PR
        run: gh pr review "$PR_URL" --approve
        env:
          PR_URL: ${{ github.event.pull_request.html_url }}
      - name: Auto merge PR
        uses: peter-evans/enable-pull-request-merge@v3
        with:
          token: ${{ secrets.GITHUB_TOKEN }}
          merge_method: squash
```

## Mitigation Strategies

1. **Remove automation that bypasses reviewers**  
   Delete auto-approval/merge steps or replace them with manual review workflows (`workflow_run` plus approval gates).
2. **Enforce branch protection in GitHub settings**  
   Require at least one review, enable “Require status checks to pass,” and block force pushes.
3. **Restrict workflow permissions**  
   Set `permissions: { contents: read }` by default and elevate only in dedicated release workflows reviewed by humans.
4. **Add reviewer confirmation steps**  
   Use `workflow_dispatch` with required inputs or GitHub’s built-in review system so humans must acknowledge the change.
5. **Monitor for bypass keywords**  
   Periodically scan workflows for `auto-approve`, `auto-merge`, `gh pr review`, `gh pr merge`, or similar commands.

### Secure Version

```diff
 name: Lint & Gate
 on:
   pull_request:
     branches: [ main ]
 jobs:
-  auto-approve-and-merge:
-    permissions: write-all
+  checks:
+    permissions:
+      contents: read
+      pull-requests: write
     runs-on: ubuntu-latest
     steps:
       - uses: actions/checkout@v4
       - run: npm test
-      - name: Auto approve PR
-        run: gh pr review "$PR_URL" --approve
-        env:
-          PR_URL: ${{ github.event.pull_request.html_url }}
-      - name: Auto merge PR
-        uses: peter-evans/enable-pull-request-merge@v3
-        with:
-          token: ${{ secrets.GITHUB_TOKEN }}
-          merge_method: squash
+  require-review:
+    needs: checks
+    runs-on: ubuntu-latest
+    permissions:
+      contents: read
+    steps:
+      - name: Notify reviewers
+        run: echo "All checks passed—waiting for human approval."
```

## Impact

| Dimension | Severity | Notes |
| --- | --- | --- |
| Likelihood | ![High](https://img.shields.io/badge/-High-orange?style=flat-square) | Auto-merge helpers are common in CI templates, especially for dependency updates. |
| Risk | ![Critical](https://img.shields.io/badge/-Critical-red?style=flat-square) | Bypassing branch protection enables unreviewed code (or attacker payloads) to land on protected branches. |
| Blast radius | ![Wide](https://img.shields.io/badge/-Wide-yellow?style=flat-square) | Compromised main/default branches impact every downstream deployment, release, or package built from them. |

## References

- GitHub Docs, “Managing a branch protection rule,” https://docs.github.com/en/repositories/configuring-branches-and-merges-in-your-repository/defining-the-mergeability-of-pull-requests/managing-a-branch-protection-rule [^gh_branch_protection]
- GitHub Docs, “Automatically merging a pull request,” https://docs.github.com/en/pull-requests/collaborating-with-pull-requests/incorporating-changes-from-a-pull-request/automatically-merging-a-pull-request [^gh_auto_merge]

[^gh_branch_protection]: GitHub Docs, “Managing a branch protection rule,” https://docs.github.com/en/repositories/configuring-branches-and-merges-in-your-repository/defining-the-mergeability-of-pull-requests/managing-a-branch-protection-rule

[^gh_auto_merge]: GitHub Docs, “Automatically merging a pull request,” https://docs.github.com/en/pull-requests/collaborating-with-pull-requests/incorporating-changes-from-a-pull-request/automatically-merging-a-pull-request