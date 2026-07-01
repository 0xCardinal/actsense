# GitHub Environment File Injection

## Description

GitHub Actions exposes the special files `$GITHUB_ENV` and `$GITHUB_PATH` so that a step can set environment variables and prepend directories to `PATH` for **subsequent** steps in the same job. When a workflow appends **user-controllable** data (for example `github.event.issue.title`, `github.event.pull_request.body`, or `github.head_ref`) to these files, an attacker can define security-sensitive variables such as `LD_PRELOAD`, `NODE_OPTIONS`, `BASH_ENV`, or `PATH` and achieve arbitrary code execution in later, often more privileged, steps. [^gh_actions_security] The data delivered by these events is the same untrusted input described in [Risky Context Usage](/vulnerabilities/risky_context_usage/); writing it to a runner environment file turns an information-flow problem into a code-execution one.

## Vulnerable Instance

- A `run:` step writes `${{ github.event.* }}` (or another user-controllable context) to `$GITHUB_ENV` or `$GITHUB_PATH`.
- A later step inherits the attacker-defined variable or `PATH` entry and executes code under its control.

```yaml
name: Label PR
on:
  pull_request_target:
jobs:
  label:
    runs-on: ubuntu-latest
    steps:
      - name: Capture title
        run: echo "PR_TITLE=${{ github.event.pull_request.title }}" >> $GITHUB_ENV
        # An attacker can set a PR title such as:
        #   foo\nLD_PRELOAD=/tmp/evil.so
        # which injects an extra environment variable consumed by later steps.
      - name: Build
        run: make build   # runs with the attacker-controlled LD_PRELOAD
```

## Mitigation Strategies

1. **Never write user-controllable context to environment files**
   Do not place `${{ github.event.* }}`, `${{ github.head_ref }}`, or any untrusted value directly into `$GITHUB_ENV` or `$GITHUB_PATH`.

2. **Pass through an intermediate environment variable and validate**
   Assign the value to a step `env:` variable, validate it against a strict allowlist, and only then use it. The heredoc-style write below cannot inject extra lines because the value is no longer interpolated by the shell.

   ```yaml
   - name: Capture title safely
     env:
       PR_TITLE: ${{ github.event.pull_request.title }}
     run: |
       if [[ ! "$PR_TITLE" =~ ^[[:alnum:][:space:].,!?/-]+$ ]]; then
         echo "Invalid PR title; rejecting"
         exit 1
       fi
       printf 'PR_TITLE=%s\n' "$PR_TITLE" >> "$GITHUB_ENV"
   ```

3. **Avoid privileged triggers for untrusted input**
   Prefer `pull_request` over `pull_request_target` when you must process fork-supplied data, so the job runs without access to secrets or a write-scoped token.

4. **Apply least-privilege permissions**
   Set `permissions:` to the minimum required so that code execution in a later step has a limited blast radius.

### Secure Version

```diff
 name: Label PR
 on:
-  pull_request_target:
+  pull_request:
 jobs:
   label:
     runs-on: ubuntu-latest
+    permissions:
+      contents: read
     steps:
       - name: Capture title
-        run: echo "PR_TITLE=${{ github.event.pull_request.title }}" >> $GITHUB_ENV
+        env:
+          PR_TITLE: ${{ github.event.pull_request.title }}
+        run: |
+          if [[ ! "$PR_TITLE" =~ ^[[:alnum:][:space:].,!?/-]+$ ]]; then
+            echo "Invalid PR title; rejecting"
+            exit 1
+          fi
+          printf 'PR_TITLE=%s\n' "$PR_TITLE" >> "$GITHUB_ENV"
```

## Impact

| Dimension | Severity | Notes |
| --- | --- | --- |
| Likelihood | ![Medium](https://img.shields.io/badge/-Medium-yellow?style=flat-square) | Requires a workflow that both processes untrusted input and writes it to an environment file, but this pattern appears frequently in labelling and automation workflows. |
| Risk | ![Critical](https://img.shields.io/badge/-Critical-red?style=flat-square) | Injected variables such as `LD_PRELOAD` or `PATH` lead to arbitrary code execution in later steps, often with access to secrets and a write-scoped token. |
| Blast radius | ![Wide](https://img.shields.io/badge/-Wide-yellow?style=flat-square) | Code executes with whatever the compromised job can reach: repository contents, secrets, deployment targets, and internal networks. |

## References

- GitHub Docs, "Security hardening for GitHub Actions," https://docs.github.com/en/actions/security-guides/security-hardening-for-github-actions [^gh_actions_security]
- GitHub Docs, "Workflow commands for GitHub Actions — Setting an environment variable," https://docs.github.com/en/actions/using-workflows/workflow-commands-for-github-actions#setting-an-environment-variable [^gh_env_files]

---

[^gh_actions_security]: GitHub Docs, "Security hardening for GitHub Actions," https://docs.github.com/en/actions/security-guides/security-hardening-for-github-actions
[^gh_env_files]: GitHub Docs, "Workflow commands for GitHub Actions," https://docs.github.com/en/actions/using-workflows/workflow-commands-for-github-actions#setting-an-environment-variable
