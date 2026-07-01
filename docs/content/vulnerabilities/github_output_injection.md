# GitHub Output File Injection

## Description

A step can publish outputs to later steps and jobs by appending `key=value` lines to the special `$GITHUB_OUTPUT` file. When a workflow writes **user-controllable** data (such as `github.event.issue.title`, `github.event.pull_request.body`, or `github.head_ref`) to `$GITHUB_OUTPUT`, an attacker can inject additional output keys or smuggle newline-delimited payloads that downstream steps consume and act on. [^gh_actions_security] This is a variant of the runner environment-file problem described in [GitHub Environment File Injection](/vulnerabilities/github_env_injection/): the data is the same untrusted input covered in [Risky Context Usage](/vulnerabilities/risky_context_usage/), but the sink is the step-output channel rather than the environment.

## Vulnerable Instance

- A `run:` step writes `${{ github.event.* }}` (or another user-controllable context) to `$GITHUB_OUTPUT`.
- A later step or job reads `steps.<id>.outputs.<key>` and uses it in a command, condition, or action parameter.

```yaml
name: Triage
on:
  issues:
jobs:
  triage:
    runs-on: ubuntu-latest
    steps:
      - id: meta
        run: echo "title=${{ github.event.issue.title }}" >> $GITHUB_OUTPUT
        # A crafted issue title can inject extra output keys, e.g.:
        #   foo\nlabel=critical
      - name: Apply
        run: ./label.sh "${{ steps.meta.outputs.title }}"
```

## Mitigation Strategies

1. **Do not write untrusted context to `$GITHUB_OUTPUT`**
   Treat `${{ github.event.* }}` and `${{ github.head_ref }}` as attacker-controlled and never serialize them directly.

2. **Sanitize and validate via an intermediate environment variable**
   Move the value into a step `env:` variable, validate it, and write it using a delimiter-safe form.

   ```yaml
   - id: meta
     env:
       ISSUE_TITLE: ${{ github.event.issue.title }}
     run: |
       if [[ ! "$ISSUE_TITLE" =~ ^[[:alnum:][:space:].,!?/-]+$ ]]; then
         echo "Invalid issue title; rejecting"
         exit 1
       fi
       printf 'title=%s\n' "$ISSUE_TITLE" >> "$GITHUB_OUTPUT"
   ```

3. **Validate again at the consumer**
   Steps that read `steps.<id>.outputs.<key>` should not pass the value unquoted into shell commands; quote it and validate against expected formats.

4. **Use random delimiters for multi-line values**
   For legitimately multi-line outputs use the documented heredoc syntax with an unpredictable delimiter so attacker-supplied newlines cannot terminate the block early.

### Secure Version

```diff
 name: Triage
 on:
   issues:
 jobs:
   triage:
     runs-on: ubuntu-latest
+    permissions:
+      issues: write
     steps:
       - id: meta
-        run: echo "title=${{ github.event.issue.title }}" >> $GITHUB_OUTPUT
+        env:
+          ISSUE_TITLE: ${{ github.event.issue.title }}
+        run: |
+          if [[ ! "$ISSUE_TITLE" =~ ^[[:alnum:][:space:].,!?/-]+$ ]]; then
+            echo "Invalid issue title; rejecting"
+            exit 1
+          fi
+          printf 'title=%s\n' "$ISSUE_TITLE" >> "$GITHUB_OUTPUT"
       - name: Apply
-        run: ./label.sh "${{ steps.meta.outputs.title }}"
+        env:
+          TITLE: ${{ steps.meta.outputs.title }}
+        run: ./label.sh "$TITLE"
```

## Impact

| Dimension | Severity | Notes |
| --- | --- | --- |
| Likelihood | ![Medium](https://img.shields.io/badge/-Medium-yellow?style=flat-square) | Common in triage and automation workflows that echo event fields into step outputs. |
| Risk | ![High](https://img.shields.io/badge/-High-orange?style=flat-square) | Poisoned outputs can alter the behaviour of downstream steps and jobs, including injecting labels, flags, or commands. |
| Blast radius | ![Moderate](https://img.shields.io/badge/-Moderate-yellow?style=flat-square) | Limited to consumers of the output, but those consumers may run with elevated permissions or feed further automation. |

## References

- GitHub Docs, "Security hardening for GitHub Actions," https://docs.github.com/en/actions/security-guides/security-hardening-for-github-actions [^gh_actions_security]
- GitHub Docs, "Workflow commands for GitHub Actions — Setting an output parameter," https://docs.github.com/en/actions/using-workflows/workflow-commands-for-github-actions#setting-an-output-parameter [^gh_output_files]

---

[^gh_actions_security]: GitHub Docs, "Security hardening for GitHub Actions," https://docs.github.com/en/actions/security-guides/security-hardening-for-github-actions
[^gh_output_files]: GitHub Docs, "Workflow commands for GitHub Actions," https://docs.github.com/en/actions/using-workflows/workflow-commands-for-github-actions#setting-an-output-parameter
