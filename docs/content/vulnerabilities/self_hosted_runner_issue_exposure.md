# Self Hosted Runner Issue Exposure

## Description

Self-hosted runners that can be triggered by issue events in public repositories create significant security risks: anyone can create issues in public repositories, issue events can trigger workflows on self-hosted runners, and attackers can abuse this to execute code on your infrastructure. Issue content may be used in workflow execution, enabling injection attacks. This allows unauthorized code execution on self-hosted infrastructure with minimal barriers. [^gh_runners]

## Vulnerable Instance

- Public repository workflow triggers on `issues` events and uses self-hosted runners.
- Anyone can create issues to trigger the workflow.
- Issue content may be used in workflow execution, enabling injection.

```yaml
name: Process Issue
on:
  issues:
    types: [opened]
jobs:
  process:
    runs-on: self-hosted  # Dangerous with issue triggers
    steps:
      - name: Process issue
        run: |
          echo "${{ github.event.issue.title }}"  # User-controlled input
```

## Mitigation Strategies

1. **Use GitHub-hosted runners for issue workflows**  
   Always use `runs-on: ubuntu-latest` (or other GitHub-hosted runners) for issue-triggered workflows, especially in public repositories.

2. **Restrict self-hosted runners to trusted events**  
   If self-hosted runners are necessary, restrict to trusted events only (push, workflow_dispatch). Don't allow issue, pull_request, or other user-controllable triggers.

3. **Use runner groups with restricted access**  
   Create runner groups that only allow specific workflows or events. Prevent issue-triggered workflows from using self-hosted runners.

4. **Validate and sanitize issue content**  
   If you must process issues, validate and sanitize all issue content. Never use issue content directly in commands without validation.

5. **Use minimal permissions**  
   Issue-triggered workflows should use minimal permissions. Never grant write permissions to issue workflows.

6. **Consider making repository private**  
   If self-hosted runners are required for issue processing, consider making the repository private to limit who can create issues.

### Secure Version

```yaml
name: Process Issue Safely
on:
  issues:
    types: [opened]
jobs:
  process:
    runs-on: ubuntu-latest  # GitHub-hosted for issue triggers
    permissions:
      issues: read
      contents: read
    steps:
      - name: Process issue
        run: |
          # Validate and sanitize input
          TITLE="${{ github.event.issue.title }}"
          echo "Processing: ${TITLE}"
```

## Impact

| Dimension | Severity | Notes |
| --- | --- | --- |
| Likelihood | ![Medium](https://img.shields.io/badge/-Medium-yellow?style=flat-square) | Issue-triggered workflows with self-hosted runners are less common but create high risk when present. |
| Risk | ![Critical](https://img.shields.io/badge/-Critical-red?style=flat-square) | Attackers can trigger workflows on self-hosted infrastructure by creating issues, enabling code execution and potential infrastructure compromise. |
| Blast radius | ![Wide](https://img.shields.io/badge/-Wide-yellow?style=flat-square) | Compromised self-hosted runners can affect all systems the runner can access, including internal networks and services. |

## References

- GitHub Docs, "About self-hosted runners," https://docs.github.com/en/actions/hosting-your-own-runners/about-self-hosted-runners [^gh_runners]

---

[^gh_runners]: GitHub Docs, "About self-hosted runners," https://docs.github.com/en/actions/hosting-your-own-runners/about-self-hosted-runners
