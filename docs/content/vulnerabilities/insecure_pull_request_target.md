# Insecure Pull Request Target

## Description

`pull_request_target` runs with the base repository’s token (Usually write). If the workflow checks out the PR’s head commit, code from an untrusted fork executes with maintainer permissions—allowing attackers to steal secrets or push malicious commits. GitHub Security Lab explicitly warns against checking out PR code in `pull_request_target` workflows. [^gh_untrusted_input]

## Vulnerable Instance

- Workflow triggers on `pull_request_target`.
- Step checks out `github.event.pull_request.head.sha`.
- Subsequent steps run build/test scripts from the fork.

```yaml
name: PR Target
on:
  pull_request_target:
    branches: [main]
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          ref: ${{ github.event.pull_request.head.sha }}  # Dangerous
      - run: npm test
```

## Mitigation Strategies

1. **Use `pull_request` for untrusted code**  
   Standard PR workflows run with read-only tokens; use them for building fork contributions.
2. **Never checkout head ref in `pull_request_target`**  
   If you need repository context, only check out the base branch (`github.event.pull_request.base.ref`).
3. **Split validation and privileged actions**  
   Use `pull_request` to build/test and `workflow_dispatch`/`push` for deployments.
4. **Minimize permissions**  
   Explicitly set `permissions: read-all` in `pull_request_target` workflows; escalate only after manual review.
5. **Validate inputs and artifacts**  
   Treat data from the head repo as untrusted; avoid running scripts or commands from it.

### Secure Version

- PR workflow runs on `pull_request` (read-only).
- `pull_request_target` workflow checks out only the base branch for tasks like labeling.
- Deployment happens in a separate trusted workflow. [^gh_untrusted_input]

```yaml
name: PR Validation
on: pull_request
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - run: npm test

name: PR Target Labeler
on:
  pull_request_target:
    branches: [main]
jobs:
  label:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      pull-requests: write
    steps:
      - uses: actions/checkout@v4
        with:
          ref: ${{ github.event.pull_request.base.ref }}
      - run: gh pr edit ${{ github.event.pull_request.number }} --add-label "triaged"
```

## Impact

| Dimension | Severity | Notes |
| --- | --- | --- |
| Likelihood | ![High](https://img.shields.io/badge/-High-orange?style=flat-square) | Many tutorials misuse `pull_request_target` for testing forks. |
| Risk | ![Critical](https://img.shields.io/badge/-Critical-red?style=flat-square) | Attackers gain maintainer-level repo access and secrets. |
| Blast radius | ![Wide](https://img.shields.io/badge/-Wide-yellow?style=flat-square) | Entire repository, environments, and registries tied to the token are exposed. |

## References

- GitHub Security Lab, “Untrusted input in GitHub Actions,” https://securitylab.github.com/research/github-actions-untrusted-input/ [^gh_untrusted_input]
- GitHub Docs, “Events that trigger workflows: pull_request_target,” https://docs.github.com/actions/using-workflows/events-that-trigger-workflows#pull_request_target

---

[^gh_untrusted_input]: GitHub Security Lab, “Untrusted input in GitHub Actions,” https://securitylab.github.com/research/github-actions-untrusted-input/