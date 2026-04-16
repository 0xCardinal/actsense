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

Split into two separate workflow files. The first runs tests safely with read-only access; the second uses `pull_request_target` only for the privileged action it actually needs (labelling) and never touches fork code.

**`.github/workflows/pr-test.yml`** — build and test the fork's code safely:

```yaml
name: PR Validation
on:
  pull_request:        # read-only token, fork code can't access secrets
    branches: [main]
jobs:
  build:
    runs-on: ubuntu-latest
    permissions:
      contents: read
    steps:
      - uses: actions/checkout@v4   # checks out the fork's code safely
      - run: npm ci && npm test
```

**`.github/workflows/pr-label.yml`** — privileged action using `pull_request_target`, but checks out only the base branch:

```yaml
name: PR Labeler
on:
  pull_request_target:
    branches: [main]
    types: [opened, synchronize]
jobs:
  label:
    runs-on: ubuntu-latest
    permissions:
      contents: read       # only reading the base branch
      pull-requests: write # needed to add labels
    steps:
      - uses: actions/checkout@v4
        with:
          ref: ${{ github.event.pull_request.base.ref }}  # base branch only — NOT fork code
      - name: Add triage label
        env:
          GH_TOKEN: ${{ secrets.GITHUB_TOKEN }}
          PR_NUMBER: ${{ github.event.pull_request.number }}
        run: gh pr edit "$PR_NUMBER" --add-label "needs-review"
```

## Impact

| Dimension | Severity | Notes |
| --- | --- | --- |
| Likelihood | ![High](https://img.shields.io/badge/-High-orange?style=flat-square) | Many tutorials misuse `pull_request_target` for testing forks. |
| Risk | ![High](https://img.shields.io/badge/-Critical-red?style=flat-square) | Attackers gain maintainer-level repo access and secrets. |
| Blast radius | ![Wide](https://img.shields.io/badge/-Wide-yellow?style=flat-square) | Entire repository, environments, and registries tied to the token are exposed. |

## References

- GitHub Security Lab, “Untrusted input in GitHub Actions,” https://securitylab.github.com/research/github-actions-untrusted-input/ [^gh_untrusted_input]
- GitHub Docs, “Events that trigger workflows: pull_request_target,” https://docs.github.com/actions/using-workflows/events-that-trigger-workflows#pull_request_target

---

[^gh_untrusted_input]: GitHub Security Lab, “Untrusted input in GitHub Actions,” https://securitylab.github.com/research/github-actions-untrusted-input/