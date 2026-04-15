# Environment Bypass Risk

## Description

Workflows triggered by `pull_request_target`, `workflow_run`, or other elevated events can call protected environments without the usual approval gates. A malicious contributor can craft a PR that triggers the privileged workflow and bypasses environment reviewers or required branches, releasing unreviewed code. GitHub cautions that `pull_request_target` should never deploy directly to production because it runs with the base repository’s token. [^gh_environments]

## Vulnerable Instance

- Workflow uses `pull_request_target`.
- Job targets a protected environment (deployments, secrets) without checking the source branch.
- No manual approval before environment deployment.

```yaml
name: Deploy on PR Target
on:
  pull_request_target:
    branches: [main]
jobs:
  deploy:
    environment: production
    permissions:
      contents: write
      deployments: write
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          ref: ${{ github.event.pull_request.head.sha }}
      - run: ./scripts/deploy.sh
```

A forked PR can inject arbitrary code into `deploy.sh`; the workflow runs with maintainer permissions and bypasses environment approvals.

## Mitigation Strategies

1. **Avoid privileged deployments on `pull_request_target`**  
   Use `pull_request` for testing only; gate deployments on `workflow_dispatch`/`push`.
2. **Require environment reviewers**  
   Configure environments with required reviewers and wait timers so automation cannot bypass them.
3. **Validate triggering metadata**  
   Check `github.event.pull_request.head_repo.full_name` and restrict to trusted repos/branches.
4. **Split validation from deployment**  
   Have PR workflows create artifacts; only trusted `push` or `workflow_dispatch` jobs deploy them.
5. **Scope permissions**  
   Set `permissions: read-all` by default and elevate only after approval.

### Secure Version

Split into two separate workflow files. The PR workflow only runs tests; production deploys only on trusted `push` events and require a human reviewer on the environment.

**`.github/workflows/pr-validation.yml`** — safe, read-only PR checks:

```yaml
name: PR Validation
on:
  pull_request:          # NOT pull_request_target
    branches: [main]
jobs:
  build:
    runs-on: ubuntu-latest
    permissions:
      contents: read     # read-only; no deployment access
    steps:
      - uses: actions/checkout@v4
      - run: npm ci
      - run: npm test
```

**`.github/workflows/deploy.yml`** — production deploys only on merged commits:

```yaml
name: Deploy to Production
on:
  push:
    branches: [main]     # only runs after PR is merged and reviewed
jobs:
  deploy:
    runs-on: ubuntu-latest
    environment:
      name: production   # requires a human reviewer to approve in GitHub UI
      url: https://prod.example.com
    permissions:
      contents: read
      deployments: write
    steps:
      - uses: actions/checkout@v4
      - run: ./scripts/deploy.sh
```

## Impact

| Dimension | Severity | Notes |
| --- | --- | --- |
| Likelihood | ![Medium](https://img.shields.io/badge/-Medium-yellow?style=flat-square) | Many teams use `pull_request_target` or chained workflows for convenience. |
| Risk | ![High](https://img.shields.io/badge/-Critical-red?style=flat-square) | Attackers can push unreviewed code to protected environments or access secrets. |
| Blast radius | ![Wide](https://img.shields.io/badge/-Wide-yellow?style=flat-square) | Compromised workflow affects all environments linked via `workflow_run` or deployments. |

## References

- GitHub Docs, “Using environments for deployment,” https://docs.github.com/actions/deployment/targeting-different-environments/using-environments-for-deployment [^gh_environments]
- GitHub Docs, “pull_request_target event,” https://docs.github.com/actions/using-workflows/events-that-trigger-workflows#pull_request_target

---

[^gh_environments]: GitHub Docs, “Using environments for deployment,” https://docs.github.com/actions/deployment/targeting-different-environments/using-environments-for-deployment