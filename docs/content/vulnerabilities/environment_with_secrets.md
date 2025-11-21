# Environment With Secrets

## Description

GitHub environments act as secret vaults plus deployment gates, but if you attach an environment to a job without configuring protection rules, any workflow with sufficient permissions can automatically deploy and read those secrets. Attackers abusing `pull_request_target` or compromised branches can therefore extract production credentials. [^gh_environment_secrets]

## Vulnerable Instance

- Job references `environment: production` but the environment lacks required reviewers or branch restrictions.
- Workflow is triggered by untrusted events (`pull_request`, `workflow_dispatch` from forks).
- Environment secrets (API keys, cloud creds) are injected directly into steps.

```yaml
jobs:
  deploy:
    environment: production
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Deploy
        env:
          API_KEY: ${{ secrets.PROD_API_KEY }}
        run: ./scripts/deploy.sh "$API_KEY"
```

Any actor who can trigger the workflow gains access to `PROD_API_KEY`.

## Mitigation Strategies

1. **Enable protection rules**  
   Require reviewers and wait timers on every environment with secrets.
2. **Restrict deployment branches**  
   Limit environments to trusted branches (`main`, `release/*`) and block forks.
3. **Limit who can deploy**  
   Use branch protection + CODEOWNERS to ensure only trusted maintainers trigger deployments.
4. **Rotate and scope secrets**  
   Store least-privilege credentials per environment; rotate routinely.
5. **Audit workflow triggers**  
   Ensure only `push`/`workflow_dispatch` from the base repo reference production environments.

### Secure Version

- Environment requires two reviewers and a 10-minute wait timer.
- Deployment job runs only on `push` to `main`.
- Secrets are scoped per environment and never exposed to forked PRs. [^gh_environment_secrets]

```yaml
jobs:
  deploy:
    if: github.ref == 'refs/heads/main'
    environment:
      name: production
      url: https://prod.example.com
    runs-on: ubuntu-latest
    permissions:
      contents: read
      deployments: write
    steps:
      - uses: actions/checkout@v4
      - name: Deploy
        env:
          API_KEY: ${{ secrets.PROD_API_KEY }}
        run: ./scripts/deploy.sh "$API_KEY"
```

## Impact

| Dimension | Severity | Notes |
| --- | --- | --- |
| Likelihood | ![Medium](https://img.shields.io/badge/-Medium-yellow?style=flat-square) | Many teams add environments but skip configuring protection. |
| Risk | ![High](https://img.shields.io/badge/-High-orange?style=flat-square) | Compromised workflow grants direct access to production secrets and deploy rights. |
| Blast radius | ![Wide](https://img.shields.io/badge/-Wide-yellow?style=flat-square) | Any system using the environment’s secrets (prod infra, APIs) is exposed. |

## References

- GitHub Docs, “Managing environments for deployment,” https://docs.github.com/actions/deployment/targeting-different-environments/using-environments-for-deployment [^gh_environment_secrets]
- GitHub Docs, “Environment protection rules,” https://docs.github.com/actions/deployment/targeting-different-environments/about-environments#environment-protection-rules

---

[^gh_environment_secrets]: GitHub Docs, “Using environments for deployment,” https://docs.github.com/actions/deployment/targeting-different-environments/using-environments-for-deployment