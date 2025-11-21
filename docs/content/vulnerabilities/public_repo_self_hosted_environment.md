# Public Repo Self Hosted Environment

## Description

Self-hosted runners in public repositories that access protected environments create significant security risks: public repos are accessible to anyone, so attackers can analyze workflow code, submit pull requests, or trigger workflows to potentially bypass environment protection rules and access environment secrets. Self-hosted runners on attacker-controlled infrastructure can exfiltrate secrets or perform unauthorized actions. [^gh_runners]

## Vulnerable Instance

- Public repository uses self-hosted runners with environment access.
- Environment protection rules may be bypassed through workflow manipulation.
- Attackers can trigger workflows that access protected environments.

```yaml
name: Deploy with Self-Hosted
on:
  pull_request:
    branches: [main]
jobs:
  deploy:
    runs-on: self-hosted  # Dangerous in public repo
    environment: production
    steps:
      - uses: actions/checkout@v4
      - run: deploy.sh
```

## Mitigation Strategies

1. **Use GitHub-hosted runners for public repos**  
   Prefer `runs-on: ubuntu-latest` (or other GitHub-hosted runners) for public repositories. GitHub-hosted runners are isolated and ephemeral.

2. **Make repository private if self-hosted runners are required**  
   If self-hosted runners are necessary, consider making the repository private to limit who can trigger workflows and access environments.

3. **Restrict environment access**  
   If self-hosted runners must be used, restrict environment access, use environment protection rules, require approvals for environment access, and use minimal environment permissions.

4. **Use branch protection**  
   Require pull request reviews and status checks before workflows can access protected environments. Prevent direct pushes to protected branches.

5. **Monitor and audit**  
   Regularly review environment access logs, monitor for suspicious workflow runs, and audit which workflows access which environments.

6. **Isolate sensitive operations**  
   Keep self-hosted runners for public repos limited to read-only operations. Use GitHub-hosted runners or private repos for deployments and secret access.

### Secure Version

```diff
 name: Deploy with GitHub Runner
 on:
   pull_request:
     branches: [main]
 jobs:
   deploy:
-    runs-on: self-hosted  # Dangerous in public repo
+    runs-on: ubuntu-latest  # GitHub-hosted for public repos
     environment: production
     steps:
       - uses: actions/checkout@v4
       - run: deploy.sh
```

## Impact

| Dimension | Severity | Notes |
| --- | --- | --- |
| Likelihood | ![Medium](https://img.shields.io/badge/-Medium-yellow?style=flat-square) | Public repos with self-hosted runners are less common but create high risk when present. |
| Risk | ![Critical](https://img.shields.io/badge/-Critical-red?style=flat-square) | Attackers can potentially bypass environment protection and access environment secrets through compromised self-hosted runners. |
| Blast radius | ![Wide](https://img.shields.io/badge/-Wide-yellow?style=flat-square) | Compromised environment access can affect all systems and secrets in that environment, potentially including production infrastructure. |

## References

- GitHub Docs, "About self-hosted runners," https://docs.github.com/en/actions/hosting-your-own-runners/about-self-hosted-runners [^gh_runners]

---

[^gh_runners]: GitHub Docs, "About self-hosted runners," https://docs.github.com/en/actions/hosting-your-own-runners/about-self-hosted-runners
