# Public Repo Self Hosted Secrets

## Description

Self-hosted runners in public repositories that have access to secrets create extreme security risks: public repos are accessible to anyone, so attackers can analyze workflow code, submit malicious pull requests, or trigger workflows to potentially exfiltrate secrets through compromised self-hosted runners. Self-hosted runners on attacker-controlled infrastructure can access secrets, modify files, or perform unauthorized actions with the workflow's permissions. [^gh_runners] [^gh_secrets]

## Vulnerable Instance

- Public repository uses self-hosted runners with access to repository secrets.
- Attackers can trigger workflows that expose secrets to the self-hosted runner.
- Compromised self-hosted runner infrastructure can exfiltrate secrets.

```yaml
name: Build with Secrets
on:
  pull_request:
    branches: [main]
jobs:
  build:
    runs-on: self-hosted  # Dangerous in public repo
    steps:
      - uses: actions/checkout@v4
      - name: Use secret
        run: echo "${{ secrets.API_KEY }}"  # Exposed to self-hosted runner
```

## Mitigation Strategies

1. **Use GitHub-hosted runners for public repos**  
   Prefer `runs-on: ubuntu-latest` (or other GitHub-hosted runners) for public repositories. GitHub-hosted runners are isolated, ephemeral, and more secure.

2. **Make repository private if self-hosted runners are required**  
   If self-hosted runners are necessary, make the repository private to limit who can trigger workflows and access secrets.

3. **Minimize secrets in public repos**  
   If self-hosted runners must be used, minimize secrets, use environment secrets with protection rules, rotate secrets regularly, and implement additional security controls.

4. **Use environment protection**  
   Use environment secrets with required reviewers and protection rules. Require manual approval before workflows can access secrets.

5. **Monitor and audit**  
   Regularly review secret access logs, monitor for suspicious workflow runs, and audit which workflows access which secrets.

6. **Isolate sensitive operations**  
   Keep self-hosted runners for public repos limited to read-only operations. Use GitHub-hosted runners or private repos for operations requiring secrets.

### Secure Version

```diff
 name: Build with Secrets
 on:
   pull_request:
     branches: [main]
 jobs:
   build:
-    runs-on: self-hosted  # Dangerous in public repo
+    runs-on: ubuntu-latest  # GitHub-hosted for public repos
     steps:
       - uses: actions/checkout@v4
       - name: Use secret
-        run: echo "${{ secrets.API_KEY }}"  # Exposed to self-hosted runner
+        run: echo "${{ secrets.API_KEY }}"  # Safer on GitHub-hosted runner
```

## Impact

| Dimension | Severity | Notes |
| --- | --- | --- |
| Likelihood | ![Medium](https://img.shields.io/badge/-Medium-yellow?style=flat-square) | Public repos with self-hosted runners are less common but create extreme risk when present. |
| Risk | ![Critical](https://img.shields.io/badge/-Critical-red?style=flat-square) | Attackers can potentially exfiltrate secrets through compromised self-hosted runners, enabling full system compromise. |
| Blast radius | ![Wide](https://img.shields.io/badge/-Wide-yellow?style=flat-square) | Compromised secrets can affect all systems the secrets can access, potentially including production infrastructure, databases, and services. |

## References

- GitHub Docs, "About self-hosted runners," https://docs.github.com/en/actions/hosting-your-own-runners/about-self-hosted-runners [^gh_runners]
- GitHub Docs, "Encrypted secrets," https://docs.github.com/en/actions/security-guides/encrypted-secrets [^gh_secrets]

---

[^gh_runners]: GitHub Docs, "About self-hosted runners," https://docs.github.com/en/actions/hosting-your-own-runners/about-self-hosted-runners
[^gh_secrets]: GitHub Docs, "Encrypted secrets," https://docs.github.com/en/actions/security-guides/encrypted-secrets
