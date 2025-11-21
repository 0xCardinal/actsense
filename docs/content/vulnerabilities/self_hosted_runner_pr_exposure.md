# Self Hosted Runner Pr Exposure

## Description

Self-hosted runners exposed to pull requests in public repositories create extreme security risks: attackers from forks can create PRs that trigger workflows on your self-hosted runners, malicious code from forks can execute on your infrastructure, and attackers can access your network, secrets, and internal resources. This is one of the most dangerous self-hosted runner configurations and should never be used. [^gh_runners]

## Vulnerable Instance

- Public repository workflow triggers on `pull_request` events and uses self-hosted runners.
- Attackers can fork the repository, create a PR with malicious workflow code, and trigger execution on your infrastructure.
- Malicious code runs with access to your network and secrets.

```yaml
name: PR Build
on:
  pull_request:
    branches: [main]
jobs:
  build:
    runs-on: self-hosted  # CRITICAL: Never do this in public repos
    steps:
      - uses: actions/checkout@v4
      - run: npm test
```

## Mitigation Strategies

1. **Use GitHub-hosted runners for public repositories**  
   Always use `runs-on: ubuntu-latest` (or other GitHub-hosted runners) for pull request workflows in public repositories.

2. **Restrict self-hosted runners to trusted events**  
   If self-hosted runners are necessary, restrict to trusted events only (push, workflow_dispatch). Never allow pull_request or pull_request_target triggers.

3. **Use runner groups with restricted access**  
   Create runner groups that only allow specific workflows or events. Prevent pull request workflows from using self-hosted runners.

4. **Make repository private if needed**  
   If self-hosted runners are required for PR workflows, make the repository private to limit who can create pull requests.

5. **Use separate workflows**  
   Use GitHub-hosted runners for PR workflows and self-hosted runners only for trusted push events or manual triggers.

6. **Implement network isolation**  
   If you must use self-hosted runners, isolate them in separate networks with minimal access to internal resources.

### Secure Version

```diff
 name: PR Build Safe
 on:
   pull_request:
     branches: [main]
 jobs:
   build:
-    runs-on: self-hosted  # CRITICAL: Never do this in public repos
+    runs-on: ubuntu-latest  # GitHub-hosted for PRs
     steps:
       - uses: actions/checkout@v4
       - run: npm test
```

## Impact

| Dimension | Severity | Notes |
| --- | --- | --- |
| Likelihood | ![High](https://img.shields.io/badge/-High-orange?style=flat-square) | Public repos with self-hosted runners on PRs are less common but create extreme risk when present. |
| Risk | ![Critical](https://img.shields.io/badge/-Critical-red?style=flat-square) | Attackers can trigger malicious code execution on your infrastructure by creating pull requests, enabling full system compromise. |
| Blast radius | ![Wide](https://img.shields.io/badge/-Wide-yellow?style=flat-square) | Compromised self-hosted runners can affect all systems the runner can access, including internal networks, databases, and services. |

## References

- GitHub Docs, "About self-hosted runners," https://docs.github.com/en/actions/hosting-your-own-runners/about-self-hosted-runners [^gh_runners]

---

[^gh_runners]: GitHub Docs, "About self-hosted runners," https://docs.github.com/en/actions/hosting-your-own-runners/about-self-hosted-runners
