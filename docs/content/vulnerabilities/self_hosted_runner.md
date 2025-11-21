# Self Hosted Runner

## Description

Workflows using self-hosted runners pose significant security risks compared to GitHub-hosted runners: self-hosted runners have persistent access to your infrastructure, and if compromised through malicious workflows or actions, attackers can access your network, systems, secrets, and internal resources. Compromised runners can be used to exfiltrate data, attack other systems, or maintain persistent access. Self-hosted runners require careful security hardening, isolation, and monitoring. [^gh_runners]

## Vulnerable Instance

- Workflow uses a self-hosted runner that may not be properly isolated or secured.
- Runner has persistent access to infrastructure and may have access to secrets.
- Compromised runner can be used to attack other systems.

```yaml
name: Build on Self-Hosted
on: [push]
jobs:
  build:
    runs-on: self-hosted  # Requires careful security
    steps:
      - uses: actions/checkout@v4
      - run: npm test
```

## Mitigation Strategies

1. **Prefer GitHub-hosted runners**  
   Use `runs-on: ubuntu-latest` (or other GitHub-hosted runners) when possible. GitHub-hosted runners are isolated, ephemeral, and more secure.

2. **Isolate runners**  
   If self-hosted runners are necessary, isolate them in separate networks/VPCs, use minimal network access (only required endpoints), and implement network segmentation and firewall rules.

3. **Use ephemeral runners**  
   Use ephemeral runners that are destroyed after each job rather than persistent runners. This limits the window of exposure if a runner is compromised.

4. **Regularly update and patch**  
   Keep runner systems updated and patched. Monitor runner activity and access logs. Use runner groups with restricted access.

5. **Limit secret access**  
   Use environment secrets with restricted access, rotate secrets regularly, and use minimal permissions for GITHUB_TOKEN.

6. **Consider GitHub Actions Runner Controller**  
   Use GitHub Actions Runner Controller (ARC) for better management, automatic scaling, and improved security of self-hosted runners.

### Secure Version

```diff
 name: Build on GitHub Runner
 on: [push]
 jobs:
   build:
-    runs-on: self-hosted  # Requires careful security
+    runs-on: ubuntu-latest  # GitHub-hosted, isolated, ephemeral
     steps:
       - uses: actions/checkout@v4
       - run: npm test
```

## Impact

| Dimension | Severity | Notes |
| --- | --- | --- |
| Likelihood | ![Medium](https://img.shields.io/badge/-Medium-yellow?style=flat-square) | Self-hosted runners are common in enterprise environments but require careful security configuration. |
| Risk | ![High](https://img.shields.io/badge/-High-orange?style=flat-square) | Compromised self-hosted runners can provide persistent access to infrastructure, networks, and internal systems. |
| Blast radius | ![Wide](https://img.shields.io/badge/-Wide-yellow?style=flat-square) | Compromised runners can affect all systems the runner can access, including internal networks, databases, and services. |

## References

- GitHub Docs, "About self-hosted runners," https://docs.github.com/en/actions/hosting-your-own-runners/about-self-hosted-runners [^gh_runners]

---

[^gh_runners]: GitHub Docs, "About self-hosted runners," https://docs.github.com/en/actions/hosting-your-own-runners/about-self-hosted-runners
