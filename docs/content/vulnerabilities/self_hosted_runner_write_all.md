# Self Hosted Runner Write All

## Description

Self-hosted runners with write-all permissions create extreme security risks: write-all grants excessive access to repository resources, and if the runner is compromised, attackers have full write access to modify code, create backdoors, or exfiltrate data. Self-hosted runners with write-all are extremely dangerous and violate the principle of least privilege. [^gh_permissions] [^gh_runners]

## Vulnerable Instance

- Workflow uses self-hosted runners with `permissions: write-all` or no explicit permissions (defaults to write-all).
- Compromised runner can modify repository contents, create backdoors, or exfiltrate data.
- Full repository access enables persistent compromise.

```yaml
name: Build with Write All
on: [push]
jobs:
  build:
    runs-on: self-hosted
    permissions:
      contents: write  # Dangerous on self-hosted
    steps:
      - uses: actions/checkout@v4
      - run: npm test
```

## Mitigation Strategies

1. **Use specific, scoped permissions**  
   Grant only the minimum permissions required. Use `contents: read`, `pull-requests: read`, etc., instead of write-all.

2. **Follow principle of least privilege**  
   Review what the workflow actually needs. Grant only the minimum permissions required and avoid write-all at all costs.

3. **Use job-level permissions**  
   Scope permissions to specific jobs. Use different permissions for different jobs and minimize permissions on self-hosted runners.

4. **Prefer GitHub-hosted runners**  
   Use GitHub-hosted runners when possible. They're isolated and ephemeral, reducing the risk of compromise.

5. **Regularly audit permissions**  
   Review all workflow permissions, remove unnecessary permissions, and document why permissions are needed.

6. **Isolate self-hosted runners**  
   If write permissions are necessary, isolate self-hosted runners in separate networks with minimal access to other systems.

### Secure Version

```yaml
name: Build with Minimal Permissions
on: [push]
jobs:
  build:
    runs-on: self-hosted
    permissions:
      contents: read  # Only what's needed
      pull-requests: read
    steps:
      - uses: actions/checkout@v4
      - run: npm test
```

## Impact

| Dimension | Severity | Notes |
| --- | --- | --- |
| Likelihood | ![Medium](https://img.shields.io/badge/-Medium-yellow?style=flat-square) | Write-all permissions on self-hosted runners are less common but create extreme risk when present. |
| Risk | ![Critical](https://img.shields.io/badge/-Critical-red?style=flat-square) | Compromised runners with write-all can modify code, create backdoors, or exfiltrate data, enabling persistent repository compromise. |
| Blast radius | ![Wide](https://img.shields.io/badge/-Wide-yellow?style=flat-square) | Full repository write access can affect all code, workflows, and secrets in the repository, potentially compromising the entire codebase. |

## References

- GitHub Docs, "Permissions for the GITHUB_TOKEN," https://docs.github.com/en/actions/security-guides/automatic-token-authentication#permissions-for-the-github_token [^gh_permissions]
- GitHub Docs, "About self-hosted runners," https://docs.github.com/en/actions/hosting-your-own-runners/about-self-hosted-runners [^gh_runners]

---

[^gh_permissions]: GitHub Docs, "Permissions for the GITHUB_TOKEN," https://docs.github.com/en/actions/security-guides/automatic-token-authentication#permissions-for-the-github_token
[^gh_runners]: GitHub Docs, "About self-hosted runners," https://docs.github.com/en/actions/hosting-your-own-runners/about-self-hosted-runners
