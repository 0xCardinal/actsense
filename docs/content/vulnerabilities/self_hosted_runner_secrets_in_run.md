# Self Hosted Runner Secrets In Run

## Description

Workflows that use secrets directly in run commands on self-hosted runners expose those secrets to process lists, shell history, and logs: secrets may be visible in process lists (ps, top, etc.), logged by shell or command execution, exposed in error messages or stack traces, and stored in shell history. Process arguments containing secrets are visible to other processes on the same system. This is particularly dangerous on self-hosted runners where other processes or users may have access to the system. [^gh_secrets] [^gh_runners]

## Vulnerable Instance

- Workflow uses secrets directly in run commands on self-hosted runners.
- Secrets appear in process arguments visible to other processes.
- Secrets may be logged or stored in shell history.

```yaml
name: Deploy with Secret
on: [push]
jobs:
  deploy:
    runs-on: self-hosted
    steps:
      - run: |
          curl -H "Authorization: Bearer ${{ secrets.API_KEY }}" https://api.example.com
          # Secret visible in process list
```

## Mitigation Strategies

1. **Use environment variables for secrets**  
   Pass secrets through environment variables instead of direct interpolation. Access via `$SECRET` in commands rather than `${{ secrets.SECRET }}` in the command string.

2. **Avoid direct secret interpolation**  
   Never use `${{ secrets.SECRET }}` directly in run commands. Always use environment variables to pass secrets to commands.

3. **Use action inputs when possible**  
   Pass secrets as action inputs rather than environment variables or command arguments. Actions handle secrets more securely.

4. **Review all secret usage**  
   Audit all workflows for secrets in run commands. Move secrets to environment variables and use secure secret handling practices.

5. **Clear shell history**  
   If secrets were exposed, clear shell history on self-hosted runners. Consider using ephemeral runners that don't persist history.

6. **Rotate exposed secrets**  
   If secrets were exposed in process lists or logs, rotate them immediately and review access logs for unauthorized usage.

### Secure Version

```yaml
name: Deploy with Secret
on: [push]
jobs:
  deploy:
    runs-on: self-hosted
    steps:
      - name: Deploy
        env:
          API_KEY: ${{ secrets.API_KEY }}  # Secret in env, not command
        run: |
          curl -H "Authorization: Bearer $API_KEY" https://api.example.com
          # Secret not visible in process list
```

## Impact

| Dimension | Severity | Notes |
| --- | --- | --- |
| Likelihood | ![High](https://img.shields.io/badge/-High-orange?style=flat-square) | Using secrets directly in commands is common, especially on self-hosted runners where the risk is higher. |
| Risk | ![High](https://img.shields.io/badge/-High-orange?style=flat-square) | Secrets visible in process lists can be accessed by other processes or users on self-hosted runners, enabling unauthorized access. |
| Blast radius | ![Medium](https://img.shields.io/badge/-Medium-yellow?style=flat-square) | Impact depends on what the secret can access, but can affect all systems and services the secret authorizes. |

## References

- GitHub Docs, "Encrypted secrets," https://docs.github.com/en/actions/security-guides/encrypted-secrets [^gh_secrets]
- GitHub Docs, "About self-hosted runners," https://docs.github.com/en/actions/hosting-your-own-runners/about-self-hosted-runners [^gh_runners]

---

[^gh_secrets]: GitHub Docs, "Encrypted secrets," https://docs.github.com/en/actions/security-guides/encrypted-secrets
[^gh_runners]: GitHub Docs, "About self-hosted runners," https://docs.github.com/en/actions/hosting-your-own-runners/about-self-hosted-runners
