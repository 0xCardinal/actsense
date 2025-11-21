# Secret In Environment

## Description

Workflows that expose secrets directly in environment variables create security risks: environment variables may be logged by actions or tools, visible in workflow logs, exposed in error messages, or accessible to child processes. While GitHub Actions automatically masks secrets in logs when accessed via `${{ secrets.SECRET_NAME }}`, explicitly setting secrets as environment variables can bypass this protection and expose credentials to tools that log environment variables. [^gh_secrets]

## Vulnerable Instance

- Workflow sets a secret as an environment variable that gets logged by an action or tool.
- Environment variable is visible in workflow logs or error messages.
- Child processes can access the environment variable.

```yaml
name: Build with Exposed Secret
on: [push]
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - name: Use secret
        env:
          API_KEY: ${{ secrets.API_KEY }}  # May be logged
        run: |
          echo "Using API key: $API_KEY"  # Exposed in logs
          curl -H "Authorization: Bearer $API_KEY" https://api.example.com
```

## Mitigation Strategies

1. **Use action input parameters**  
   Pass secrets as action inputs rather than environment variables when possible. Actions can handle secrets more securely.

2. **Access secrets directly**  
   Use `${{ secrets.SECRET_NAME }}` directly in commands rather than setting as environment variables. GitHub automatically masks these in logs.

3. **Minimize secret exposure**  
   If environment variables are necessary, use minimal secrets, review action documentation for secret handling, monitor logs for exposure, and use secrets that can be rotated easily.

4. **Use environment secrets with protection**  
   For sensitive operations, use environment secrets with required reviewers and protection rules instead of repository secrets.

5. **Review all environment variable usage**  
   Audit all workflows for environment variables containing secrets. Use automated scanning to detect secret exposure in logs.

6. **Consider GitHub Apps**  
   Use GitHub Apps with limited scopes instead of broad secret access when possible.

### Secure Version

```diff
 name: Build with Secure Secret
 on: [push]
 jobs:
   build:
     runs-on: ubuntu-latest
     steps:
       - name: Use secret
-        env:
-          API_KEY: ${{ secrets.API_KEY }}  # May be logged
         run: |
-          echo "Using API key: $API_KEY"  # Exposed in logs
           curl -H "Authorization: Bearer ${{ secrets.API_KEY }}" https://api.example.com
+          # Secret is automatically masked in logs
```

## Impact

| Dimension | Severity | Notes |
| --- | --- | --- |
| Likelihood | ![High](https://img.shields.io/badge/-High-orange?style=flat-square) | Environment variables with secrets are common, and many tools log environment variables by default. |
| Risk | ![High](https://img.shields.io/badge/-High-orange?style=flat-square) | Exposed secrets in logs can be accessed by anyone with log access, enabling unauthorized API or service access. |
| Blast radius | ![Medium](https://img.shields.io/badge/-Medium-yellow?style=flat-square) | Impact depends on what the secret can access, but can affect all systems and services the secret authorizes. |

## References

- GitHub Docs, "Encrypted secrets," https://docs.github.com/en/actions/security-guides/encrypted-secrets [^gh_secrets]

---

[^gh_secrets]: GitHub Docs, "Encrypted secrets," https://docs.github.com/en/actions/security-guides/encrypted-secrets
