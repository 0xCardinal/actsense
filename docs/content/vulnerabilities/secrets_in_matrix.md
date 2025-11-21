# Secrets In Matrix

## Description

Workflows that include secrets in matrix strategy definitions expose those secrets to ALL matrix job combinations: each matrix job can access and potentially log the secrets, secrets are visible in the workflow YAML to all contributors, and secrets may be logged or exposed in error messages. This violates the principle of least privilege and dramatically increases the attack surface—attackers with access to any matrix job can see all secrets. [^gh_secrets]

## Vulnerable Instance

- Workflow defines secrets in the matrix strategy, making them available to all matrix combinations.
- All matrix jobs can access the secrets, even if they don't need them.
- Secrets are visible in workflow YAML and logs.

```yaml
name: Build Matrix with Secrets
on: [push]
jobs:
  build:
    strategy:
      matrix:
        os: [ubuntu, windows, macos]
        api_key: [${{ secrets.API_KEY }}]  # Dangerous - exposed to all jobs
    runs-on: ${{ matrix.os }}-latest
    steps:
      - run: echo "Using ${{ matrix.api_key }}"
```

## Mitigation Strategies

1. **Move secrets to job or step level**  
   Remove secrets from matrix definitions. Pass secrets at the job or step level where they're actually needed.

2. **Use environment secrets**  
   For sensitive operations, use environment secrets with job-level access instead of including them in the matrix.

3. **Never use secrets in matrix definitions**  
   Matrix values should only contain non-sensitive configuration like OS versions, Node versions, or test configurations.

4. **Review all matrix strategies**  
   Audit all workflows for secrets in matrix definitions. Use automated scanning to detect this pattern.

5. **Rotate exposed secrets**  
   If secrets were exposed in matrix definitions, rotate them immediately and review access logs for unauthorized usage.

6. **Use separate jobs for sensitive operations**  
   If secrets are needed for specific matrix combinations, create separate jobs that only run for those combinations.

### Secure Version

```diff
 name: Build Matrix Secure
 on: [push]
 jobs:
   build:
     strategy:
       matrix:
         os: [ubuntu, windows, macos]
-        api_key: [${{ secrets.API_KEY }}]  # Dangerous - exposed to all jobs
+        # No secrets here
     runs-on: ${{ matrix.os }}-latest
     steps:
-      - run: echo "Using ${{ matrix.api_key }}"
+      - name: Use secret
+        env:
+          API_KEY: ${{ secrets.API_KEY }}  # Secret at step level
+        run: echo "Using API key"
```

## Impact

| Dimension | Severity | Notes |
| --- | --- | --- |
| Likelihood | ![Low](https://img.shields.io/badge/-Low-green?style=flat-square) | Secrets in matrix definitions are less common but create extreme risk when present. |
| Risk | ![Critical](https://img.shields.io/badge/-Critical-red?style=flat-square) | All matrix jobs can access secrets, dramatically increasing exposure. Secrets visible in YAML to all contributors. |
| Blast radius | ![Wide](https://img.shields.io/badge/-Wide-yellow?style=flat-square) | All matrix job combinations can access the secrets, and secrets are visible in workflow files to anyone with read access. |

## References

- GitHub Docs, "Encrypted secrets," https://docs.github.com/en/actions/security-guides/encrypted-secrets [^gh_secrets]

---

[^gh_secrets]: GitHub Docs, "Encrypted secrets," https://docs.github.com/en/actions/security-guides/encrypted-secrets
