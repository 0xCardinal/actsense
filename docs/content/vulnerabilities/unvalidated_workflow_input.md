# Unvalidated Workflow Input

## Description

Workflows with `workflow_dispatch` inputs that are optional or used in shell commands without validation create security risks: optional inputs may be used without proper validation, inputs can be used in shell commands or file operations enabling injection attacks, and missing validation can lead to path traversal or code injection. Unvalidated inputs are a common vector for command injection and other security vulnerabilities. [^gh_actions_security]

## Vulnerable Instance

- Workflow has `workflow_dispatch` inputs that are optional or used without validation.
- Inputs are used in shell commands or file operations.
- Attacker can inject malicious code through inputs.

```yaml
name: Deploy
on:
  workflow_dispatch:
    inputs:
      environment:
        type: string
        required: false  # Optional, unvalidated
jobs:
  deploy:
    runs-on: ubuntu-latest
    steps:
      - name: Deploy
        run: |
          deploy.sh ${{ inputs.environment }}  # Dangerous - unvalidated
```

## Mitigation Strategies

1. **Make inputs required when necessary**  
   Set `required: true` for inputs that must be provided. This ensures inputs are always present and can be validated.

2. **Validate inputs before use**  
   Validate inputs against allowlists, check for required values, and reject inputs that don't match expected patterns.

3. **Use input types with validation**  
   Use `choice` type when possible to restrict inputs to specific options. This prevents arbitrary input values.

4. **Sanitize inputs used in shell commands**  
   Sanitize all inputs before using them in shell commands. Escape special characters and use parameterized commands.

5. **Review all workflow_dispatch inputs**  
   Audit all workflows for `workflow_dispatch` inputs. Ensure all inputs are validated before use.

6. **Use environment variables**  
   Pass inputs through environment variables instead of direct interpolation in commands. This reduces injection risk.

### Secure Version

```diff
 name: Deploy
 on:
   workflow_dispatch:
     inputs:
       environment:
-        type: string
-        required: false  # Optional, unvalidated
+        type: choice  # Restricted choices
+        options: [production, staging]
+        required: true
 jobs:
   deploy:
     runs-on: ubuntu-latest
     steps:
+      - name: Validate input
+        run: |
+          if [[ "${{ inputs.environment }}" != "production" && "${{ inputs.environment }}" != "staging" ]]; then
+            echo "Invalid environment"
+            exit 1
+          fi
       - name: Deploy
+        env:
+          ENV: ${{ inputs.environment }}
         run: |
-          deploy.sh ${{ inputs.environment }}  # Dangerous - unvalidated
+          deploy.sh "$ENV"  # Validated, quoted
```

## Impact

| Dimension | Severity | Notes |
| --- | --- | --- |
| Likelihood | ![High](https://img.shields.io/badge/-High-orange?style=flat-square) | Unvalidated workflow inputs are common, especially in deployment workflows, and create high risk when used in commands. |
| Risk | ![High](https://img.shields.io/badge/-Critical-red?style=flat-square) | Unvalidated inputs can enable command injection, path traversal, or other attacks that compromise the workflow and its permissions. |
| Blast radius | ![Wide](https://img.shields.io/badge/-Wide-yellow?style=flat-square) | Compromised workflows can affect all systems the workflow can access, including repositories, secrets, and deployment targets. |

## References

- GitHub Docs, "Security hardening for GitHub Actions," https://docs.github.com/en/actions/security-guides/security-hardening-for-github-actions [^gh_actions_security]

---

[^gh_actions_security]: GitHub Docs, "Security hardening for GitHub Actions," https://docs.github.com/en/actions/security-guides/security-hardening-for-github-actions
