# Unsafe Checkout Ref

## Description

Workflows that use `actions/checkout` with refs containing variables that may not be properly validated create security risks: if the ref comes from user input (workflow_dispatch, pull_request), attackers could checkout arbitrary branches or commits, malicious code could be executed from untrusted refs, and secrets could be exposed if checking out untrusted code. Refs should be validated against allowlists before use. [^gh_checkout]

## Vulnerable Instance

- Workflow uses `actions/checkout` with a ref from user input without validation.
- Ref could point to malicious code or branches.
- Attackers can checkout arbitrary branches or commits.

```yaml
name: Build from Ref
on:
  workflow_dispatch:
    inputs:
      branch:
        type: string
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          ref: ${{ inputs.branch }}  # Dangerous - unvalidated user input
      - run: npm test
```

## Mitigation Strategies

1. **Validate refs against an allowlist**  
   Validate refs before using them in checkout. Only allow specific branches or patterns that are safe.

2. **Use fixed refs when possible**  
   Use fixed refs like `refs/heads/main` instead of user-controlled variables when the branch is known.

3. **For pull requests, checkout the base branch**  
   Use `github.event.pull_request.base.ref` instead of the PR branch to avoid checking out untrusted code from forks.

4. **Sanitize ref inputs**  
   Sanitize ref inputs before use. Reject refs that don't match expected patterns or contain suspicious characters.

5. **Review all checkout refs**  
   Audit all workflows for checkout steps with user-controlled refs. Ensure all refs are validated.

6. **Use branch protection**  
   Use branch protection rules to prevent direct pushes to protected branches. Require pull requests for changes.

### Secure Version

```diff
 name: Build from Ref
 on:
   workflow_dispatch:
     inputs:
       branch:
-        type: string
+        type: choice
+        options: [main, develop]  # Restricted choices
 jobs:
   build:
     runs-on: ubuntu-latest
     steps:
+      - name: Validate ref
+        run: |
+          if [[ "${{ inputs.branch }}" != "main" && "${{ inputs.branch }}" != "develop" ]]; then
+            echo "Invalid branch"
+            exit 1
+          fi
       - uses: actions/checkout@v4
         with:
-          ref: ${{ inputs.branch }}  # Dangerous - unvalidated user input
+          ref: refs/heads/${{ inputs.branch }}  # Validated
       - run: npm test
```

## Impact

| Dimension | Severity | Notes |
| --- | --- | --- |
| Likelihood | ![Medium](https://img.shields.io/badge/-Medium-yellow?style=flat-square) | Unvalidated checkout refs are less common but create high risk when present, especially with user input. |
| Risk | ![Medium](https://img.shields.io/badge/-High-orange?style=flat-square) | Attackers can checkout malicious branches or commits, enabling code injection, secret exfiltration, or system compromise. |
| Blast radius | ![Wide](https://img.shields.io/badge/-Wide-yellow?style=flat-square) | Compromised code from untrusted refs can affect all systems the workflow can access, including repositories, secrets, and deployment targets. |

## References

- GitHub Docs, "actions/checkout," https://github.com/actions/checkout [^gh_checkout]

---

[^gh_checkout]: GitHub Docs, "actions/checkout," https://github.com/actions/checkout
