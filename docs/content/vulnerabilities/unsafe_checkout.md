# Unsafe Checkout

## Description

Workflows that use `actions/checkout` with `persist-credentials: true` create security risks: credentials are stored in the runner's Git configuration, subsequent steps can access and potentially misuse these credentials, and credentials may be exposed in logs or artifacts. If the runner is compromised, credentials are accessible. The default behavior (`persist-credentials: false`) is more secure and should be used unless credentials are explicitly needed for pushing changes. [^gh_checkout]

## Vulnerable Instance

- Workflow uses `actions/checkout` with `persist-credentials: true`.
- Credentials are persisted in Git configuration for subsequent steps.
- Credentials can be accessed by malicious steps or actions.

```yaml
name: Build
on: [push]
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          persist-credentials: true  # Dangerous - credentials persisted
      - run: npm test
```

## Mitigation Strategies

1. **Remove persist-credentials or set to false**  
   Update the checkout step to use `persist-credentials: false` or remove the line entirely (default is false).

2. **Use GITHUB_TOKEN for pushing**  
   If you need to push changes, use GITHUB_TOKEN with appropriate permissions instead of persisting credentials. GITHUB_TOKEN is automatically available and doesn't need to be persisted.

3. **Use PAT stored in secrets for external repos**  
   For external repositories, use a Personal Access Token (PAT) stored in GitHub Secrets. Don't persist credentials unnecessarily.

4. **Review all checkout steps**  
   Audit all workflows for checkout steps with `persist-credentials: true`. Remove or set to false unless explicitly needed.

5. **Use minimal permissions**  
   Use minimal permissions for GITHUB_TOKEN. Only grant write permissions when necessary for pushing changes.

6. **Isolate credential usage**  
   If credentials must be persisted, isolate their usage to specific steps and clear them afterward when possible.

### Secure Version

```diff
 name: Build
 on: [push]
 jobs:
   build:
     runs-on: ubuntu-latest
+    permissions:
+      contents: write  # Only if pushing needed
     steps:
       - uses: actions/checkout@v4
         with:
-          persist-credentials: true  # Dangerous - credentials persisted
+          persist-credentials: false  # Secure - no credential persistence
       - run: npm test
+      - run: git push  # Uses GITHUB_TOKEN automatically
```

## Impact

| Dimension | Severity | Notes |
| --- | --- | --- |
| Likelihood | ![Medium](https://img.shields.io/badge/-Medium-yellow?style=flat-square) | Persisting credentials is less common but creates risk when present, especially with untrusted actions. |
| Risk | ![High](https://img.shields.io/badge/-High-orange?style=flat-square) | Persisted credentials can be accessed by malicious steps or actions, enabling unauthorized repository access or code modification. |
| Blast radius | ![Medium](https://img.shields.io/badge/-Medium-yellow?style=flat-square) | Impact depends on what the credentials can access, but can affect repository contents and potentially enable persistent compromise. |

## References

- GitHub Docs, "actions/checkout," https://github.com/actions/checkout [^gh_checkout]

---

[^gh_checkout]: GitHub Docs, "actions/checkout," https://github.com/actions/checkout
