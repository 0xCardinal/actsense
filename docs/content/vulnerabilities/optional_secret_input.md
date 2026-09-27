# Optional Secret Input

## Description

An action declares an input whose description says it carries a secret, password, or token, but marks it `required: false` with no default. If a caller forgets to pass it, the action does not fail. Depending on how it is written, it may run unauthenticated, fall back to a weaker credential, or skip a verification step, and the job still passes. [^gh_metadata] An input such as `token` that defaults to `${{ github.token }}` is the standard, safe pattern and is not reported.

## Vulnerable Instance

- The action's `action.yml` declares a secret-like input as optional.
- The input has no safe default, so omitting it silently changes the action's behavior.

```yaml
# action.yml
inputs:
  registry-password:
    description: Password for the private registry
    required: false
runs:
  using: node20
  main: dist/index.js
```

## Mitigation Strategies

1. **Make the input required**
   If the action cannot do its job securely without the credential, declare `required: true` so a missing value fails fast.

2. **Fail closed in code**
   When an input really is optional, have the action error out (or clearly log a warning) instead of continuing unauthenticated.

3. **Provide a safe default**
   For GitHub API access, default to `${{ github.token }}` so the action always has a scoped credential.

### Secure Version

```diff
 inputs:
   registry-password:
     description: Password for the private registry
-    required: false
+    required: true
```

## Impact

| Dimension | Severity | Notes |
| --- | --- | --- |
| Likelihood | ![Low](https://img.shields.io/badge/-Low-green?style=flat-square) | Only matters when a caller omits the input. |
| Risk | ![Low](https://img.shields.io/badge/-Low-green?style=flat-square) | The usual outcome is a silently skipped check or an unauthenticated request, not direct credential exposure. |
| Blast radius | ![Narrow](https://img.shields.io/badge/-Narrow-green?style=flat-square) | Limited to workflows that use the action without the input. |

## References

- GitHub Docs, "Metadata syntax for GitHub Actions — inputs," https://docs.github.com/en/actions/sharing-automations/creating-actions/metadata-syntax-for-github-actions#inputs [^gh_metadata]

---

[^gh_metadata]: GitHub Docs, "Metadata syntax for GitHub Actions," https://docs.github.com/en/actions/sharing-automations/creating-actions/metadata-syntax-for-github-actions#inputs
