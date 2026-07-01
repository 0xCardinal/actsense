# Reusable Workflow Secrets Inheritance

## Description

When one workflow calls a reusable workflow, it can forward credentials with `secrets: inherit`. This passes **all** of the caller's secrets to the called workflow with no per-secret control. [^gh_reusable] The called workflow — which may live in another repository, be maintained by a different team, or be updated independently — then has access to the caller's complete secret store, widening the blast radius of any vulnerability or compromise in that downstream workflow. Explicitly naming the secrets a reusable workflow requires keeps each credential scoped to where it is genuinely needed. This complements [Excessive Secret Exposure](/vulnerabilities/excessive_secret_exposure/), which concerns bulk serialization within a single workflow.

## Vulnerable Instance

- A job calls a reusable workflow via `uses:` and forwards credentials with `secrets: inherit`.
- The reusable workflow receives every secret available to the caller, not just the ones it needs.

```yaml
name: Release
on: [push]
jobs:
  publish:
    uses: ./.github/workflows/publish.yml
    secrets: inherit   # forwards ALL caller secrets downstream
```

## Mitigation Strategies

1. **Pass only the required secrets, explicitly by name**
   Declare each secret the reusable workflow needs and forward just those.

   ```yaml
   jobs:
     publish:
       uses: ./.github/workflows/publish.yml
       secrets:
         REGISTRY_TOKEN: ${{ secrets.REGISTRY_TOKEN }}
   ```

2. **Declare inputs in the reusable workflow**
   Have the reusable workflow define a `workflow_call` block with explicit `secrets:` entries so callers cannot accidentally over-share.

3. **Audit cross-repository reuse**
   Be especially careful when the reusable workflow lives in a different repository or is maintained by another team; `inherit` exposes your secrets to code you do not directly control.

4. **Prefer short-lived credentials**
   Where possible, have the reusable workflow obtain its own short-lived tokens via OIDC instead of receiving long-lived secrets from the caller.

### Secure Version

```diff
 name: Release
 on: [push]
 jobs:
   publish:
     uses: ./.github/workflows/publish.yml
-    secrets: inherit
+    secrets:
+      REGISTRY_TOKEN: ${{ secrets.REGISTRY_TOKEN }}
```

## Impact

| Dimension | Severity | Notes |
| --- | --- | --- |
| Likelihood | ![Medium](https://img.shields.io/badge/-Medium-yellow?style=flat-square) | `secrets: inherit` is convenient and widely used, often without considering how many secrets it forwards. |
| Risk | ![Medium](https://img.shields.io/badge/-Medium-orange?style=flat-square) | A vulnerability or compromise in the called workflow gains access to every secret the caller holds. |
| Blast radius | ![Wide](https://img.shields.io/badge/-Wide-yellow?style=flat-square) | All caller secrets become reachable by the downstream workflow, which may be externally maintained. |

## References

- GitHub Docs, "Reusing workflows — Passing inherited secrets to a reusable workflow," https://docs.github.com/en/actions/using-workflows/reusing-workflows#passing-inherited-secrets-to-a-reusable-workflow [^gh_reusable]
- GitHub Docs, "Security hardening for GitHub Actions," https://docs.github.com/en/actions/security-guides/security-hardening-for-github-actions [^gh_actions_security]

---

[^gh_reusable]: GitHub Docs, "Reusing workflows," https://docs.github.com/en/actions/using-workflows/reusing-workflows#passing-inherited-secrets-to-a-reusable-workflow
[^gh_actions_security]: GitHub Docs, "Security hardening for GitHub Actions," https://docs.github.com/en/actions/security-guides/security-hardening-for-github-actions
