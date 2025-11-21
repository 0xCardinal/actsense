# Inconsistent Action Version

## Description

Using the same action with different versions across workflows means some jobs miss security patches while others get them. Attackers monitor action advisories and target repositories that still run older tags because they know the code path is exploitable. GitHub recommends pinning actions to a reviewed version or a commit SHA and keeping that consistent across workflows. [^gh_action_versions]

## Vulnerable Instance

- `actions/checkout` appears as `@v2` in one workflow and `@v4` in another.
- Some jobs pin to SHAs, others use floating `@main`.
- When a vulnerability is patched in `v4`, workflows still on `v2` remain at risk.

```yaml
name: Build
on: push
jobs:
  build_v2:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v2
      - run: npm test

  build_latest:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - run: npm test
```

## Mitigation Strategies

1. **Inventory action usage**  
   List every action reference across workflows and identify mismatched versions.
2. **Select a supported baseline**  
   Choose the newest secure major (or SHA) that the project supports.
3. **Update all workflows simultaneously**  
   Apply the version bump across every workflow, not just one file.
4. **Automate drift detection**  
   Use Dependabot or custom scripts to flag actions whose versions diverge.
5. **Document upgrade cadence**  
   Record when the action was last reviewed and schedule periodic reassessments.

### Secure Version

```diff
 name: Build
 on: push
 jobs:
-  build_v2:
+  build:
     runs-on: ubuntu-latest
     steps:
-      - uses: actions/checkout@v2
+      - uses: actions/checkout@v4
       - run: npm test
-
-  build_latest:
-    runs-on: ubuntu-latest
-    steps:
-      - uses: actions/checkout@v4
-      - run: npm test
```

## Impact

| Dimension | Severity | Notes |
| --- | --- | --- |
| Likelihood | ![High](https://img.shields.io/badge/-High-orange?style=flat-square) | Repositories often copy legacy workflows without aligning versions. |
| Risk | ![High](https://img.shields.io/badge/-High-orange?style=flat-square) | Older tags may contain public vulnerabilities or missing mitigations. |
| Blast radius | ![Medium](https://img.shields.io/badge/-Medium-yellow?style=flat-square) | Affected workflows continue to run insecure code even after others are patched. |

## References

- GitHub Docs, “Using versions for actions,” https://docs.github.com/actions/using-workflows/workflow-syntax-for-github-actions#using-versions-for-actions [^gh_action_versions]
- GitHub Docs, “Security hardening for GitHub Actions,” https://docs.github.com/actions/security-guides/security-hardening-for-github-actions

---

[^gh_action_versions]: GitHub Docs, “Using versions for actions,” https://docs.github.com/actions/using-workflows/workflow-syntax-for-github-actions#using-versions-for-actions
