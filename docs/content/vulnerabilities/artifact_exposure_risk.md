# Artifact Exposure Risk

## Description

Uploading workflow artifacts with overly broad path patterns, missing retention policies, or unsafe configurations can create risks of exposing sensitive files through publicly accessible artifacts. This static analysis check identifies workflow misconfigurations that may lead to unintended data exposure, including:

- Dangerous artifact upload paths (`.`, `**`, `*`, `${{ github.workspace }}`)
- Uploading entire workspace including `.git/` directory
- Checkout with persisted credentials increasing leak risk
- Missing retention-days on upload-artifact
- Upload-artifact steps happening before the end of a job
- Misconfigured artifact paths potentially including sensitive files

The check assigns severity levels based on the risk: **CRITICAL** for broad workspace uploads (`.`, `${{ github.workspace }}`) combined with persisted credentials (can expose `.git/config`), **HIGH** for broad path patterns (`**`, `*`) without persisted credentials, **MEDIUM** for missing `retention-days` configuration, and **LOW** for artifact uploads not at the end of a job (increases exposure window but still safe if paths are properly scoped).

**Note:** This check detects static workflow misconfigurations that create exposure risks. It does not perform runtime exploitation or artifact content analysis. For information about the ArtiPACKED vulnerability (which includes runtime exploitation), see the references section.

## Vulnerable Instance

- A workflow uploads the entire checkout directory (including `.git/`) as an artifact, which could expose persisted `GITHUB_TOKEN` values if credentials are persisted by `actions/checkout`.
- Artifact uploads use broad glob patterns (`**`, `*`) that may unintentionally include sensitive files.
- Missing `retention-days` configuration allows artifacts to be retained longer than necessary.
- Artifact uploads occur before the final step, increasing the exposure window.

```yaml
jobs:
  lint-and-archive:
    steps:
      - uses: actions/checkout@v4
        # Default persist-credentials=true stores GITHUB_TOKEN in .git/
      - uses: super-linter/super-linter@v6
        env:
          CREATE_LOG_FILE: true
      - uses: actions/upload-artifact@v4
        with:
          name: full-checkout
          path: .
          # Missing retention-days
```

## Mitigation Strategies

1. **Use explicit artifact paths**  
   Restrict `actions/upload-artifact` inputs to the minimal set of files required. Avoid broad patterns like `.`, `**`, or `${{ github.workspace }}`.

2. **Exclude sensitive directories**  
   Explicitly exclude `.git/`, `node_modules/`, and other sensitive directories from artifact uploads.

3. **Disable credential persistence**  
   Set `persist-credentials: false` on `actions/checkout` unless authenticated git operations are necessary.

4. **Set retention-days**  
   Set `retention-days` to the minimal necessary value to reduce the exposure window.

5. **Order artifact uploads safely**  
   Move artifact upload steps toward the end of the job for safer ordering.

### Secure Version

```diff
 jobs:
-  lint-and-archive:
+  build:
     steps:
       - uses: actions/checkout@v4
         with:
-          # Default persist-credentials=true stores GITHUB_TOKEN in .git/
-      - uses: super-linter/super-linter@v6
-        env:
-          CREATE_LOG_FILE: true
+          persist-credentials: false
+      - run: npm run build
       - uses: actions/upload-artifact@v4
         with:
-          name: full-checkout
-          path: .
-          # Missing retention-days
+          name: dist-bundle
+          path: dist/**
+          retention-days: 14
```

## Impact

| Dimension | Severity | Notes |
| --- | --- | --- |
| Likelihood | ![High](https://img.shields.io/badge/-High-orange?style=flat-square) | Broad artifact upload patterns and default checkout settings are common, creating widespread exposure risks. |
| Risk | ![High](https://img.shields.io/badge/-High-orange?style=flat-square) | Misconfigured artifacts can expose sensitive files, credentials, or internal repositories. **CRITICAL** severity when broad workspace uploads (`.`, `${{ github.workspace }}`) are combined with persisted credentials (can expose `.git/config`). **HIGH** severity for broad path patterns (`**`, `*`) without persisted credentials. **MEDIUM** for missing `retention-days` configuration. **LOW** for artifact uploads not at the end of a job. |
| Blast radius | ![Medium](https://img.shields.io/badge/-Medium-yellow?style=flat-square) | Exposed artifacts are accessible to anyone with repository access, potentially exposing sensitive build artifacts or configuration files. |

## References

- Palo Alto Networks Unit 42, "ArtiPACKED: Hacking Giants Through a Race Condition in GitHub Actions Artifacts," Aug 13, 2024. https://unit42.paloaltonetworks.com/github-repo-artifacts-leak-tokens/
- GitHub Docs, "Store workflow data as artifacts," https://docs.github.com/actions/using-workflows/storing-workflow-data-as-artifacts
