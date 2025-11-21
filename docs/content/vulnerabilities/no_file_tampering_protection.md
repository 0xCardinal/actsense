# No File Tampering Protection

## Description

Build jobs that modify files during execution without integrity checks are vulnerable to supply-chain tampering: malicious actions or compromised dependencies can alter source code or build artifacts before deployment, injecting backdoors or exfiltrating data. Without file integrity monitoring, these modifications go undetected until artifacts reach production. [^gh_actions_security]

## Vulnerable Instance

- Build job modifies source files or artifacts without checksums or integrity verification.
- Malicious action or dependency could tamper with files during the build process.
- No monitoring or alerts for unauthorized file modifications.

```yaml
name: Build Without Protection
on: [push]
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: untrusted-action/build@v1  # Could tamper with files
      - run: |
          sed -i 's/old/new/g' src/*.js  # Modifies files without verification
          npm run build
      - uses: actions/upload-artifact@v4
        with:
          name: dist
          path: dist/
```

## Mitigation Strategies

1. **Implement file integrity checks**  
   Calculate checksums (SHA-256) before and after build steps. Compare hashes to detect tampering and fail the workflow if mismatches occur.

2. **Use read-only source checkouts**  
   Minimize file modifications during build. Use separate directories for build outputs and isolate source code from artifacts.

3. **Monitor file modifications**  
   Log all file write operations and review changes in build logs. Use EDR tools or workflow steps to track file system activity.

4. **Use trusted build environments**  
   Prefer GitHub-hosted runners when possible. If using self-hosted runners, ensure they're secured and isolated with minimal file system access.

5. **Validate build outputs**  
   Before uploading artifacts, verify they match expected checksums. Sign artifacts cryptographically when deploying to production.

6. **Isolate build steps**  
   Run untrusted actions in separate jobs with limited permissions. Use job dependencies to ensure source integrity before artifact generation.

### Secure Version

```diff
 name: Build With Integrity Checks
 on: [push]
 jobs:
+  verify-source:
+    runs-on: ubuntu-latest
+    steps:
+      - uses: actions/checkout@v4
+      - name: Calculate source checksum
+        run: find src -type f -exec sha256sum {} \; > source.checksums
+      - uses: actions/upload-artifact@v4
+        with:
+          name: source-checksums
+          path: source.checksums
   build:
+    needs: verify-source
     runs-on: ubuntu-latest
     steps:
       - uses: actions/checkout@v4
-      - uses: untrusted-action/build@v1  # Could tamper with files
+      - name: Verify source integrity
+        run: |
+          find src -type f -exec sha256sum {} \; > build.checksums
+          diff source.checksums build.checksums || exit 1
       - run: npm run build
-      - uses: actions/upload-artifact@v4
+      - name: Verify build outputs
+        run: sha256sum dist/* > dist.checksums
+      - uses: actions/upload-artifact@v4
         with:
           name: dist
           path: dist/
```

## Impact

| Dimension | Severity | Notes |
| --- | --- | --- |
| Likelihood | ![Medium](https://img.shields.io/badge/-Medium-yellow?style=flat-square) | File tampering requires compromised dependencies or malicious actions, but supply-chain attacks are increasing. |
| Risk | ![High](https://img.shields.io/badge/-High-orange?style=flat-square) | Tampered artifacts deployed to production can introduce backdoors, exfiltrate data, or compromise downstream systems. |
| Blast radius | ![Wide](https://img.shields.io/badge/-Wide-yellow?style=flat-square) | Compromised build outputs affect all consumers of the artifacts, potentially spreading to production deployments and end users. |

## References

- GitHub Docs, "Security hardening for GitHub Actions," https://docs.github.com/en/actions/security-guides/security-hardening-for-github-actions [^gh_actions_security]

---

[^gh_actions_security]: GitHub Docs, "Security hardening for GitHub Actions," https://docs.github.com/en/actions/security-guides/security-hardening-for-github-actions

