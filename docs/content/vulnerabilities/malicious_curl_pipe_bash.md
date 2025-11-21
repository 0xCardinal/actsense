# Malicious Curl Pipe Bash

## Description

`curl ... | bash` downloads and executes remote code in one step with zero verification. If the server or DNS is compromised—or the script changes unexpectedly—attackers gain full control of the workflow’s token and secrets. GitHub’s hardening guide calls this pattern unsafe because it bypasses review and integrity checks. [^gh_curl_pipe]

## Vulnerable Instance

```yaml
jobs:
  setup:
    runs-on: ubuntu-latest
    steps:
      - name: Install tool
        run: curl -fsSL https://example.com/install.sh | bash
```

## Mitigation Strategies

1. **Avoid piping to shell**  
   Download files to disk, inspect them, then execute.
2. **Verify integrity**  
   Check signatures/hashes or use releases with checksums.
3. **Pin versions**  
   Reference immutable assets (e.g., GitHub releases) rather than latest endpoints.
4. **Prefer actions**  
   Use vetted GitHub Actions or container images instead of ad-hoc scripts.
5. **Restrict network egress**  
   If scripts must be fetched, use allowlists and TLS with certificate pinning. [^gh_curl_pipe]

### Secure Version

```diff
 jobs:
   setup:
     runs-on: ubuntu-latest
     steps:
-      - name: Install tool
-        run: curl -fsSL https://example.com/install.sh | bash
+      - name: Download installer
+        run: curl -fsSL https://example.com/install.sh -o install.sh
+      - name: Verify checksum
+        run: echo "abc123  install.sh" | sha256sum --check -
+      - name: Run installer
+        run: bash install.sh
```

## Impact

| Dimension | Severity | Notes |
| --- | --- | --- |
| Likelihood | ![Medium](https://img.shields.io/badge/-Medium-yellow?style=flat-square) | Quick-start guides often recommend this pattern. |
| Risk | ![Critical](https://img.shields.io/badge/-Critical-red?style=flat-square) | Remote code executes with full workflow privileges. |
| Blast radius | ![Wide](https://img.shields.io/badge/-Wide-yellow?style=flat-square) | Any repo/cloud resource accessible to the workflow can be compromised. |

## References

- GitHub Docs, “Security hardening for GitHub Actions,” https://docs.github.com/actions/security-guides/security-hardening-for-github-actions [^gh_curl_pipe]
- curl Manual, “Security considerations,” https://curl.se/docs/security.html

---

[^gh_curl_pipe]: GitHub Docs, “Security hardening for GitHub Actions,” https://docs.github.com/actions/security-guides/security-hardening-for-github-actions