# Malicious Curl Pipe Bash

## Description

`curl ... | bash` downloads and executes remote code in one step with zero verification. If the server or DNS is compromised—or the script changes unexpectedly—attackers gain full control of the workflow’s token and secrets. GitHub’s hardening guide calls this pattern unsafe because it bypasses review and integrity checks. [^gh_curl_pipe]

## Vulnerable Instance

Real-world examples of this pattern are common in quick-start docs — these are all unsafe:

```yaml
jobs:
  setup:
    runs-on: ubuntu-latest
    steps:
      # Installing a CLI tool directly from its website
      - name: Install tool
        run: curl -fsSL https://get.some-cli-tool.io | bash

      # Installing language version managers
      - name: Install nvm
        run: curl -o- https://raw.githubusercontent.com/nvm-sh/nvm/v0.39.7/install.sh | bash

      # Installing package managers
      - name: Install Homebrew
        run: /bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
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

**Preferred — use the official GitHub Action instead of a shell installer:**

```diff
 jobs:
   setup:
     runs-on: ubuntu-latest
     steps:
-      - name: Install nvm
-        run: curl -o- https://raw.githubusercontent.com/nvm-sh/nvm/v0.39.7/install.sh | bash
+      - name: Set up Node.js
+        uses: actions/setup-node@49933ea5288caeca8642d1e84afbd3f7d6820020  # v4.4.0
+        with:
+          node-version: 20
```

**When no action exists — download, verify checksum, then execute:**

```diff
 jobs:
   setup:
     runs-on: ubuntu-latest
     steps:
-      - name: Install tool
-        run: curl -fsSL https://releases.example-tool.io/v2.1.0/install.sh | bash
+      - name: Download installer
+        run: |
+          curl -fsSL -o install.sh \
+            https://releases.example-tool.io/v2.1.0/install.sh
+      - name: Verify SHA-256 checksum
+        run: |
+          # Full 64-character SHA-256 hash published on the release page
+          echo "b94d27b9934d3e08a52e52d7da7dabfac484efe04294e576f62f6b6d87c67e8  install.sh" \
+            | sha256sum -c -
+      - name: Run verified installer
+        run: bash install.sh
```

> **Note:** The hash in the `echo` must be the real 64-character SHA-256 digest from the tool's official release page. A placeholder or shortened hash provides no security guarantee.

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