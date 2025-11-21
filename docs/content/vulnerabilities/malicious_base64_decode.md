# Malicious Base64 Decode

## Description

Attackers often smuggle malicious scripts in base64-encoded strings, then decode and execute them inside workflows (`base64 -d | bash`). Because the encoded payload is unreadable, reviewers miss it and scanners may not flag it. GitHub warns that decoding opaque data and piping it to a shell is a red flag for supply-chain attacks. [^gh_base64]

## Vulnerable Instance

- Workflow decodes a base64 string and executes the result in one step.

```yaml
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - name: Run helper
        run: echo "ZXZpbCBtYWxpY2lvdXMgcGF5bG9hZA==" | base64 -d | bash
```

## Mitigation Strategies

1. **Avoid opaque payloads**  
   Store scripts in the repository or trusted action, not inline encoded strings.
2. **Decode then verify**  
   If binary data is unavoidable, decode to a file, inspect it, verify checksums, then execute.
3. **Use signed releases**  
   Pull helpers from signed/tagged releases instead of embedding them.
4. **Enable code scanning**  
   Use CodeQL/secret scanning to detect suspicious decode patterns. [^gh_base64]
5. **Review contributions**  
   Block PRs that introduce `base64 -d | bash` or similar constructs.

### Secure Version

```diff
 jobs:
   build:
     runs-on: ubuntu-latest
     steps:
+      - uses: actions/checkout@v4
-      - name: Run helper
-        run: echo "ZXZpbCBtYWxpY2lvdXMgcGF5bG9hZA==" | base64 -d | bash
+      - run: ./scripts/setup.sh
```

## Impact

| Dimension | Severity | Notes |
| --- | --- | --- |
| Likelihood | ![Medium](https://img.shields.io/badge/-Medium-yellow?style=flat-square) | Attackers frequently obfuscate payloads this way. |
| Risk | ![Critical](https://img.shields.io/badge/-Critical-red?style=flat-square) | Decoded code runs with workflow permissions, enabling full compromise. |
| Blast radius | ![Wide](https://img.shields.io/badge/-Wide-yellow?style=flat-square) | Any resource the workflow touches (repo, secrets, cloud) is exposed. |

## References

- GitHub Security Lab, “Untrusted input in GitHub Actions,” https://securitylab.github.com/research/github-actions-untrusted-input/ [^gh_base64]
- GitHub Docs, “Security hardening for GitHub Actions,” https://docs.github.com/actions/security-guides/security-hardening-for-github-actions

---

[^gh_base64]: GitHub Security Lab, “Untrusted input in GitHub Actions,” https://securitylab.github.com/research/github-actions-untrusted-input/

