# Unpinned Javascript Resources

## Description

JavaScript actions that download external resources (scripts, binaries, archives) without checksum verification create supply-chain security risks: downloaded resources can be tampered with, man-in-the-middle attacks can replace resources, and compromised download servers can serve malicious files. Without checksum verification, resource integrity cannot be verified, making actions vulnerable to network attacks and supply-chain compromises. [^gh_actions_security]

## Vulnerable Instance

- JavaScript action downloads external resources without checksum verification.
- Downloaded resources can be tampered with or replaced with malicious versions.
- No way to verify resource integrity.

```javascript
// action.js
const https = require('https');
const fs = require('fs');

// Download file without verification
const file = fs.createWriteStream('script.sh');
https.get('https://example.com/script.sh', (response) => {
  response.pipe(file);
  // No checksum verification
});
```

## Mitigation Strategies

1. **Download and verify checksum in JavaScript**  
   Use Node.js crypto module to calculate SHA256 hashes and verify against expected checksums before using downloaded files.

2. **Use SHA256 checksums**  
   Prefer SHA256 checksums for verification. Store expected checksums securely and verify checksums before using downloaded files. Fail the action if checksums don't match.

3. **Store checksums securely**  
   Include checksums in the action code or use a checksums file in the repository. Verify checksums match expected values before using resources.

4. **Use HTTPS for all downloads**  
   Always use HTTPS for downloads to prevent man-in-the-middle attacks. Verify SSL certificates.

5. **Review all external resource downloads**  
   Audit all JavaScript actions for external resource downloads. Document why each resource is needed and where it comes from.

6. **Prefer repository storage**  
   When possible, store resources in the repository rather than downloading them. This allows version control and code review.

### Secure Version

```diff
 // action.js
+const crypto = require('crypto');
 const https = require('https');
 const fs = require('fs');
+
+const expectedHash = 'a1b2c3d4e5f6...'; // SHA256 checksum
+
+// Download and verify
 const file = fs.createWriteStream('script.sh');
 https.get('https://example.com/script.sh', (response) => {
   response.pipe(file);
-  // No checksum verification
+  file.on('finish', () => {
+    const data = fs.readFileSync('script.sh');
+    const hash = crypto.createHash('sha256').update(data).digest('hex');
+    if (hash !== expectedHash) {
+      throw new Error('Checksum verification failed');
+    }
+    // Use verified file
+  });
 });
```

## Impact

| Dimension | Severity | Notes |
| --- | --- | --- |
| Likelihood | ![Medium](https://img.shields.io/badge/-Medium-yellow?style=flat-square) | Downloading resources without verification is common, but creates high risk when present. |
| Risk | ![High](https://img.shields.io/badge/-High-orange?style=flat-square) | Tampered resources can contain backdoors, malicious code, or exfiltrate secrets, enabling system compromise. |
| Blast radius | ![Medium](https://img.shields.io/badge/-Medium-yellow?style=flat-square) | Impact depends on what the resource does, but can affect all workflows that use the JavaScript action. |

## References

- GitHub Docs, "Security hardening for GitHub Actions," https://docs.github.com/en/actions/security-guides/security-hardening-for-github-actions [^gh_actions_security]

---

[^gh_actions_security]: GitHub Docs, "Security hardening for GitHub Actions," https://docs.github.com/en/actions/security-guides/security-hardening-for-github-actions
