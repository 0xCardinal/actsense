# Self Hosted Runner Network Risk

## Description

Self-hosted runners that download and execute code from the internet without verification create significant security risks: downloaded scripts may be malicious, there's no verification of code integrity, and attackers can inject malicious payloads that compromise the runner. Once compromised, runners can be used to access internal networks, exfiltrate secrets, or perform lateral movement attacks. Network operations from self-hosted runners should be carefully controlled and verified. [^gh_runners]

## Vulnerable Instance

- Workflow downloads and executes scripts from the internet on self-hosted runners without verification.
- No checksum verification or code review before execution.
- Malicious code can compromise the runner and access internal resources.

```yaml
name: Download and Run
on: [push]
jobs:
  setup:
    runs-on: self-hosted
    steps:
      - run: curl https://example.com/script.sh | bash  # Dangerous - no verification
```

## Mitigation Strategies

1. **Download and verify scripts first**  
   Download scripts to files, verify checksums before execution, review script content if possible, and only then execute verified scripts.

2. **Use trusted sources**  
   Only download from trusted sources, use HTTPS with certificate verification, pin to specific versions/commits, and verify checksums.

3. **Store scripts in repository**  
   Store scripts in the repository rather than downloading from the internet. This allows code review and version control.

4. **Use GitHub Actions**  
   Prefer GitHub Actions instead of shell scripts downloaded from the internet. Actions are more transparent and can be pinned to specific versions.

5. **Implement network security controls**  
   Use network segmentation, implement firewall rules, monitor outbound connections, and use allowlists for permitted endpoints.

6. **Use containerized execution**  
   Run untrusted code in containers with minimal privileges. Avoid `--privileged` flag and use specific capabilities if needed.

### Secure Version

```diff
 name: Download and Verify
 on: [push]
 jobs:
   setup:
     runs-on: self-hosted
     steps:
+      - name: Download script
+        run: |
+          curl -o script.sh https://example.com/script.sh
+          echo "expected_sha256" | sha256sum -c script.sh
+      - name: Review and execute
+        run: bash script.sh
-      - run: curl https://example.com/script.sh | bash  # Dangerous - no verification
```

## Impact

| Dimension | Severity | Notes |
| --- | --- | --- |
| Likelihood | ![Medium](https://img.shields.io/badge/-Medium-yellow?style=flat-square) | Downloading and executing scripts is common, but unverified downloads create high risk. |
| Risk | ![Critical](https://img.shields.io/badge/-Critical-red?style=flat-square) | Malicious scripts can fully compromise self-hosted runners, providing access to internal networks and secrets. |
| Blast radius | ![Wide](https://img.shields.io/badge/-Wide-yellow?style=flat-square) | Compromised runners can affect all systems the runner can access, including internal networks, databases, and services. |

## References

- GitHub Docs, "About self-hosted runners," https://docs.github.com/en/actions/hosting-your-own-runners/about-self-hosted-runners [^gh_runners]

---

[^gh_runners]: GitHub Docs, "About self-hosted runners," https://docs.github.com/en/actions/hosting-your-own-runners/about-self-hosted-runners
