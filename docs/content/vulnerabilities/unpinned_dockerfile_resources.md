# Unpinned Dockerfile Resources

## Description

Docker actions with Dockerfiles that download external resources (scripts, binaries, archives) without checksum verification create security risks: downloaded resources can be tampered with, man-in-the-middle attacks can replace resources, and compromised download servers can serve malicious files. Without checksum verification, resource integrity cannot be verified, making builds vulnerable to network attacks and supply-chain compromises. [^gh_actions_docker]

## Vulnerable Instance

- Dockerfile downloads external resources (scripts, binaries) without checksum verification.
- Downloaded resources can be tampered with or replaced with malicious versions.
- No way to verify resource integrity.

```dockerfile
FROM alpine:latest
RUN wget https://example.com/script.sh && bash script.sh  # No verification
```

## Mitigation Strategies

1. **Download and verify checksum**  
   Download the resource, verify its SHA256 checksum, and only then use it: `RUN wget https://example.com/file.tar.gz && echo "abc123..." file.tar.gz | sha256sum -c - && tar -xzf file.tar.gz`.

2. **Use SHA256 checksums**  
   Prefer SHA256 checksums for verification. Store expected checksums in the Dockerfile or a checksums file in the repository.

3. **Store checksums securely**  
   Include checksums in the Dockerfile or use a checksums file in the repository. Verify checksums match expected values before using resources.

4. **Use HTTPS for all downloads**  
   Always use HTTPS for downloads to prevent man-in-the-middle attacks. Verify SSL certificates.

5. **Review all external resource downloads**  
   Audit all Dockerfiles for external resource downloads. Document why each resource is needed and where it comes from.

6. **Prefer repository storage**  
   When possible, store resources in the repository rather than downloading them. This allows version control and code review.

### Secure Version

```diff
 FROM alpine:latest
-RUN wget https://example.com/script.sh && bash script.sh  # No verification
+RUN wget https://example.com/script.sh && \
+    echo "a1b2c3d4e5f6..." script.sh | sha256sum -c - && \
+    bash script.sh
```

## Impact

| Dimension | Severity | Notes |
| --- | --- | --- |
| Likelihood | ![Medium](https://img.shields.io/badge/-Medium-yellow?style=flat-square) | Downloading resources without verification is common, but creates high risk when present. |
| Risk | ![High](https://img.shields.io/badge/-High-orange?style=flat-square) | Tampered resources can contain backdoors, malicious code, or exfiltrate secrets, enabling system compromise. |
| Blast radius | ![Medium](https://img.shields.io/badge/-Medium-yellow?style=flat-square) | Impact depends on what the resource does, but can affect all workflows that use the Docker action. |

## References

- GitHub Docs, "Creating a Docker container action," https://docs.github.com/en/actions/creating-actions/creating-a-docker-container-action [^gh_actions_docker]

---

[^gh_actions_docker]: GitHub Docs, "Creating a Docker container action," https://docs.github.com/en/actions/creating-actions/creating-a-docker-container-action
