# Unpinnable Docker Image

## Description

Docker actions that use mutable tags (e.g., `latest`, `v1`, `v1.2`) instead of immutable digests create supply-chain risks: tags can be moved to point to different images, deleted and recreated, or redirected to malicious images if the registry is compromised. Your workflow would then automatically use the new (potentially malicious) image. Docker image digests (SHA256) are immutable and provide guaranteed integrity. [^gh_actions_docker]

## Vulnerable Instance

- Docker action uses a mutable tag like `docker://alpine:latest` instead of a digest.
- Tag can be moved to point to a different image, potentially malicious.
- Workflow would automatically use the new image on the next run.

```yaml
# action.yml
name: 'Docker Action'
runs:
  using: 'docker'
  image: 'docker://alpine:latest'  # Mutable tag - can be moved
```

## Mitigation Strategies

1. **Get the image digest**  
   Pull the image and inspect it: `docker pull alpine:latest && docker inspect alpine:latest | grep RepoDigests`. Or use `docker image inspect alpine:latest --format='{{.RepoDigests}}'`.

2. **Update the action to use digest**  
   Replace the tag with the digest: `docker://alpine@sha256:abc123...` where the digest is the full SHA256 hash.

3. **Verify the digest is correct**  
   The digest should start with `sha256:` and be 64 hexadecimal characters. Verify at the image registry.

4. **Update all Docker actions**  
   Audit all Docker actions and migrate them to use digests instead of tags.

5. **Automate digest updates**  
   Use tools to monitor for image updates and suggest digest updates, but always review changes before merging.

6. **Document pinning policy**  
   Establish team guidelines requiring digest pinning for all Docker images in actions.

### Secure Version

```diff
 # action.yml
 name: 'Docker Action'
 runs:
   using: 'docker'
-  image: 'docker://alpine:latest'  # Mutable tag - can be moved
+  image: 'docker://alpine@sha256:21a3deaa0d32a8057914f36584b5288d2e5ecc984380bc0118285d70cf261174'  # Immutable digest
```

## Impact

| Dimension | Severity | Notes |
| --- | --- | --- |
| Likelihood | ![High](https://img.shields.io/badge/-High-orange?style=flat-square) | Docker actions commonly use tags, and registry compromises or tag manipulation can redirect to malicious images. |
| Risk | ![High](https://img.shields.io/badge/-Critical-red?style=flat-square) | Compromised Docker images can contain backdoors, malicious code, or exfiltrate secrets, enabling full system compromise. |
| Blast radius | ![Wide](https://img.shields.io/badge/-Wide-yellow?style=flat-square) | Compromised Docker actions can affect all workflows that use them, potentially compromising entire CI/CD pipelines and deployments. |

## References

- GitHub Docs, "Creating a Docker container action," https://docs.github.com/en/actions/creating-actions/creating-a-docker-container-action [^gh_actions_docker]

---

[^gh_actions_docker]: GitHub Docs, "Creating a Docker container action," https://docs.github.com/en/actions/creating-actions/creating-a-docker-container-action
