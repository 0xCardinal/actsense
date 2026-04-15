# Unpinned Container Image

## Description

GitHub Actions allows jobs to run inside Docker containers via the `container` key and to spin up sidecar services via `services`. When these images are referenced by a **mutable tag** (e.g., `node:20`, `postgres:latest`), the actual image content can change at any time without the workflow file being modified. An attacker who compromises a registry account or exploits a tag-rewriting vulnerability can inject malicious code into every workflow run that pulls the tag.

Pinning to an **immutable digest** (`image@sha256:abc123…`) guarantees that the exact same image layers are used on every run, regardless of what the tag currently points to.

## Vulnerable Instance

- A job uses `container: node:20` or `container: { image: postgres:15 }`.
- A service uses `image: redis:latest`.
- Any image reference that does **not** contain `@sha256:`.

```yaml
name: Build
on: [push]

jobs:
  test:
    runs-on: ubuntu-latest
    container:
      image: node:20          # Mutable tag
    services:
      db:
        image: postgres:15    # Mutable tag
    steps:
      - run: node -v
```

## Mitigation Strategies

1. **Pin to a digest.** Look up the current digest with `docker inspect --format='{{index .RepoDigests 0}}' node:20` or on Docker Hub, then replace the tag:

   ```yaml
   container:
     image: node@sha256:a5e0ed...   # Immutable digest
   ```

2. **Use Dependabot or Renovate** to keep digests up to date automatically. Both tools can parse GitHub Actions workflow files and open PRs when new digests are available.

3. **Use a private mirror or pull-through cache** so images are scanned and approved before they reach CI runners.

### Secure Version

```diff
 jobs:
   test:
     runs-on: ubuntu-latest
     container:
-      image: node:20
+      image: node@sha256:a5e0ed056baaa3b68...
     services:
       db:
-        image: postgres:15
+        image: postgres@sha256:8f3c1e7a4b...
     steps:
       - run: node -v
```

## Impact

| Dimension | Severity | Notes |
| --- | --- | --- |
| Likelihood | ![Medium](https://img.shields.io/badge/-Medium-yellow?style=flat-square) | Requires compromise of a registry or tag, but such incidents have occurred |
| Risk | ![High](https://img.shields.io/badge/-High-orange?style=flat-square) | Arbitrary code execution inside the CI environment |
| Blast radius | ![Wide](https://img.shields.io/badge/-Wide-yellow?style=flat-square) | Affects every workflow run that pulls the compromised tag |

## References

- GitHub Docs, "Workflow syntax - jobs.&lt;id&gt;.container," https://docs.github.com/actions/using-workflows/workflow-syntax-for-github-actions#jobsjob_idcontainer
- Docker Docs, "Content trust and image signing," https://docs.docker.com/engine/security/trust/
- StepSecurity, "Harden Runner - Pin container images," https://github.com/step-security/harden-runner
