# Unpinned Dockerfile Dependencies

## Description

Docker actions with Dockerfiles that install Python packages (or other dependencies) without version pinning create security and reproducibility risks: package versions can change between builds, newer versions may introduce security vulnerabilities, and builds are not reproducible. This makes it difficult to track and fix security issues and enables supply-chain attacks through compromised packages. [^gh_actions_docker]

## Vulnerable Instance

- Dockerfile installs Python packages without version pinning (e.g., `pip install requests`).
- Package versions can change between builds, introducing vulnerabilities.
- Builds are not reproducible and difficult to audit.

```dockerfile
FROM python:3.9
RUN pip install requests flask  # Unpinned - versions can change
```

## Mitigation Strategies

1. **Pin packages to specific versions**  
   Use exact version pinning: `RUN pip install requests==2.31.0 flask==3.0.0` instead of `RUN pip install requests flask`.

2. **Use requirements.txt with pinned versions**  
   Create a `requirements.txt` file with pinned versions and install from it: `COPY requirements.txt . && RUN pip install -r requirements.txt`.

3. **Use pip-tools to generate requirements**  
   Use `pip-compile` to generate `requirements.txt` with pinned versions from a `requirements.in` file. This ensures all transitive dependencies are also pinned.

4. **Regularly update and review**  
   Periodically review pinned versions for security updates. Use automated tools like Dependabot to suggest updates.

5. **Use security scanning tools**  
   Scan Docker images for known vulnerabilities in installed packages. Use tools like Trivy or Snyk to detect security issues.

6. **Document dependency management**  
   Establish team guidelines for dependency management in Dockerfiles. Require version pinning for all external dependencies.

### Secure Version

```diff
 FROM python:3.9
+COPY requirements.txt .
-RUN pip install requests flask  # Unpinned - versions can change
+RUN pip install -r requirements.txt
+
+# requirements.txt:
+# requests==2.31.0
+# flask==3.0.0
```

## Impact

| Dimension | Severity | Notes |
| --- | --- | --- |
| Likelihood | ![High](https://img.shields.io/badge/-High-orange?style=flat-square) | Unpinned dependencies in Dockerfiles are common, and package updates can introduce vulnerabilities. |
| Risk | ![High](https://img.shields.io/badge/-High-orange?style=flat-square) | Compromised or vulnerable packages can introduce backdoors, exfiltrate secrets, or enable system compromise. |
| Blast radius | ![Medium](https://img.shields.io/badge/-Medium-yellow?style=flat-square) | Impact depends on what the Docker action does, but can affect all workflows that use the action. |

## References

- GitHub Docs, "Creating a Docker container action," https://docs.github.com/en/actions/creating-actions/creating-a-docker-container-action [^gh_actions_docker]

---

[^gh_actions_docker]: GitHub Docs, "Creating a Docker container action," https://docs.github.com/en/actions/creating-actions/creating-a-docker-container-action
