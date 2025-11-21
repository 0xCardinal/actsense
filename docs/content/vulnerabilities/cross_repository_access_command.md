# Cross Repository Access Command

## Description

Workflows that run shell commands like `git clone https://github.com/foo/bar` or `curl https://raw.githubusercontent.com/...` pull code straight from external repositories. Without validation, attackers can swap the target repo, inject malicious scripts, or harvest secrets via the fetched code. GitHub recommends pinning exact SHAs and avoiding user-supplied repository names in commands. [^gh_cross_repo_command]

## Vulnerable Instance

- `run` step clones an arbitrary repository or downloads a script without pinning.
- Repository name comes from an environment variable or workflow input.
- The downloaded code executes immediately (e.g., via `bash script.sh`).

```yaml
name: Pull External Util
on: workflow_dispatch
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - name: Download helper
        run: |
          git clone https://github.com/${{ inputs.repo }} helper
          cd helper && ./install.sh
```

If `inputs.repo` is attacker-controlled, the workflow executes arbitrary code from that repository.

## Mitigation Strategies

1. **Pin to explicit SHAs**  
   Use `git clone --depth=1 --branch <tag>` or download tarballs with known hashes.
2. **Restrict repository inputs**  
   Validate or hardcode the list of allowed repositories/owners.
3. **Prefer actions/checkout with submodules**  
   When accessing code you control, include it as a submodule rather than cloning dynamically.
4. **Verify downloads**  
   Check Git commit signatures or compute checksums before executing downloaded content.
5. **Least-privilege tokens**  
   If access requires authentication, use read-only tokens scoped to the specific repository.

### Secure Version

- Approved repos are enumerated in the workflow.
- Script downloads a reference tarball at a fixed SHA.
- Integrity is verified before execution. [^gh_cross_repo_command]

```yaml
name: Pull External Util (Safe)
on: workflow_dispatch
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - name: Fetch approved helper
        env:
          REPO: my-org/ci-utils
          SHA: 0123456789abcdef
        run: |
          curl -L "https://github.com/$REPO/archive/$SHA.tar.gz" -o helper.tar.gz
          echo "expected_checksum  helper.tar.gz" | sha256sum --check -
          tar -xzf helper.tar.gz
          cd ci-utils-$SHA && ./install.sh
```

## Impact

| Dimension | Severity | Notes |
| --- | --- | --- |
| Likelihood | ![Medium](https://img.shields.io/badge/-Medium-yellow?style=flat-square) | Pulling helper repos via shell commands is common in monorepos and legacy workflows. |
| Risk | ![Critical](https://img.shields.io/badge/-Critical-red?style=flat-square) | Untrusted code executes with workflow privileges, enabling supply-chain compromise. |
| Blast radius | ![Wide](https://img.shields.io/badge/-Wide-yellow?style=flat-square) | Any service reachable by the workflow token (packages, infra) can be affected. |

## References

- GitHub Docs, “Security hardening for GitHub Actions,” https://docs.github.com/actions/security-guides/security-hardening-for-github-actions [^gh_cross_repo_command]
- GitHub Docs, “Workflow syntax for GitHub Actions,” https://docs.github.com/actions/using-workflows/workflow-syntax-for-github-actions#example-using-run-within-a-step

---

[^gh_cross_repo_command]: GitHub Docs, “Security hardening for GitHub Actions,” https://docs.github.com/actions/security-guides/security-hardening-for-github-actions