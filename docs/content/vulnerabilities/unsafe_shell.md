# Unsafe Shell

## Description

Bash scripts that run without the `-e` flag (exit on error) create security and reliability risks: scripts continue executing even if a command fails, errors may be silently ignored, and security checks or validations may be bypassed. This can lead to unexpected behavior, invalid states, and security vulnerabilities going undetected. [^gh_actions_security]

## Vulnerable Instance

- Bash script runs without `set -e`, allowing execution to continue after failures.
- Failed security checks may not be detected.
- Script may continue with invalid state.

```yaml
name: Build
on: [push]
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - name: Run script
        run: |
          # No set -e - errors ignored
          npm install
          npm test  # May not run if install fails
          npm build
```

## Mitigation Strategies

1. **Add -e flag to bash commands**  
   Use `set -e` at the start of scripts to exit immediately if any command fails.

2. **Use stricter error handling**  
   Use `set -euo pipefail` for stricter error handling: exit on error, undefined variables, and pipe failures.

3. **Specify in shell**  
   Use `shell: bash -e {0}` to enable exit-on-error for the entire step.

4. **Review all bash scripts**  
   Audit all workflows for bash scripts without error handling. Add `set -e` or `set -euo pipefail` to all scripts.

5. **Test error handling**  
   Test error handling to ensure failures are caught. Verify that scripts fail appropriately when commands fail.

6. **Use proper error messages**  
   When using `set -e`, ensure error messages are clear and actionable. Consider using `trap` for cleanup on errors.

### Secure Version

```yaml
name: Build
on: [push]
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - name: Run script
        run: |
          set -euo pipefail  # Exit on error, undefined vars, pipe failures
          npm install
          npm test
          npm build
```

## Impact

| Dimension | Severity | Notes |
| --- | --- | --- |
| Likelihood | ![High](https://img.shields.io/badge/-High-orange?style=flat-square) | Bash scripts without error handling are common, especially in legacy workflows. |
| Risk | ![Medium](https://img.shields.io/badge/-Medium-yellow?style=flat-square) | Failed security checks or validations may go undetected, potentially allowing vulnerabilities to persist. |
| Blast radius | ![Medium](https://img.shields.io/badge/-Medium-yellow?style=flat-square) | Impact depends on what the script does, but can affect build processes, deployments, and security checks. |

## References

- GitHub Docs, "Security hardening for GitHub Actions," https://docs.github.com/en/actions/security-guides/security-hardening-for-github-actions [^gh_actions_security]

---

[^gh_actions_security]: GitHub Docs, "Security hardening for GitHub Actions," https://docs.github.com/en/actions/security-guides/security-hardening-for-github-actions
