# Artifact Poisoning

## Description

Workflows triggered by `workflow_run` or `pull_request_target` run in a privileged context (secrets, write-scoped token) but are often kicked off by a build that ran untrusted code — for example a fork pull request. If such a workflow downloads an artifact produced by that upstream run and then trusts its contents (executes a binary, reads it as configuration, publishes it), an attacker who controlled the untrusted run can poison the artifact and pivot into the privileged workflow. [^gh_security_hardening] This is the consuming (download) side of the artifact problem; the producing side is covered by [Artifact Exposure Risk](/vulnerabilities/artifact_exposure_risk/).

## Vulnerable Instance

- The workflow is triggered by `workflow_run` or `pull_request_target`.
- A job downloads an artifact (e.g. `actions/download-artifact`) and uses it without validation.

```yaml
on:
  workflow_run:
    workflows: [ci]
    types: [completed]
jobs:
  publish:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/download-artifact@v4      # artifact came from the (untrusted) ci run
        with:
          name: dist
      - run: ./dist/installer.sh                # executes attacker-controllable content
```

## Mitigation Strategies

1. **Do not consume untrusted artifacts in privileged workflows.** Keep artifact-consuming logic in the same trust context that produced it, or in a non-privileged workflow.
2. **Validate before use.** Verify artifact names and contents; never execute downloaded files, and treat their data as untrusted input.
3. **Pin and scope.** Download only the specific expected artifact, and avoid running privileged steps in the same job.
4. **Prefer the two-workflow pattern** where the privileged step operates only on trusted, verified inputs.

### Secure Version

```diff
 on:
-  workflow_run:
-    workflows: [ci]
-    types: [completed]
+  push:
+    branches: [main]
 jobs:
   publish:
     runs-on: ubuntu-latest
     steps:
       - uses: actions/download-artifact@v4
         with:
           name: dist
-      - run: ./dist/installer.sh
+      - run: |
+          # validate contents before use; never execute untrusted downloads
+          sha256sum -c dist/checksums.txt
```

## Impact

| Dimension | Severity | Notes |
| --- | --- | --- |
| Likelihood | ![Medium](https://img.shields.io/badge/-Medium-yellow?style=flat-square) | The workflow_run + download-artifact pattern is common for post-build publishing. |
| Risk | ![High](https://img.shields.io/badge/-High-orange?style=flat-square) | Trusting a poisoned artifact can lead to code execution in a privileged workflow. |
| Blast radius | ![Wide](https://img.shields.io/badge/-Wide-yellow?style=flat-square) | The privileged workflow's secrets, token, and deploy targets are exposed. |

## References

- GitHub Docs, "Security hardening for GitHub Actions — Keeping your GitHub Actions and workflows secure," https://docs.github.com/en/actions/security-guides/security-hardening-for-github-actions [^gh_security_hardening]
- GitHub Security Lab, "Keeping your GitHub Actions and workflows secure: Untrusted input," https://securitylab.github.com/research/github-actions-untrusted-input/ [^ghsl_untrusted]

---

[^gh_security_hardening]: GitHub Docs, "Security hardening for GitHub Actions," https://docs.github.com/en/actions/security-guides/security-hardening-for-github-actions
[^ghsl_untrusted]: GitHub Security Lab, "Keeping your GitHub Actions and workflows secure: Untrusted input," https://securitylab.github.com/research/github-actions-untrusted-input/
