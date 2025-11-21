# Runner Label Confusion

## Description

Workflows using runner labels that are confusing or similar to GitHub-hosted runner labels (e.g., `ubuntu-latest`, `windows-latest`, `self-hosted-ubuntu`) create security risks: jobs may run on unintended infrastructure, making it difficult to distinguish between self-hosted and GitHub-hosted runners. This confusion can lead to misconfiguration, privilege escalation, or unauthorized code execution on self-hosted infrastructure when GitHub-hosted runners were intended. [^gh_runners]

## Vulnerable Instance

- Workflow uses a confusing label like `self-hosted-ubuntu` that could be mistaken for `ubuntu-latest`.
- Generic labels like `linux`, `windows`, or `macos` don't clearly indicate self-hosted nature.
- Jobs may run on unintended runners due to label confusion.

```yaml
name: Build with Confusing Label
on: [push]
jobs:
  build:
    runs-on: self-hosted-ubuntu  # Confusing - could be mistaken for ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - run: npm test
```

## Mitigation Strategies

1. **Use unique, distinct labels**  
   Use company-specific or environment-specific labels (e.g., `my-company-runner`, `production-runner`) that clearly indicate self-hosted nature and cannot be confused with GitHub-hosted runners.

2. **Avoid GitHub-hosted runner labels**  
   Don't use labels that match GitHub-hosted runners (`ubuntu-latest`, `windows-latest`, `macos-latest`). Make labels clearly indicate self-hosted nature.

3. **Use runner groups for organization**  
   Organize runners into groups with descriptive names. Document runner labels and purposes to prevent confusion.

4. **Review all runner labels**  
   Ensure labels are unique and clear. Document runner label conventions and avoid generic or confusing labels.

5. **Implement label validation**  
   Use branch protection or workflow validation to ensure only approved runner labels are used. Reject workflows with confusing or unauthorized labels.

6. **Monitor runner usage**  
   Regularly audit which runners execute which workflows. Alert on unexpected runner usage patterns that might indicate label confusion or misconfiguration.

### Secure Version

```diff
 name: Build with Clear Label
 on: [push]
 jobs:
   build:
-    runs-on: self-hosted-ubuntu  # Confusing - could be mistaken for ubuntu-latest
+    runs-on: acme-corp-build-runner  # Clear, distinct label
     steps:
       - uses: actions/checkout@v4
       - run: npm test
```

## Impact

| Dimension | Severity | Notes |
| --- | --- | --- |
| Likelihood | ![Medium](https://img.shields.io/badge/-Medium-yellow?style=flat-square) | Label confusion is common when teams use generic or similar labels, but can be mitigated with clear naming. |
| Risk | ![High](https://img.shields.io/badge/-High-orange?style=flat-square) | Jobs running on unintended infrastructure can expose secrets, execute code on attacker-controlled runners, or bypass security controls. |
| Blast radius | ![Medium](https://img.shields.io/badge/-Medium-yellow?style=flat-square) | Impact depends on the specific runner and its access, but can affect all workflows that use the confused label. |

## References

- GitHub Docs, "About self-hosted runners," https://docs.github.com/en/actions/hosting-your-own-runners/about-self-hosted-runners [^gh_runners]

---

[^gh_runners]: GitHub Docs, "About self-hosted runners," https://docs.github.com/en/actions/hosting-your-own-runners/about-self-hosted-runners
