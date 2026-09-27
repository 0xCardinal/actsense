# Unsafe Shell

## Description

A step that runs Bash without exit-on-error keeps going after a command fails. A failed download, signature check, or test is silently ignored, and later steps build, publish, or deploy on top of a broken or unverified state.

GitHub already protects the common cases. A `run:` step with no `shell:` key on a Linux or macOS runner runs as `bash -e {0}`, and `shell: bash` runs as `bash --noprofile --norc -eo pipefail {0}`. [^gh_shell] The protection is lost only when a workflow supplies its own **custom shell template** (a `shell:` value containing `{0}`) and leaves out `-e`.

## Vulnerable Instance

- A step sets a custom shell template such as `shell: bash {0}` or `shell: bash --noprofile {0}`.
- The template has no `-e` / `-o errexit`, so a failing command does not stop the step.

```yaml
name: Release
on: [push]
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - name: Verify and publish
        shell: bash {0}   # custom template without -e
        run: |
          cosign verify-blob --signature app.sig app.tar.gz   # failure is ignored
          ./publish.sh app.tar.gz                             # still runs
```

## How actsense detects this

actsense reports a step only when its `shell:` value is a custom template (contains `{0}`), invokes `bash`, and has no `-e` flag or `errexit` option. Steps with no `shell:` key, or with plain `shell: bash`, are not reported, because GitHub already runs them with `-e`. Reported as **medium**.

## Mitigation Strategies

1. **Use the built-in shell**
   Prefer `shell: bash` (or omit `shell:`); GitHub adds `-eo pipefail` for you.

2. **Keep `-e` in custom templates**
   If you need custom flags, include exit-on-error: `shell: bash --noprofile --norc -eo pipefail {0}`.

3. **Be strict inside scripts too**
   Start longer scripts with `set -euo pipefail`, so unset variables and failures inside pipelines also stop the step.

### Secure Version

```diff
       - name: Verify and publish
-        shell: bash {0}
+        shell: bash -eo pipefail {0}
         run: |
           cosign verify-blob --signature app.sig app.tar.gz
           ./publish.sh app.tar.gz
```

## Impact

| Dimension | Severity | Notes |
| --- | --- | --- |
| Likelihood | ![Low](https://img.shields.io/badge/-Low-green?style=flat-square) | Custom shell templates are uncommon; the defaults are already safe. |
| Risk | ![Medium](https://img.shields.io/badge/-Medium-yellow?style=flat-square) | A skipped verification step can let unverified or broken artifacts through. |
| Blast radius | ![Medium](https://img.shields.io/badge/-Medium-yellow?style=flat-square) | Limited to what the affected step builds, publishes, or deploys. |

## References

- GitHub Docs, "Workflow syntax — defaults.run.shell / jobs.<job_id>.steps[*].shell," https://docs.github.com/en/actions/writing-workflows/workflow-syntax-for-github-actions#jobsjob_idstepsshell [^gh_shell]
- GitHub Docs, "Security hardening for GitHub Actions," https://docs.github.com/en/actions/security-guides/security-hardening-for-github-actions

---

[^gh_shell]: GitHub Docs, "Workflow syntax for GitHub Actions — shell," https://docs.github.com/en/actions/writing-workflows/workflow-syntax-for-github-actions#jobsjob_idstepsshell
