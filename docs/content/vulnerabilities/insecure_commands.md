# Insecure Workflow Commands

## Description

GitHub Actions once let steps set environment variables and modify `PATH` by printing `::set-env` and `::add-path` stdout commands. Because any process output could set variables, this was a code-execution sink and GitHub disabled it — unless the workflow opts back in with `ACTIONS_ALLOW_UNSECURE_COMMANDS: true`. [^gh_deprecating] Re-enabling these commands (or using them directly) lets attacker-influenced output define variables like `LD_PRELOAD`/`NODE_OPTIONS` or prepend a directory to `PATH`, exactly like the modern [GitHub Environment File Injection](/vulnerabilities/github_env_injection/) sink.

## Vulnerable Instance

- A workflow, job, or step sets `ACTIONS_ALLOW_UNSECURE_COMMANDS: true`.
- Or a step still emits `::set-env` / `::add-path` stdout commands.

```yaml
jobs:
  build:
    runs-on: ubuntu-latest
    env:
      ACTIONS_ALLOW_UNSECURE_COMMANDS: true   # re-enables the injectable commands
    steps:
      - run: echo "::set-env name=PATH::/tmp/evil:$PATH"
```

## Mitigation Strategies

1. **Remove `ACTIONS_ALLOW_UNSECURE_COMMANDS`.** There is no safe reason to re-enable the deprecated commands.
2. **Use the environment files.** Migrate to `$GITHUB_ENV` and `$GITHUB_PATH`, and validate any user-controllable value before writing it (see [GitHub Environment File Injection](/vulnerabilities/github_env_injection/)).
3. **Update old actions.** If a dependency requires the flag, upgrade it to a version that uses the environment files.

### Secure Version

```diff
 jobs:
   build:
     runs-on: ubuntu-latest
-    env:
-      ACTIONS_ALLOW_UNSECURE_COMMANDS: true
     steps:
-      - run: echo "::set-env name=FOO::bar"
+      - run: echo "FOO=bar" >> "$GITHUB_ENV"
```

## Impact

| Dimension | Severity | Notes |
| --- | --- | --- |
| Likelihood | ![Low](https://img.shields.io/badge/-Low-green?style=flat-square) | Uncommon in modern workflows, but persists in older ones and some third-party actions. |
| Risk | ![High](https://img.shields.io/badge/-High-orange?style=flat-square) | Re-enables an injection sink that can execute code in later steps. |
| Blast radius | ![Wide](https://img.shields.io/badge/-Wide-yellow?style=flat-square) | Code runs with the job's secrets and token access. |

## References

- GitHub Blog, "Deprecating set-env and add-path commands," https://github.blog/changelog/2020-10-01-github-actions-deprecating-set-env-and-add-path-commands/ [^gh_deprecating]
- GitHub Docs, "Security hardening for GitHub Actions," https://docs.github.com/en/actions/security-guides/security-hardening-for-github-actions [^gh_actions_security]

---

[^gh_deprecating]: GitHub Blog, "Deprecating set-env and add-path commands," https://github.blog/changelog/2020-10-01-github-actions-deprecating-set-env-and-add-path-commands/
[^gh_actions_security]: GitHub Docs, "Security hardening for GitHub Actions," https://docs.github.com/en/actions/security-guides/security-hardening-for-github-actions
