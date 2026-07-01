# Cache Poisoning

## Description

GitHub Actions caches (via `actions/cache` or the built-in caching of `setup-*` actions) are shared across workflow runs to speed up builds. When a workflow that runs in a **privileged context** — `pull_request_target` or `workflow_run` — also restores or saves a cache, attacker-controlled code from a fork can write poisoned content into the cache. Later, trusted runs (including those on the default branch) restore that cache and execute or trust the attacker's artifacts. [^gh_actions_security] Because the cache is keyed and persisted outside the run that created it, this turns a single malicious fork pull request into a foothold that affects subsequent privileged builds. The triggers involved are discussed further in [Dangerous Event](/vulnerabilities/dangerous_event/) and [Insecure Pull Request Target](/vulnerabilities/insecure_pull_request_target/).

## Vulnerable Instance

- The workflow is triggered by `pull_request_target` or `workflow_run`.
- A job in that workflow restores or saves a cache, directly or through a `setup-*` action's `cache` option.

```yaml
name: PR Build
on:
  pull_request_target:
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          ref: ${{ github.event.pull_request.head.sha }}   # untrusted fork code
      - uses: actions/cache@v4                              # poisoned by the fork
        with:
          path: ~/.cache
          key: build-${{ hashFiles('**/lockfile') }}
      - run: make build
```

## Mitigation Strategies

1. **Do not cache in privileged, fork-triggered workflows**
   Remove caching steps from workflows triggered by `pull_request_target` or `workflow_run`, or move the cached work into a `pull_request` workflow that runs without secrets and a read-only token.

2. **Separate untrusted build from privileged actions**
   Use the two-workflow pattern: build and test untrusted code in a `pull_request` workflow (no secrets, no cache writes that privileged runs trust), and perform privileged steps only on trusted refs.

3. **Scope and segregate cache keys by trust boundary**
   Ensure caches written while handling untrusted code cannot collide with keys consumed by trusted runs.

4. **Invalidate caches after suspected compromise**
   Treat caches as tampered if an untrusted run may have written to them, and rotate keys.

### Secure Version

```diff
-name: PR Build
+name: PR Build (untrusted)
 on:
-  pull_request_target:
+  pull_request:
 jobs:
   build:
     runs-on: ubuntu-latest
+    permissions:
+      contents: read
     steps:
       - uses: actions/checkout@v4
-        with:
-          ref: ${{ github.event.pull_request.head.sha }}
       - uses: actions/cache@v4
         with:
           path: ~/.cache
           key: build-${{ hashFiles('**/lockfile') }}
       - run: make build
```

## Impact

| Dimension | Severity | Notes |
| --- | --- | --- |
| Likelihood | ![Medium](https://img.shields.io/badge/-Medium-yellow?style=flat-square) | Requires a privileged trigger combined with caching, but both are common in CI build pipelines. |
| Risk | ![High](https://img.shields.io/badge/-High-orange?style=flat-square) | Poisoned caches are restored by later trusted runs, leading to code execution or tampered build outputs with access to secrets. |
| Blast radius | ![Wide](https://img.shields.io/badge/-Wide-yellow?style=flat-square) | A single malicious fork pull request can affect subsequent privileged builds and anything they produce or deploy. |

## References

- GitHub Docs, "Security hardening for GitHub Actions," https://docs.github.com/en/actions/security-guides/security-hardening-for-github-actions [^gh_actions_security]
- GitHub Docs, "Caching dependencies to speed up workflows," https://docs.github.com/en/actions/using-workflows/caching-dependencies-to-speed-up-workflows [^gh_cache]

---

[^gh_actions_security]: GitHub Docs, "Security hardening for GitHub Actions," https://docs.github.com/en/actions/security-guides/security-hardening-for-github-actions
[^gh_cache]: GitHub Docs, "Caching dependencies to speed up workflows," https://docs.github.com/en/actions/using-workflows/caching-dependencies-to-speed-up-workflows
