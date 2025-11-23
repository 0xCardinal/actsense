# Checkout Full History

## Description

Setting `actions/checkout` to `fetch-depth: 0` clones the entire repository history into the runner. That full history can expose secrets that were removed later, sensitive files that should remain internal, or massive diffs an attacker could mine. It also slows CI and increases the amount of data a compromised workflow can exfiltrate. [^checkout_docs]

## Vulnerable Instance

- `on: pull_request` workflow clones the entire repo for every run.
- Secrets or sensitive files exist in historical commits that would otherwise stay hidden.
- Runner writes logs/artifacts that might include those historical files.

```yaml
name: Full History Build
on: [pull_request]
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0   # Fetch the entire repository history
      - run: npm test
```

## Mitigation Strategies

1. **Use shallow clones by default**  
   Set `fetch-depth: 1` so only the latest commit is pulled, limiting exposure and speeding up builds.
2. **Fetch history only when needed**  
   If a job needs older commits (e.g., for `git describe`), run a targeted `git fetch --depth=<n>` step rather than disabling depth globally.
3. **Document exceptions**  
   When full history is mandatory, document the justification in the workflow and ensure secrets have been scrubbed from the repo.
4. **Limit artifact contents**  
   Combine shallow clones with scoped artifact uploads so historic files never leave the runner.
5. **Monitor for depth overrides**  
   Periodically scan workflows for `fetch-depth: 0` and review whether the setting is still required.

### Secure Version

```diff
 name: Shallow Checkout Build
 on: [pull_request]
 jobs:
   build:
     runs-on: ubuntu-latest
     steps:
       - uses: actions/checkout@v4
         with:
-          fetch-depth: 0   # Fetch the entire repository history
+          fetch-depth: 1   # Only the latest commit
       - run: npm test
```

## Impact

| Dimension | Severity | Notes |
| --- | --- | --- |
| Likelihood | ![Medium](https://img.shields.io/badge/-Medium-yellow?style=flat-square) | Many workflows accept the default depth and never revisit it, especially in legacy repos. |
| Risk | ![Medium](https://img.shields.io/badge/-High-orange?style=flat-square) | Historical secrets or sensitive files become accessible to any job output or attacker with runner access. |
| Blast radius | ![Wide](https://img.shields.io/badge/-Wide-yellow?style=flat-square) | Leakage spans every historical commit—including past environments, credentials, and intellectual property. |

## References

- GitHub Docs, “actions/checkout – inputs,” https://docs.github.com/actions/checkout#usage [^checkout_docs]
- GitHub Docs, “Persisting workflow data using artifacts,” https://docs.github.com/actions/using-workflows/storing-workflow-data-as-artifacts

[^checkout_docs]: GitHub Docs, “actions/checkout – inputs,” https://docs.github.com/actions/checkout#usage