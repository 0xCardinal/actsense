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

## How actsense detects this

Reported as **low** whenever `actions/checkout` sets `fetch-depth: 0`. Full history is often legitimately needed (changelogs, `git describe`, release tooling); the finding is a prompt to confirm it is.

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
| Likelihood | ![Low](https://img.shields.io/badge/-Low-green?style=flat-square) | Only matters if sensitive data was ever committed, or if a compromised step can read the workspace. |
| Risk | ![Medium](https://img.shields.io/badge/-Medium-yellow?style=flat-square) | History of a public repository is already public; for private repositories it widens what a compromised step or leaked artifact exposes. |
| Blast radius | ![Medium](https://img.shields.io/badge/-Medium-yellow?style=flat-square) | Limited to what exists in the repository's history. |

## References

- GitHub Docs, “actions/checkout – inputs,” https://docs.github.com/actions/checkout#usage [^checkout_docs]
- GitHub Docs, “Persisting workflow data using artifacts,” https://docs.github.com/actions/using-workflows/storing-workflow-data-as-artifacts

[^checkout_docs]: GitHub Docs, “actions/checkout – inputs,” https://docs.github.com/actions/checkout#usage