# Large Matrix

## Description

Matrix jobs that explode into dozens or hundreds of combinations slow feedback loops, burn runner minutes, and make it easy to miss failures (logs become overwhelming). GitHub recommends pruning matrices with `include`/`exclude`, splitting into targeted workflows, and using `max-parallel` to keep concurrency manageable. [^gh_matrix]

## Vulnerable Instance

- Single job runs every OS and Node version combination (3×5=15 jobs) for each push, even though only a subset is needed.

```yaml
jobs:
  test:
    runs-on: ${{ matrix.os }}
    strategy:
      matrix:
        os: [ubuntu-latest, windows-latest, macos-latest]
        node: [14, 16, 18, 20, 22]
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-node@v4
        with:
          node-version: ${{ matrix.node }}
      - run: npm test
```

## Mitigation Strategies

1. **Trim combinations**  
   Limit to the OS/runtime pairs your customers actually use; rely on scheduled runs for full coverage.
2. **Use `include`/`exclude`**  
   Remove redundant combos (e.g., macOS + older Node) to cut matrix size.
3. **Split workflows**  
   Separate smoke tests (fast) from exhaustive compatibility tests (scheduled).
4. **Set `max-parallel`**  
   Prevent runaway concurrency that starves other workflows.
5. **Monitor duration/costs**  
   Track metrics via GitHub Actions usage reports and adjust accordingly. [^gh_matrix]

### Secure Version

- Default workflow tests a minimal set per push.
- Scheduled workflow runs full compatibility matrix weekly.

```yaml
jobs:
  test:
    runs-on: ${{ matrix.os }}
    strategy:
      max-parallel: 3
      matrix:
        os: [ubuntu-latest, windows-latest]
        node: [18, 20]
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-node@v4
        with:
          node-version: ${{ matrix.node }}
      - run: npm test
```

## Impact

| Dimension | Severity | Notes |
| --- | --- | --- |
| Likelihood | ![High](https://img.shields.io/badge/-High-orange?style=flat-square) | Teams often over-provision matrices to match every environment. |
| Risk | ![Medium](https://img.shields.io/badge/-Medium-yellow?style=flat-square) | Operational fatigue increases the chance of missing regressions. |
| Blast radius | ![Medium](https://img.shields.io/badge/-Medium-yellow?style=flat-square) | Repository-wide CI slows down and may hit concurrency limits. |

## References

- GitHub Docs, “Using a matrix strategy,” https://docs.github.com/actions/using-jobs/using-a-matrix-for-your-jobs [^gh_matrix]
- GitHub Docs, “Managing GitHub Actions usage,” https://docs.github.com/billing/managing-billing-for-github-actions/about-billing-for-github-actions

---

[^gh_matrix]: GitHub Docs, “Using a matrix strategy,” https://docs.github.com/actions/using-jobs/using-a-matrix-for-your-jobs