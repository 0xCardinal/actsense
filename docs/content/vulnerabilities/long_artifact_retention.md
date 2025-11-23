# Long Artifact Retention

## Description

GitHub Actions artifacts default to a 90-day retention period, but workflows can override it up to 400 days. Keeping build outputs (which may include logs, secrets, or binaries) for longer than needed expands the window for data leakage and can violate data-retention requirements. GitHub recommends setting the shortest retention compatible with business needs and deleting sensitive artifacts promptly. [^gh_artifacts]

## Vulnerable Instance

- Workflow stores artifacts for a full year, even though they contain build logs with secrets.

```yaml
jobs:
  build:
    steps:
      - run: npm run build
      - uses: actions/upload-artifact@v4
        with:
          name: build-logs
          path: logs/**
          retention-days: 365
```

## Mitigation Strategies

1. **Set minimal retention**  
   Choose the fewest days needed for troubleshooting (e.g., 7 or 30).
2. **Segment artifacts**  
   Separate sensitive artifacts (logs, dumps) from binaries and apply shorter retention.
3. **Use external archival if needed**  
   If compliance demands longer retention, move artifacts to encrypted storage outside Actions.
4. **Review contents**  
   Ensure artifacts don’t include credentials or personal data before uploading.
5. **Automate cleanup**  
   Periodically audit artifact settings and remove outdated uploads. [^gh_artifacts]

### Secure Version

```diff
 jobs:
   build:
     steps:
       - run: npm run build
       - uses: actions/upload-artifact@v4
         with:
           name: build-logs
           path: logs/**
-          retention-days: 365
+          retention-days: 30
```

## Impact

| Dimension | Severity | Notes |
| --- | --- | --- |
| Likelihood | ![Medium](https://img.shields.io/badge/-Medium-yellow?style=flat-square) | Many teams leave retention at high values for convenience. |
| Risk | ![Low](https://img.shields.io/badge/-Low-green?style=flat-square) | Longer retention increases exposure of sensitive artifacts. |
| Blast radius | ![Medium](https://img.shields.io/badge/-Medium-yellow?style=flat-square) | Any secrets or proprietary code in artifacts remain accessible for months. |

## References

- GitHub Docs, “Storing workflow data as artifacts,” https://docs.github.com/actions/using-workflows/storing-workflow-data-as-artifacts [^gh_artifacts]
- GitHub Docs, “Managing artifacts,” https://docs.github.com/actions/managing-workflow-runs/managing-artifacts

---

[^gh_artifacts]: GitHub Docs, “Storing workflow data as artifacts,” https://docs.github.com/actions/using-workflows/storing-workflow-data-as-artifacts