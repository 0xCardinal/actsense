# Cross Repository Access

## Description

When a workflow checks out or clones a repository other than the one that triggered it, any secrets granted to the workflow can cross trust boundaries. Attackers can substitute malicious dependencies, exfiltrate data to forked repos, or silently tamper with code if the external repo is compromised. GitHub recommends using organization allowlists and scoped tokens for cross-repo interactions. [^gh_cross_repo]

## Vulnerable Instance

- `actions/checkout` fetches `owner/other-repo` using the default `GITHUB_TOKEN`.
- Workflow writes artifacts or pushes commits back to that repository.
- There is no allowlist or validation of the requested repository name.

```yaml
name: Cross Repo Sync
on:
  workflow_dispatch:
    inputs:
      target_repo:
        required: true

jobs:
  sync:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Clone target repository
        run: git clone https://github.com/${{ inputs.target_repo }} target
      - name: Push changes
        run: |
          cd target
          git commit --allow-empty -m "sync"
          git push
```

A malicious user can supply `inputs.target_repo` pointing to an attacker-controlled repo, causing secrets or code to be exposed.

## Mitigation Strategies

1. **Allowlist target repositories**  
   Check the requested repo against a regex or `case` statement before cloning.
2. **Use fine-grained PATs**  
   Replace the default `GITHUB_TOKEN` with repo- or org-scoped PATs that limit write operations.
3. **Pin revisions and verify sources**  
   When consuming code, pin to specific SHAs and configure Dependabot/CodeQL scanning.
4. **Log and audit access**  
   Emit telemetry when cross-repo operations run and review logs for unexpected targets.
5. **Prefer GitHub Actions Marketplace**  
   Use prebuilt actions from trusted publishers instead of cloning arbitrary repos.

### Secure Version

- Workflow restricts inputs to a known set of repositories.
- Custom token only grants read access to the target repo.
- Code is pulled read-only; no blind pushes occur. [^gh_cross_repo]

```yaml
name: Approved Cross Repo Sync
on:
  workflow_dispatch:
    inputs:
      target_repo:
        type: choice
        options:
          - my-org/docs
          - my-org/app
        required: true

jobs:
  sync:
    runs-on: ubuntu-latest
    permissions:
      contents: read
    steps:
      - uses: actions/checkout@v4
      - name: Clone approved repo
        env:
          TARGET_REPO: ${{ inputs.target_repo }}
        run: |
          case "$TARGET_REPO" in
            my-org/docs|my-org/app) ;;
            *) echo "Repo not allowlisted"; exit 1 ;;
          esac
          git clone https://github.com/$TARGET_REPO target
      - name: Sync read-only data
        run: rsync -a src/ target/
```

## Impact

| Dimension | Severity | Notes |
| --- | --- | --- |
| Likelihood | ![Medium](https://img.shields.io/badge/-Medium-yellow?style=flat-square) | Cross-repo clones are common in monorepos and mirrored workflows. |
| Risk | ![High](https://img.shields.io/badge/-High-orange?style=flat-square) | Exposes secrets to untrusted repos or allows supply-chain tampering. |
| Blast radius | ![Wide](https://img.shields.io/badge/-Wide-yellow?style=flat-square) | Any repository or service that the workflow token can reach becomes vulnerable. |

## References

- GitHub Docs, “Granting access to workflows,” https://docs.github.com/actions/using-jobs/assigning-permissions-to-jobs [^gh_cross_repo]
- GitHub Docs, “Creating a fine-grained personal access token,” https://docs.github.com/authentication/keeping-your-account-and-data-secure/creating-a-personal-access-token

---

[^gh_cross_repo]: GitHub Docs, “Granting access to workflows,” https://docs.github.com/actions/using-jobs/assigning-permissions-to-jobs