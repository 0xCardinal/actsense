# Potential Hardcoded Secret

## Description

Workflows containing hardcoded secrets (passwords, API keys, tokens, database credentials) expose those credentials to anyone with read access to the repository. Secrets are visible in workflow files, stored in git history even if removed later, and may be exposed in logs, artifacts, and workflow runs. Exposed credentials can be used by attackers to access cloud resources, databases, or services; modify or delete infrastructure; exfiltrate sensitive data; or perform unauthorized actions. [^gh_secrets]

## Vulnerable Instance

- Workflow contains a hardcoded password, API key, or token directly in the YAML file.
- Secret is visible in the workflow file and stored in git history.
- Secret may appear in workflow logs or artifacts.

```yaml
name: Deploy with Hardcoded Secret
on: [push]
jobs:
  deploy:
    runs-on: ubuntu-latest
    steps:
      - name: Connect to database
        run: |
          mysql -u admin -p'MyHardcodedPassword123!' -h db.example.com
```

## Mitigation Strategies

1. **Rotate exposed credentials immediately**  
   Change the password/token/key in the target system, invalidate any exposed API keys or tokens, and review access logs for unauthorized usage.

2. **Remove hardcoded secrets**  
   Delete hardcoded values from workflow files. If already committed, remove from git history using `git filter-branch` or BFG Repo-Cleaner.

3. **Use GitHub Secrets**  
   Add secrets to Repository Settings → Secrets and variables → Actions. Reference them in workflows as `${{ secrets.SECRET_NAME }}`. Secrets are encrypted and never exposed in logs.

4. **Use environment secrets for environment-specific values**  
   For environment-specific secrets, use Repository Settings → Environments → [Environment Name] → Secrets and reference as `${{ secrets.ENV_SECRET }}`.

5. **Enable secret scanning**  
   Set up GitHub's secret scanning alerts to detect accidentally committed credentials. Configure push protection to block commits containing known secret patterns.

6. **Review all workflows**  
   Audit all workflow files for other hardcoded secrets. Use automated tools to scan repositories for credential patterns.

### Secure Version

```yaml
name: Deploy with Secrets
on: [push]
jobs:
  deploy:
    runs-on: ubuntu-latest
    steps:
      - name: Connect to database
        run: |
          mysql -u admin -p"${{ secrets.DB_PASSWORD }}" -h db.example.com
```

## Impact

| Dimension | Severity | Notes |
| --- | --- | --- |
| Likelihood | ![Medium](https://img.shields.io/badge/-Medium-yellow?style=flat-square) | Hardcoded secrets are less common but still occur, especially during rapid development or in legacy workflows. |
| Risk | ![Critical](https://img.shields.io/badge/-Critical-red?style=flat-square) | Exposed credentials provide direct access to systems, enabling data exfiltration, infrastructure modification, or service compromise. |
| Blast radius | ![Wide](https://img.shields.io/badge/-Wide-yellow?style=flat-square) | Compromised credentials can affect all systems the credentials can access, potentially including production databases, APIs, and services. |

## References

- GitHub Docs, "Encrypted secrets," https://docs.github.com/en/actions/security-guides/encrypted-secrets [^gh_secrets]

---

[^gh_secrets]: GitHub Docs, "Encrypted secrets," https://docs.github.com/en/actions/security-guides/encrypted-secrets
