# Potential Hardcoded Cloud Credentials

## Description

Workflows that contain hardcoded cloud credentials (AWS keys, Azure secrets, GCP service account keys) in run commands expose those credentials to anyone with read access to the repository. Credentials are visible in workflow files, stored in git history even if removed later, and may be exposed in logs, artifacts, and workflow runs. Exposed credentials can be used by attackers to access cloud resources, modify infrastructure, exfiltrate data, or incur significant costs through resource abuse. [^gh_secrets]

## Vulnerable Instance

- Workflow contains AWS access keys, Azure client secrets, or GCP service account keys directly in run commands.
- Credentials are visible in the workflow YAML file and git history.
- Credentials may appear in workflow logs or artifacts.

```yaml
name: Deploy with Hardcoded Creds
on: [push]
jobs:
  deploy:
    runs-on: ubuntu-latest
    steps:
      - run: |
          export AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE
          export AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
          aws s3 cp dist/ s3://my-bucket/
```

## Mitigation Strategies

1. **Rotate exposed credentials immediately**  
   Revoke the exposed credentials in your cloud provider, create new credentials, and review access logs for unauthorized usage.

2. **Remove hardcoded credentials**  
   Delete any hardcoded credential values from workflow files. If already committed, remove from git history using `git filter-branch` or BFG Repo-Cleaner.

3. **Use GitHub Secrets**  
   Add credentials to Repository Settings → Secrets and reference them in workflows as `${{ secrets.CREDENTIAL_NAME }}`. Secrets are encrypted and never exposed in logs.

4. **Migrate to OIDC**  
   Configure OpenID Connect (OIDC) with your cloud provider to use temporary credentials instead of long-term ones. This eliminates the need to store credentials at all.

5. **Enable secret scanning**  
   Set up GitHub's secret scanning alerts to detect accidentally committed credentials. Configure push protection to block commits containing known credential patterns.

6. **Review all workflows**  
   Audit all workflow files for other hardcoded credentials. Use automated tools to scan repositories for credential patterns.

### Secure Version

```diff
 name: Deploy with OIDC
 on: [push]
+permissions:
+  id-token: write
+  contents: read
 jobs:
   deploy:
     runs-on: ubuntu-latest
     steps:
+      - uses: actions/checkout@v4
+      - name: Configure AWS credentials
+        uses: aws-actions/configure-aws-credentials@v4
+        with:
+          role-to-assume: arn:aws:iam::ACCOUNT:role/GitHubActionsRole
+          aws-region: us-east-1
       - run: |
-          export AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE
-          export AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
           aws s3 cp dist/ s3://my-bucket/
```

## Impact

| Dimension | Severity | Notes |
| --- | --- | --- |
| Likelihood | ![Medium](https://img.shields.io/badge/-Medium-yellow?style=flat-square) | Hardcoded credentials are less common but still occur, especially in legacy workflows or during rapid development. |
| Risk | ![Critical](https://img.shields.io/badge/-Critical-red?style=flat-square) | Exposed credentials provide direct access to cloud resources, enabling data exfiltration, infrastructure modification, or financial abuse. |
| Blast radius | ![Wide](https://img.shields.io/badge/-Wide-yellow?style=flat-square) | Compromised credentials can affect all resources the credentials can access, potentially including production systems, databases, and storage. |

## References

- GitHub Docs, "Encrypted secrets," https://docs.github.com/en/actions/security-guides/encrypted-secrets [^gh_secrets]
- GitHub Docs, "Security hardening for GitHub Actions," https://docs.github.com/en/actions/security-guides/security-hardening-for-github-actions

---

[^gh_secrets]: GitHub Docs, "Encrypted secrets," https://docs.github.com/en/actions/security-guides/encrypted-secrets
