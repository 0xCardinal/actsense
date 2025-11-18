# Potential Hardcoded Cloud Credentials

## Vulnerability Description


Potential hardcoded cloud credentials detected in run command for job {job_name}.
This is extremely dangerous:

- Credentials are visible in the workflow file to anyone with read access

- Credentials are stored in git history even if removed later

- Credentials may be exposed in logs, artifacts, and workflow runs

- Credentials can be accidentally committed to public repositories

- Credentials cannot be rotated without modifying the workflow file


Exposed cloud credentials can be used by attackers to:

- Access your cloud resources and infrastructure

- Modify or delete your cloud resources

- Exfiltrate sensitive data from cloud services

- Perform unauthorized actions on your behalf

- Incur significant costs through resource abuse


## Recommendation


Immediately remove hardcoded credentials and use GitHub Secrets or OIDC:


1. Rotate the exposed credentials immediately:

- Revoke the exposed credentials in your cloud provider

- Create new credentials

- Review access logs for unauthorized usage


2. Remove hardcoded credentials from the workflow:

- Delete any hardcoded credential values

- Remove from git history if needed


3. Use GitHub Secrets:

- Add credentials to Repository Settings → Secrets

- Reference in workflow: ${{{{ secrets.CREDENTIAL_NAME }}}}


4. Better: Use OIDC for cloud authentication:

- Configure OIDC with your cloud provider

- Use temporary credentials instead of long-term ones

- See cloud provider documentation for OIDC setup


5. Review all workflow files for other hardcoded credentials

6. Set up secret scanning alerts

