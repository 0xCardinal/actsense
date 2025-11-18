# Potential Hardcoded Secret

## Vulnerability Description


A potential hardcoded secret was detected at {path}. Hardcoded secrets in workflow files are extremely dangerous:

- Secrets are visible to anyone with read access to the repository

- Secrets are stored in git history even if removed later

- Secrets can be exposed in logs, artifacts, and workflow runs

- Secrets can be accidentally committed to public repositories

- Secrets cannot be rotated without modifying the workflow file


Exposed credentials can be used by attackers to:

- Access your cloud resources, databases, or services

- Modify or delete your infrastructure

- Exfiltrate sensitive data

- Perform unauthorized actions on your behal


## Recommendation


Immediately remove the hardcoded secret and use GitHub Secrets:


1. Rotate the exposed credential immediately:

- Change the password/token/key in the target system

- Invalidate any exposed API keys or tokens

- Review access logs for unauthorized usage


2. Remove the hardcoded secret from the workflow file:

- Delete the hardcoded value at {path}

- Remove it from git history if needed (consider using git filter-branch or BFG Repo-Cleaner)


3. Add the secret to GitHub Secrets:

- Go to: Repository Settings → Secrets and variables → Actions

- Click New repository secret

- Add the secret with an appropriate name (e.g., API_KEY, DATABASE_PASSWORD)


4. Update the workflow to use the secret:

Change: password: \hardcoded-value\

To: password: ${{{{ secrets.API_KEY }}}}


5. For environment-specific secrets, use environment secrets:

- Repository Settings → Environments → [Environment Name] → Secrets

- Add environment-specific secrets

- Reference in workflow: ${{{{ secrets.ENV_SECRET }}}}


6. Review all workflow files for other hardcoded secrets

7. Set up secret scanning alerts to prevent future exposures

