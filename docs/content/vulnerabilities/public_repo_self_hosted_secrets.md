# Public Repo Self Hosted Secrets

## Vulnerability Description


Self-hosted runner in public repository has access to secrets. This is dangerous because:

- Public repositories are accessible to anyone

- Workflow code is visible to all users

- Secrets may be exposed through workflow execution

- Attackers can analyze workflow code for vulnerabilities

- Self-hosted runners with secrets in public repos are high risk


Security risks:

- Secret exposure through workflow execution

- Potential for secret exfiltration

- Unauthorized access to secrets

- Compromise of self-hosted runner infrastructure


## Recommendation


Use GitHub-hosted runners for public repositories with secrets:


1. Use GitHub-hosted runners:

runs-on: ubuntu-latest  # For public repos


2. If self-hosted runners are necessary:

- Make repository private

- Or use minimal secrets with restricted access

- Implement additional security controls

- Use environment secrets with protection rules


3. Review secret usage:

- Minimize secrets in public repositories

- Use environment secrets with protection

- Rotate secrets regularly


4. Consider repository visibility:

- Public repos should use GitHub-hosted runners

- Self-hosted runners are better suited for private repos

