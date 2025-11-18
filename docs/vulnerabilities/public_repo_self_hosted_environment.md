# Public Repo Self Hosted Environment

## Vulnerability Description


Self-hosted runner in public repository has environment access. This creates risks because:

- Environments may have protection rules that can be bypassed

- Environment secrets may be accessible

- Privilege escalation through environment access

- Public repos with self-hosted runners and environments are risky


Security concerns:

- Potential bypass of environment protection rules

- Unauthorized access to environment secrets

- Privilege escalation risks

- Difficult to audit and control access


## Recommendation


Restrict environment access for self-hosted runners in public repositories:


1. Use GitHub-hosted runners:

runs-on: ubuntu-latest  # For public repos


2. If self-hosted runners are necessary:

- Restrict environment access

- Use environment protection rules

- Require approvals for environment access

- Use minimal environment permissions


3. Review environment usage:

- Minimize environment access in public repos

- Use environment protection rules

- Document environment access requirements


4. Consider making repository private if environments are required

