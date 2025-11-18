# Self Hosted Runner Pr Exposure

## Vulnerability Description


Self-hosted runner in job {job_name} is exposed to pull requests in a public repository. This is CRITICAL because:

- Attackers from forks can create PRs that trigger workflows on your self-hosted runners

- Malicious code from forks can execute on your infrastructure

- Attackers can access your network, secrets, and internal resources

- This is one of the most dangerous self-hosted runner configurations


Attack scenario:

1. Attacker forks your public repository

2. Attacker creates a PR with malicious workflow code

3. Workflow triggers on your self-hosted runner

4. Malicious code executes on your infrastructure

5. Attacker gains access to your network and secrets


## Recommendation


NEVER expose self-hosted runners to PRs in public repositories:


1. Use GitHub-hosted runners for public repositories:

runs-on: ubuntu-latest  # For public repos


2. If you must use self-hosted runners:

- Restrict to trusted events only (push, workflow_dispatch)

- Never allow pull_request or pull_request_target triggers

- Use runner groups with restricted access

- Implement network isolation


3. For PR workflows in public repos:

- Always use GitHub-hosted runners

- Never use self-hosted runners

- Consider making the repository private if self-hosted runners are required

