# Overly Permissive

## Vulnerability Description


Workflow has write permissions to GitHub Actions. This is extremely dangerous because:

- The workflow can create, modify, or delete GitHub Actions in your repository

- An attacker could inject malicious actions that run in other workflows

- Actions can be used to persist access or create backdoors

- Compromised actions can affect all workflows that use them


If the workflow is compromised, an attacker could:

- Create malicious actions that steal secrets or credentials

- Modify existing actions to include backdoors

- Use actions to maintain persistent access to your repository

- Escalate privileges by creating actions with higher permissions


Write access to actions should almost never be granted to workflows,
as it creates a significant security risk.


## Recommendation


Remove write permissions to actions immediately:


1. Review if write access to actions is truly necessary:

- Most workflows do NOT need to modify actions

- Action creation/modification should be done through PRs, not workflows


2. Remove write permissions:

permissions:

actions: read  # Or remove entirely if not needed


3. If you must create/modify actions programmatically:

- Use a separate, highly restricted workflow

- Require manual approval

- Use branch protection rules

- Implement additional security controls


4. Consider using GitHub Apps with limited permissions instead

5. Regularly audit all workflows for unnecessary permissions

