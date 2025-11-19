# Environment Bypass Risk

## Vulnerability Description


Pull request triggered workflow contains pattern {description} that may bypass environment protections.
This is dangerous because:

- PRs from forks can trigger workflows that bypass environment protection rules

- Environment protections may be circumvented through workflow chaining

- Attackers can trigger workflows with elevated permissions

- Protected environments may be accessed without proper approvals


Security risks:

- Bypass of environment protection rules

- Unauthorized access to protected environments

- Workflow chaining attacks

- Privilege escalation through workflow triggers


## Recommendation


Secure workflow triggers to prevent environment bypass:


1. Restrict workflow triggers:

- Dont allow PRs to trigger workflows that can bypass environments

- Use branch protection rules

- Require approvals for sensitive workflows


2. Validate workflow triggers:

- Check the source of workflow triggers

- Validate triggering workflow names

- Use allowlists for permitted workflows


3. Use environment protection:

- Enable environment protection rules

- Require reviewers for protected environments

- Use deployment branches for protected environments


4. Review all workflow triggers in PR workflows

5. Consider using pull_request instead of pull_request_target

