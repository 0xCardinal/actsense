# Environment With Secrets

## Vulnerability Description


Job {job_name} uses environment {env_name} with secrets.
While environments can provide additional security controls, they should be properly configured:

- Environment protection rules should be enabled

- Required reviewers should be configured

- Wait timer should be set if needed

- Deployment branches should be restricted


Security concerns:

- Environments without protection rules may allow unauthorized deployments

- Secrets may be accessible without proper approval

- Deployment controls may be bypassed


## Recommendation


Configure environment protection rules:


1. Enable environment protection:

- Repository Settings → Environments → {env_name}

- Enable Required reviewers

- Add required reviewers


2. Configure deployment branches:

- Restrict to specific branches (e.g., main, production)

- Prevent deployments from feature branches


3. Set wait timer if needed:

- Add delay before deployment

- Allows time to cancel if unauthorized


4. Limit access to environments:

- Restrict who can trigger deployments

- Use branch protection rules


5. Review environment secrets:

- Ensure secrets are properly scoped

- Rotate secrets regularly

- Use minimal permissions

