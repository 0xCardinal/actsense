# Untrusted Action Source

## Vulnerability Description


Workflow uses action {action_ref} from owner {owner}, which is not a trusted publisher.
{description}


Third-party actions pose security risks:

- Actions can contain malicious code

- Actions run with your workflows permissions

- Actions can access secrets and sensitive data

- Actions may have security vulnerabilities

- Actions can be compromised by attackers


Security concerns:

- Supply chain attacks through compromised actions

- Unauthorized access to secrets and resources

- Potential for malicious behavior

- Dependency on external code you dont control


## Recommendation


Review and secure third-party action usage:


1. Review the action source code:

- Visit: https://github.com/{action_ref.split(@)[0]}

- Review the code for security issues

- Check commit history and maintainer activity

- Look for security advisories


2. Ensure the action is pinned to a commit SHA:

- Use full 40-character commit SHA, not tags

- Verify the SHA matches a trusted release


3. Consider forking and maintaining your own copy:

- Fork to your organization

- Review and audit the code

- Use your forked version for critical workflows


4. Use actions from trusted publishers when possible:

- GitHub official actions (actions/*)

- Well-known, reputable organizations

- Actions with active maintenance and security practices


5. Regularly review and update actions

6. Monitor for security advisories

