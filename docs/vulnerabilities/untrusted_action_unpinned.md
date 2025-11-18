# Untrusted Action Unpinned

## Vulnerability Description


Untrusted third-party action {action_ref} from owner {owner} is not pinned to a specific version.
This creates critical security risks:

- The action can be updated by the maintainer at any time

- Malicious code can be introduced without your knowledge

- The action runs with your workflows permissions

- Attackers who compromise the action repository can inject malicious code

- Your workflow will automatically use the compromised version


Security risks:

- Supply chain attacks through compromised actions

- Secret exfiltration by malicious action code

- Unauthorized access to your repository and resources

- Data breaches and system compromise


## Recommendation


Pin the action to a specific commit SHA and review the source code:


1. Review the action source code:

- Visit: https://github.com/{action_ref.split(@)[0]}

- Review the code for security issues

- Check for recent security advisories


2. Pin to a specific commit SHA:

- Find a specific release or commit

- Copy the full 40-character commit SHA

- Update: {action_ref.split(@)[0]}@<full-40-char-sha>


3. Consider forking and maintaining your own copy:

- Fork the action to your organization

- Review and audit the code

- Use your forked version: your-org/{action_ref.split(@)[0].split(/, 1)[1]}@<sha>


4. Regularly review and update pinned actions

5. Monitor for security advisories about the action

