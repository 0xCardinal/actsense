# Secrets Access Untrusted

## Vulnerability Description


Secrets are passed to untrusted action {uses}. This is dangerous because:

- Untrusted actions may be malicious or compromised

- Secrets can be exfiltrated by malicious actions

- Actions have access to all secrets passed to them

- Malicious actions can log or expose secrets

- Supply chain attacks can compromise actions


Security risks:

- Secret exfiltration by malicious actions

- Supply chain attacks through compromised actions

- Unauthorized access to secrets

- Persistent access through stolen secrets


## Recommendation


Only pass secrets to trusted, verified actions:


1. Verify action trustworthiness:

- Review action source code

- Check action publisher reputation

- Verify action is from trusted publisher

- Review action security history


2. Use trusted actions when possible:

- Prefer actions from trusted publishers (actions/, github/, etc.)

- Use official actions from well-known organizations

- Review third-party actions before use


3. Minimize secret exposure:

- Only pass secrets to actions that absolutely need them

- Use minimal permissions for actions

- Consider using GitHub Apps with limited scopes


4. If you must use untrusted actions:

- Review action source code thoroughly

- Pin to specific commit SHA

- Monitor action for updates

- Consider forking and maintaining your own copy


5. Review all actions that receive secrets

6. Use secrets only when absolutely necessary

