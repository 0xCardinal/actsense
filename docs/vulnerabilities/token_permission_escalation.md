# Token Permission Escalation

## Vulnerability Description


Detected pattern {description} that could be used to escalate token permissions or extract token data.
This is dangerous because:

- Tokens can be extracted and used outside the workflow context

- Token permissions can be escalated through manipulation

- Extracted tokens can be used to access resources beyond workflow scope

- Tokens may be logged or exposed in artifacts

- Attackers can use extracted tokens to maintain persistent access


Security risks:

- Token extraction and exfiltration

- Permission escalation attacks

- Unauthorized access to repository resources

- Persistent access even after workflow completion


## Recommendation


Avoid manipulating tokens directly:


1. Use built-in GitHub Actions permissions instead:

permissions:

contents: read  # Use permissions, not token manipulation


2. Dont extract or encode tokens:

- Avoid base64 encoding of tokens

- Dont echo tokens to logs or files

- Dont pass tokens in command-line arguments


3. Use GitHub Actions secrets for sensitive data:

- Store tokens in GitHub Secrets

- Access via ${{{{ secrets.TOKEN_NAME }}}}

- Secrets are automatically masked in logs


4. If you need different permissions:

- Use job-level permissions

- Create separate workflows with appropriate permissions

- Use GitHub Apps with limited scopes


5. Review all token usage in workflows

6. Never log or expose tokens in any form

