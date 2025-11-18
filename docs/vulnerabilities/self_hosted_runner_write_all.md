# Self Hosted Runner Write All

## Vulnerability Description


Self-hosted runner has write-all permissions. This is CRITICAL because:

- Write-all grants excessive access to repository resources

- If compromised, attackers have full write access

- Attackers can modify code, create backdoors, or exfiltrate data

- Self-hosted runners with write-all are extremely dangerous


Security risks:

- Full repository access if runner is compromised

- Ability to modify code and create backdoors

- Potential for persistent access

- Violation of least privilege principle


## Recommendation


Use minimal required permissions instead of write-all:


1. Use specific, scoped permissions:

permissions:

contents: read  # Only whats needed

pull-requests: read


2. Follow principle of least privilege:

- Grant only the minimum permissions required

- Review what the workflow actually needs

- Avoid write-all at all costs


3. Use job-level permissions:

- Scope permissions to specific jobs

- Use different permissions for different jobs

- Minimize permissions on self-hosted runners


4. Regularly audit permissions:

- Review all workflow permissions

- Remove unnecessary permissions

- Document why permissions are needed

