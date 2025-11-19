# Cross Repository Access

## Vulnerability Description


Workflow accesses a different repository {repo} than the current repository.
This may have security implications:

- Cross-repository access may require additional permissions

- Accessing untrusted repositories can introduce security risks

- Secrets may be exposed to external repositories

- Code from external repositories may be executed


Security concerns:

- Unauthorized access to other repositories

- Potential for supply chain attacks

- Secrets exposure to external code

- Difficult to audit and control access


## Recommendation


Ensure cross-repository access is intentional and properly secured:


1. Verify the repository is trusted:

- Only access repositories you own or trust

- Review repository security and maintenance status

- Check for known vulnerabilities


2. Use minimal permissions:

- Only grant read access when possible

- Use specific repository permissions

- Avoid write access to external repositories


3. Validate repository access:

- Use allowlists for permitted repositories

- Validate repository names before access

- Log all cross-repository access


4. Consider alternatives:

- Use GitHub Actions from trusted sources

- Fork and maintain your own copy

- Use pinned versions of external code


5. Review all cross-repository access in workflows

