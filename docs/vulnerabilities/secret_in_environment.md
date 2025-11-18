# Secret In Environment

## Vulnerability Description


Secret is directly exposed in environment variable {env_key}. This is risky because:

- Environment variables may be logged by actions or tools

- Environment variables are visible in workflow logs

- Some tools may expose environment variables in error messages

- Environment variables can be accessed by child processes


Security concerns:

- Secret exposure in logs

- Secret visibility to actions and tools

- Potential for secret leakage

- Difficult to control secret access


## Recommendation


Use secure secret handling instead of environment variables:


1. Use action input parameters:

- name: Action Step

uses: action@v1

with:

secret: ${{{{ secrets.SECRET_NAME }}}}  # Pass as input


2. Use GitHub Actions secrets directly:

- Access secrets via ${{{{ secrets.SECRET_NAME }}}}

- Secrets are automatically masked in logs

- Use secrets only when necessary


3. If environment variables are necessary:

- Use minimal secrets

- Review action documentation for secret handling

- Monitor logs for secret exposure

- Use secrets that can be rotated easily


4. Review all environment variable usage

5. Consider using GitHub Apps with limited scopes

