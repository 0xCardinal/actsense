# Self Hosted Runner Secrets In Run

## Vulnerability Description


Secrets are directly used in run commands on self-hosted runner. This is dangerous because:

- Secrets may be visible in process lists (ps, top, etc.)

- Secrets may be logged by shell or command execution

- Secrets can be exposed in error messages or stack traces

- Process arguments containing secrets are visible to other processes

- Secrets may be stored in shell history


Security risks:

- Secret exposure in process lists

- Secret leakage through logs

- Unauthorized access to secrets

- Potential for secret exfiltration


## Recommendation


Use environment variables instead of direct secret interpolation:


1. Use environment variables for secrets:

- name: Run command

env:

SECRET: ${{{{ secrets.MY_SECRET }}}}

run: |

echo \Using secret\  # Secret not in command line

# Use $SECRET in commands


2. Avoid direct secret interpolation:

# Bad: run: echo ${{{{ secrets.MY_SECRET }}}}

# Good: Use env variable


3. Use action inputs when possible:

- Pass secrets as action inputs

- Actions handle secrets more securely

- Secrets are masked in logs


4. Review all secret usage:

- Check for secrets in run commands

- Move secrets to environment variables

- Use secure secret handling practices

