# Secrets In Matrix

## Vulnerability Description


Secrets are used in the matrix strategy for job {job_name}. This is extremely dangerous because:

- Secrets are visible to ALL matrix job combinations

- Each matrix job can access and potentially log the secrets

- Secrets are exposed in the workflow YAML visible to all contributors

- Secrets may be logged or exposed in error messages

- Attackers with access to any matrix job can see all secrets


Security risks:

- Secrets can be exfiltrated by any matrix job

- Secrets are visible in workflow logs and artifacts

- Secrets may be exposed to unauthorized users

- This violates the principle of least privilege


## Recommendation


Remove secrets from matrix definitions immediately:


1. Move secrets to job-level or step-level:

jobs:

build:

strategy:

matrix:

os: [ubuntu, windows]  # No secrets here

steps:

- name: Use secret

env:

SECRET: ${{{{ secrets.API_KEY }}}}  # Secret at step level


2. Or use environment secrets with job-level access:

jobs:

build:

environment: production

strategy:

matrix:

os: [ubuntu, windows]

steps:

- run: echo ${{{{ secrets.ENV_SECRET }}}}


3. Never use secrets in matrix definitions

4. Review all matrix strategies for secret usage

5. Rotate any exposed secrets immediately

