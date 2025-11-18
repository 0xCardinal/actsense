# Long Term Aws Credentials

## Vulnerability Description


Job {job_name} uses long-term AWS credentials (AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY) instead of OIDC.
This creates security risks:

- Long-term credentials dont expire automatically

- Credentials are harder to rotate and manage

- Credentials may be stored in secrets for extended periods

- If compromised, credentials remain valid until manually rotated

- Credentials may have excessive permissions


Security concerns:

- Compromised credentials can be used indefinitely

- Credentials may have broader permissions than needed

- Difficult to audit and track credential usage

- No automatic expiration or rotation


## Recommendation


Migrate to GitHub OIDC for AWS authentication:


1. Configure OIDC in AWS:

- Create an OIDC identity provider in AWS IAM

- Configure trust relationship with GitHub

- Create IAM role with required permissions


2. Update the workflow to use OIDC:

permissions:

id-token: write  # Required for OIDC

contents: read

steps:

- name: Configure AWS credentials

uses: aws-actions/configure-aws-credentials@v4

with:

role-to-assume: arn:aws:iam::ACCOUNT:role/GitHubActionsRole

aws-region: us-east-1


3. Remove long-term credentials from secrets

4. Test the OIDC authentication

5. See: https://docs.github.com/en/actions/deployment/security-hardening-your-deployments/configuring-openid-connect-in-amazon-web-services

