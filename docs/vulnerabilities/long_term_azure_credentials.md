# Long Term Azure Credentials

## Vulnerability Description


Job {job_name} uses long-term Azure credentials (AZURE_CLIENT_ID, AZURE_CLIENT_SECRET, AZURE_TENANT_ID) instead of OIDC.
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


Migrate to GitHub OIDC for Azure authentication:


1. Configure OIDC in Azure:

- Create an App Registration in Azure AD

- Configure federated credential with GitHub

- Create a service principal with required permissions


2. Update the workflow to use OIDC:

permissions:

id-token: write  # Required for OIDC

contents: read

steps:

- name: Azure Login

uses: azure/login@v1

with:

client-id: ${{{{ secrets.AZURE_CLIENT_ID }}}}

tenant-id: ${{{{ secrets.AZURE_TENANT_ID }}}}

subscription-id: ${{{{ secrets.AZURE_SUBSCRIPTION_ID }}}}


3. Remove long-term credentials from secrets

4. Test the OIDC authentication

5. See: https://docs.github.com/en/actions/deployment/security-hardening-your-deployments/configuring-openid-connect-in-azure

