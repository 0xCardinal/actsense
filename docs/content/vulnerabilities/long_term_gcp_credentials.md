# Long Term Gcp Credentials

## Vulnerability Description


Job {job_name} uses long-term GCP credentials (GOOGLE_APPLICATION_CREDENTIALS, GCP_SA_KEY) instead of OIDC.
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


Migrate to GitHub OIDC for GCP authentication:


1. Configure OIDC in GCP:

- Create a Workload Identity Pool in GCP

- Configure OIDC provider with GitHub

- Create a service account with required permissions

- Grant the service account access to the workload identity pool


2. Update the workflow to use OIDC:

permissions:

id-token: write  # Required for OIDC

contents: read

steps:

- name: Authenticate to Google Cloud

uses: google-github-actions/auth@v2

with:

workload_identity_provider: projects/PROJECT_NUMBER/locations/global/workloadIdentityPools/POOL_ID/providers/PROVIDER_ID

service_account: SERVICE_ACCOUNT@PROJECT_ID.iam.gserviceaccount.com


3. Remove long-term credentials from secrets

4. Test the OIDC authentication

5. See: https://docs.github.com/en/actions/deployment/security-hardening-your-deployments/configuring-openid-connect-in-google-cloud-platform

