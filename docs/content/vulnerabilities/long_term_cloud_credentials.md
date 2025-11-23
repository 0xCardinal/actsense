# Long Term Cloud Credentials

## Description

Storing static cloud provider credentials (AWS, Azure, or GCP) in GitHub secrets means the keys never expire. If an attacker exfiltrates them (e.g., via a compromised workflow), they can use the credentials until you manually rotate them. GitHub and cloud providers recommend using GitHub's OIDC provider to request short-lived credentials at runtime instead. [^gh_oidc_aws] [^gh_oidc_azure] [^gh_oidc_gcp]

## Vulnerable Instance

- Workflow loads static cloud provider keys from secrets and runs deployment commands.

### AWS Example

```yaml
jobs:
  deploy:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Configure AWS credentials
        run: |
          export AWS_ACCESS_KEY_ID=${{ secrets.AWS_ACCESS_KEY_ID }}
          export AWS_SECRET_ACCESS_KEY=${{ secrets.AWS_SECRET_ACCESS_KEY }}
      - run: aws s3 sync dist/ s3://my-bucket
```

### Azure Example

```yaml
jobs:
  deploy:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Configure Azure credentials
        run: |
          export AZURE_CLIENT_ID=${{ secrets.AZURE_CLIENT_ID }}
          export AZURE_CLIENT_SECRET=${{ secrets.AZURE_CLIENT_SECRET }}
          export AZURE_TENANT_ID=${{ secrets.AZURE_TENANT_ID }}
      - run: az login --service-principal -u $AZURE_CLIENT_ID -p $AZURE_CLIENT_SECRET --tenant $AZURE_TENANT_ID
```

### GCP Example

```yaml
jobs:
  deploy:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Configure GCP credentials
        run: |
          echo "${{ secrets.GCP_SA_KEY }}" > $HOME/gcp-key.json
          export GOOGLE_APPLICATION_CREDENTIALS=$HOME/gcp-key.json
      - run: gcloud auth activate-service-account --key-file=$HOME/gcp-key.json
```

## Mitigation Strategies

### General Principles

1. **Enable GitHub OIDC in your cloud provider**  
   Configure OIDC identity providers for `token.actions.githubusercontent.com` and define trust policies.
2. **Use short-lived credentials**  
   Request credentials dynamically at runtime so tokens expire automatically.
3. **Scope roles tightly**  
   Grant least-privilege policies per workflow (deploy, infrastructure, etc.).
4. **Remove stored keys**  
   Delete static cloud provider secrets from GitHub once OIDC is configured.
5. **Monitor access**  
   Audit credential usage and alert on anomalies.

### AWS-Specific

1. **Create IAM identity provider**  
   Set up OIDC provider for `token.actions.githubusercontent.com` in AWS IAM.
2. **Use aws-actions/configure-aws-credentials**  
   Use the official action with `role-to-assume` parameter.
3. **Monitor CloudTrail**  
   Audit role-assumption events and alert on anomalies. [^gh_oidc_aws]

### Azure-Specific

1. **Create App Registration**  
   Register an Azure AD application for OIDC federation.
2. **Use azure/login action**  
   Use `azure/login@v1` with `credentials` parameter pointing to OIDC.
3. **Configure federated credentials**  
   Set up federated identity credentials in Azure AD. [^gh_oidc_azure]

### GCP-Specific

1. **Create Workload Identity Pool**  
   Set up a Workload Identity Pool in GCP for GitHub Actions.
2. **Use google-github-actions/auth**  
   Use `google-github-actions/auth@v1` with `workload_identity_provider`.
3. **Configure service account mapping**  
   Map GitHub repositories to GCP service accounts. [^gh_oidc_gcp]

### Secure Versions

#### AWS

```diff
+permissions:
+  id-token: write
+  contents: read
+
 jobs:
  deploy:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Configure AWS credentials
-        run: |
-          export AWS_ACCESS_KEY_ID=${{ secrets.AWS_ACCESS_KEY_ID }}
-          export AWS_SECRET_ACCESS_KEY=${{ secrets.AWS_SECRET_ACCESS_KEY }}
+        uses: aws-actions/configure-aws-credentials@v4
+        with:
+          role-to-assume: arn:aws:iam::123456789012:role/GitHubActionsDeploy
+          aws-region: us-east-1
      - run: aws s3 sync dist/ s3://my-bucket
```

#### Azure

```diff
+permissions:
+  id-token: write
+  contents: read
+
 jobs:
  deploy:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Configure Azure credentials
-        run: |
-          export AZURE_CLIENT_ID=${{ secrets.AZURE_CLIENT_ID }}
-          export AZURE_CLIENT_SECRET=${{ secrets.AZURE_CLIENT_SECRET }}
-          export AZURE_TENANT_ID=${{ secrets.AZURE_TENANT_ID }}
-      - run: az login --service-principal -u $AZURE_CLIENT_ID -p $AZURE_CLIENT_SECRET --tenant $AZURE_TENANT_ID
+        uses: azure/login@v1
+        with:
+          client-id: ${{ secrets.AZURE_CLIENT_ID }}
+          tenant-id: ${{ secrets.AZURE_TENANT_ID }}
+          subscription-id: ${{ secrets.AZURE_SUBSCRIPTION_ID }}
      - run: az deployment group create --resource-group my-rg --template-file template.json
```

#### GCP

```diff
+permissions:
+  id-token: write
+  contents: read
+
 jobs:
  deploy:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Configure GCP credentials
-        run: |
-          echo "${{ secrets.GCP_SA_KEY }}" > $HOME/gcp-key.json
-          export GOOGLE_APPLICATION_CREDENTIALS=$HOME/gcp-key.json
-      - run: gcloud auth activate-service-account --key-file=$HOME/gcp-key.json
+        uses: google-github-actions/auth@v1
+        with:
+          workload_identity_provider: projects/123456789/locations/global/workloadIdentityPools/my-pool/providers/github
+          service_account: github-actions@my-project.iam.gserviceaccount.com
      - run: gcloud app deploy
```

## Impact

| Dimension | Severity | Notes |
| --- | --- | --- |
| Likelihood | ![High](https://img.shields.io/badge/-High-orange?style=flat-square) | Many legacy workflows still use static keys across all cloud providers. |
| Risk | ![High](https://img.shields.io/badge/-Critical-red?style=flat-square) | Leaked keys enable long-term cloud account compromise with full access to resources. |
| Blast radius | ![Wide](https://img.shields.io/badge/-Wide-yellow?style=flat-square) | Any cloud resource accessible to the key is exposed, potentially affecting entire projects or organizations. |

## References

- GitHub Docs, "Configuring OpenID Connect in Amazon Web Services," https://docs.github.com/actions/deployment/security-hardening-your-deployments/configuring-openid-connect-in-amazon-web-services [^gh_oidc_aws]
- GitHub Docs, "Configuring OpenID Connect in Azure," https://docs.github.com/actions/deployment/security-hardening-your-deployments/configuring-openid-connect-in-azure [^gh_oidc_azure]
- GitHub Docs, "Configuring OpenID Connect in Google Cloud Platform," https://docs.github.com/actions/deployment/security-hardening-your-deployments/configuring-openid-connect-in-google-cloud-platform [^gh_oidc_gcp]
- AWS Docs, "Use IAM roles to connect GitHub Actions to AWS," https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_providers_create_oidc.html
- Azure Docs, "Configure an app to trust GitHub," https://learn.microsoft.com/azure/active-directory/develop/workload-identity-federation-create-trust-github
- GCP Docs, "Authenticating GitHub Actions with Workload Identity Federation," https://cloud.google.com/iam/docs/workload-identity-federation-with-deployment-pipelines

---

[^gh_oidc_aws]: GitHub Docs, "Configuring OpenID Connect in Amazon Web Services," https://docs.github.com/actions/deployment/security-hardening-your-deployments/configuring-openid-connect-in-amazon-web-services

[^gh_oidc_azure]: GitHub Docs, "Configuring OpenID Connect in Azure," https://docs.github.com/actions/deployment/security-hardening-your-deployments/configuring-openid-connect-in-azure

[^gh_oidc_gcp]: GitHub Docs, "Configuring OpenID Connect in Google Cloud Platform," https://docs.github.com/actions/deployment/security-hardening-your-deployments/configuring-openid-connect-in-google-cloud-platform

