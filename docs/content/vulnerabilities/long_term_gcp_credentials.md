# Long Term GCP Credentials

## Description

Storing Google Cloud JSON service account keys (`GOOGLE_APPLICATION_CREDENTIALS`, `GCP_SA_KEY`) in GitHub secrets creates a long-lived credential. If the key leaks, attackers can impersonate the service account until you manually revoke it. GitHub’s OIDC + Workload Identity Federation lets workflows request short-lived credentials without storing keys. [^gh_oidc_gcp]

## Vulnerable Instance

- Workflow base64-decodes a service account key and activates it with `gcloud auth activate-service-account`.

```yaml
jobs:
  deploy:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Authenticate to GCP
        env:
          GCP_SA_KEY: ${{ secrets.GCP_SA_KEY }}
        run: |
          echo "$GCP_SA_KEY" > key.json
          gcloud auth activate-service-account --key-file key.json
      - run: gcloud run deploy ...
```

## Mitigation Strategies

1. **Create a Workload Identity Pool/Provider**  
   Configure `token.actions.githubusercontent.com` as an OIDC provider in GCP IAM.
2. **Bind service accounts to the provider**  
   Grant the necessary IAM roles to the service account and allow GitHub workflows to impersonate it.
3. **Use `google-github-actions/auth`**  
   Request tokens at runtime with `id-token: write`.
4. **Delete stored keys**  
   Remove JSON key secrets after federation is in place.
5. **Monitor Cloud Audit Logs**  
   Alert on unexpected service account impersonations. [^gh_oidc_gcp]

### Secure Version

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
       - name: Authenticate to GCP
-        env:
-          GCP_SA_KEY: ${{ secrets.GCP_SA_KEY }}
+      - id: auth
+        uses: google-github-actions/auth@v2
+        with:
+          workload_identity_provider: projects/123456789/locations/global/workloadIdentityPools/github/providers/actions
+          service_account: deployer@my-project.iam.gserviceaccount.com
+      - uses: google-github-actions/setup-gcloud@v2
         run: |
-          echo "$GCP_SA_KEY" > key.json
-          gcloud auth activate-service-account --key-file key.json
       - run: gcloud run deploy ...
```

## Impact

| Dimension | Severity | Notes |
| --- | --- | --- |
| Likelihood | ![High](https://img.shields.io/badge/-High-orange?style=flat-square) | Many repos still rely on JSON keys. |
| Risk | ![Critical](https://img.shields.io/badge/-Critical-red?style=flat-square) | Exposed keys allow persistent GCP access. |
| Blast radius | ![Wide](https://img.shields.io/badge/-Wide-yellow?style=flat-square) | Any project/resource accessible to the service account is at risk. |

## References

- GitHub Docs, “Configuring OpenID Connect in Google Cloud Platform,” https://docs.github.com/actions/deployment/security-hardening-your-deployments/configuring-openid-connect-in-google-cloud-platform [^gh_oidc_gcp]
- Google Cloud Docs, “Authenticate workloads using Workload Identity Federation,” https://cloud.google.com/iam/docs/workload-identity-federation

---

[^gh_oidc_gcp]: GitHub Docs, “Configuring OpenID Connect in Google Cloud Platform,” https://docs.github.com/actions/deployment/security-hardening-your-deployments/configuring-openid-connect-in-google-cloud-platform