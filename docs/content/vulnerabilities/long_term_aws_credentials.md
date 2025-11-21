# Long Term AWS Credentials

## Description

Storing `AWS_ACCESS_KEY_ID`/`AWS_SECRET_ACCESS_KEY` in GitHub secrets means the keys never expire. If an attacker exfiltrates them (e.g., via a compromised workflow), they can use the credentials until you manually rotate them. GitHub and AWS recommend using GitHub’s OIDC provider to request short-lived credentials at runtime instead. [^gh_oidc_aws]

## Vulnerable Instance

- Workflow loads static AWS keys from secrets and runs deployment commands.

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

## Mitigation Strategies

1. **Enable GitHub OIDC in AWS**  
   Create an IAM identity provider for `token.actions.githubusercontent.com` and define trust policies.
2. **Assume roles dynamically**  
   Use `aws-actions/configure-aws-credentials` with `role-to-assume` so tokens expire automatically.
3. **Scope roles tightly**  
   Grant least-privilege policies per workflow (deploy, infrastructure, etc.).
4. **Remove stored keys**  
   Delete static AWS secrets from GitHub once OIDC is configured.
5. **Monitor CloudTrail**  
   Audit role-assumption events and alert on anomalies. [^gh_oidc_aws]

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

## Impact

| Dimension | Severity | Notes |
| --- | --- | --- |
| Likelihood | ![High](https://img.shields.io/badge/-High-orange?style=flat-square) | Many legacy workflows still use static keys. |
| Risk | ![Critical](https://img.shields.io/badge/-Critical-red?style=flat-square) | Leaked keys enable long-term AWS account compromise. |
| Blast radius | ![Wide](https://img.shields.io/badge/-Wide-yellow?style=flat-square) | Any AWS resource accessible to the key is exposed. |

## References

- GitHub Docs, “Configuring OpenID Connect in Amazon Web Services,” https://docs.github.com/actions/deployment/security-hardening-your-deployments/configuring-openid-connect-in-amazon-web-services [^gh_oidc_aws]
- AWS Docs, “Use IAM roles to connect GitHub Actions to AWS,” https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_providers_create_oidc.html

---

[^gh_oidc_aws]: GitHub Docs, “Configuring OpenID Connect in Amazon Web Services,” https://docs.github.com/actions/deployment/security-hardening-your-deployments/configuring-openid-connect-in-amazon-web-services