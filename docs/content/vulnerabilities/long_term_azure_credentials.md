# Long Term Azure Credentials

## Description

Workflows that authenticate to Azure using static service principal secrets (`AZURE_CLIENT_SECRET`) rely on long-lived credentials. If those secrets leak, attackers can access Azure resources indefinitely. GitHub’s OIDC integration with Azure AD issues short-lived tokens tied to a specific workflow run and eliminates stored secrets. [^gh_oidc_azure]

## Vulnerable Instance

- Workflow exports client ID/secret into environment variables and runs Azure CLI commands.

```yaml
jobs:
  deploy:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Login to Azure
        env:
          AZURE_CLIENT_ID: ${{ secrets.AZURE_CLIENT_ID }}
          AZURE_CLIENT_SECRET: ${{ secrets.AZURE_CLIENT_SECRET }}
          AZURE_TENANT_ID: ${{ secrets.AZURE_TENANT_ID }}
        run: az login --service-principal -u "$AZURE_CLIENT_ID" -p "$AZURE_CLIENT_SECRET" --tenant "$AZURE_TENANT_ID"
      - run: az webapp deployment source config-zip ...
```

## Mitigation Strategies

1. **Create federated credentials**  
   In Azure AD, configure the GitHub OIDC provider on your app registration.
2. **Use `azure/login` with OIDC**  
   Grant `id-token: write` and use the `azure/login@v1` action with `client-id`/`tenant-id`/`subscription-id` (no secret).
3. **Scope roles tightly**  
   Assign least-privilege roles (e.g., `Contributor` on specific resource groups).
4. **Remove long-term secrets**  
   Delete `AZURE_CLIENT_SECRET` from repository/org secrets after migration.
5. **Monitor sign-ins**  
   Use Azure AD sign-in logs to alert on unexpected role assumptions. [^gh_oidc_azure]

### Secure Version

- Workflow relies on GitHub OIDC to request Azure tokens at runtime.

```yaml
permissions:
  id-token: write
  contents: read

jobs:
  deploy:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Azure login
        uses: azure/login@v1
        with:
          client-id: ${{ vars.AZURE_CLIENT_ID }}
          tenant-id: ${{ vars.AZURE_TENANT_ID }}
          subscription-id: ${{ vars.AZURE_SUBSCRIPTION_ID }}
      - run: az webapp deployment source config-zip ...
```

## Impact

| Dimension | Severity | Notes |
| --- | --- | --- |
| Likelihood | ![High](https://img.shields.io/badge/-High-orange?style=flat-square) | Many Azure workflows still use service principal secrets. |
| Risk | ![Critical](https://img.shields.io/badge/-Critical-red?style=flat-square) | Stolen secrets allow persistent Azure access. |
| Blast radius | ![Wide](https://img.shields.io/badge/-Wide-yellow?style=flat-square) | Any subscription/resource group assigned to the principal is exposed. |

## References

- GitHub Docs, “Configuring OpenID Connect in Azure,” https://docs.github.com/actions/deployment/security-hardening-your-deployments/configuring-openid-connect-in-azure [^gh_oidc_azure]
- Microsoft Docs, “Use workload identity federation for GitHub Actions,” https://learn.microsoft.com/azure/developer/github/connect-from-azure

---

[^gh_oidc_azure]: GitHub Docs, “Configuring OpenID Connect in Azure,” https://docs.github.com/actions/deployment/security-hardening-your-deployments/configuring-openid-connect-in-azure