# Token Permission Escalation

## Description

Workflows that manipulate GITHUB_TOKEN directly (base64 encoding, echoing to logs, passing in command-line arguments) create security risks: tokens can be extracted and used outside the workflow context, token permissions can be escalated through manipulation, and extracted tokens can be used to access resources beyond the workflow scope. Tokens may be logged or exposed in artifacts, enabling attackers to maintain persistent access even after workflow completion. [^gh_permissions]

## Vulnerable Instance

- Workflow encodes, logs, or manipulates GITHUB_TOKEN in ways that could expose it.
- Token is passed in command-line arguments or written to files.
- Token could be extracted and used outside the workflow context.

```yaml
name: Dangerous Token Usage
on: [push]
jobs:
  deploy:
    runs-on: ubuntu-latest
    steps:
      - name: Encode token
        run: |
          echo "${{ secrets.GITHUB_TOKEN }}" | base64 > token.txt  # Dangerous
          # Token could be extracted from token.txt
```

## Mitigation Strategies

1. **Use built-in GitHub Actions permissions**  
   Use the `permissions` key to control token permissions instead of manipulating tokens directly. Set specific permissions like `contents: read`, `pull-requests: write`, etc.

2. **Don't extract or encode tokens**  
   Avoid base64 encoding of tokens, don't echo tokens to logs or files, and don't pass tokens in command-line arguments. Let GitHub Actions handle tokens securely.

3. **Use GitHub Secrets for sensitive data**  
   Store tokens in GitHub Secrets and access via `${{ secrets.TOKEN_NAME }}`. Secrets are automatically masked in logs.

4. **Use job-level permissions**  
   If you need different permissions, use job-level permissions, create separate workflows with appropriate permissions, or use GitHub Apps with limited scopes.

5. **Review all token usage**  
   Audit all workflows for token manipulation. Never log or expose tokens in any form. Use GitHub's built-in token handling.

6. **Rotate exposed tokens**  
   If tokens were exposed, they cannot be rotated (GITHUB_TOKEN is auto-generated), but review access logs and consider using PATs with limited scopes if needed.

### Secure Version

```diff
 name: Secure Token Usage
 on: [push]
 jobs:
   deploy:
     runs-on: ubuntu-latest
+    permissions:
+      contents: read
+      pull-requests: write  # Use permissions, not token manipulation
     steps:
+      - uses: actions/checkout@v4
+      - name: Deploy
+        run: |
+          # Token is handled securely by GitHub Actions
+          git push origin main
-      - name: Encode token
-        run: |
-          echo "${{ secrets.GITHUB_TOKEN }}" | base64 > token.txt  # Dangerous
-          # Token could be extracted from token.txt
```

## Impact

| Dimension | Severity | Notes |
| --- | --- | --- |
| Likelihood | ![Low](https://img.shields.io/badge/-Low-green?style=flat-square) | Token manipulation is less common but creates high risk when present. |
| Risk | ![High](https://img.shields.io/badge/-Critical-red?style=flat-square) | Extracted tokens can be used outside workflows to access repository resources, potentially enabling persistent compromise. |
| Blast radius | ![Wide](https://img.shields.io/badge/-Wide-yellow?style=flat-square) | Compromised tokens can affect all resources the token can access, potentially including the entire repository and its contents. |

## References

- GitHub Docs, "Permissions for the GITHUB_TOKEN," https://docs.github.com/en/actions/security-guides/automatic-token-authentication#permissions-for-the-github_token [^gh_permissions]

---

[^gh_permissions]: GitHub Docs, "Permissions for the GITHUB_TOKEN," https://docs.github.com/en/actions/security-guides/automatic-token-authentication#permissions-for-the-github_token
