# Secrets In Matrix

## Description

Workflows that include secrets in matrix strategy definitions expose those secrets to ALL matrix job combinations: each matrix job can access and potentially log the secrets, secrets are visible in the workflow YAML to all contributors, and secrets may be logged or exposed in error messages. This violates the principle of least privilege and dramatically increases the attack surface—attackers with access to any matrix job can see all secrets. [^gh_secrets]

## Vulnerable Instance

- Workflow defines secrets in the matrix strategy, making them available to all matrix combinations.
- All matrix jobs can access the secrets, even if they don't need them.
- Secrets are visible in workflow YAML and logs.

A realistic case: publishing to npm across Node versions while embedding the token in the matrix:

```yaml
name: Publish to npm
on:
  push:
    tags: ['v*']
jobs:
  publish:
    strategy:
      matrix:
        node: [18, 20, 22]
        # Secret embedded in matrix — leaked into every job's run context,
        # visible in the workflow YAML to all contributors, and may appear
        # in debug logs for all three matrix jobs simultaneously
        npm_token: [${{ secrets.NPM_TOKEN }}]
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-node@v4
        with:
          node-version: ${{ matrix.node }}
      - run: npm publish
        env:
          NODE_AUTH_TOKEN: ${{ matrix.npm_token }}
```

## Mitigation Strategies

1. **Move secrets to job or step level**  
   Remove secrets from matrix definitions. Pass secrets at the job or step level where they're actually needed.

2. **Use environment secrets**  
   For sensitive operations, use environment secrets with job-level access instead of including them in the matrix.

3. **Never use secrets in matrix definitions**  
   Matrix values should only contain non-sensitive configuration like OS versions, Node versions, or test configurations.

4. **Review all matrix strategies**  
   Audit all workflows for secrets in matrix definitions. Use automated scanning to detect this pattern.

5. **Rotate exposed secrets**  
   If secrets were exposed in matrix definitions, rotate them immediately and review access logs for unauthorized usage.

6. **Use separate jobs for sensitive operations**  
   If secrets are needed for specific matrix combinations, create separate jobs that only run for those combinations.

### Secure Version

Remove the secret from the matrix entirely. Reference it directly at the step level via `env:` so it is scoped only to the step that needs it and never serialised into the matrix definition:

```diff
 name: Publish to npm
 on:
   push:
     tags: ['v*']
 jobs:
   publish:
     strategy:
       matrix:
         node: [18, 20, 22]
-        npm_token: [${{ secrets.NPM_TOKEN }}]  # exposed to all matrix jobs
     runs-on: ubuntu-latest
     steps:
       - uses: actions/checkout@v4
       - uses: actions/setup-node@v4
         with:
           node-version: ${{ matrix.node }}
           registry-url: https://registry.npmjs.org
       - run: npm publish
         env:
-          NODE_AUTH_TOKEN: ${{ matrix.npm_token }}
+          NODE_AUTH_TOKEN: ${{ secrets.NPM_TOKEN }}  # scoped to this step only
```

## Impact

| Dimension | Severity | Notes |
| --- | --- | --- |
| Likelihood | ![Low](https://img.shields.io/badge/-Low-green?style=flat-square) | Secrets in matrix definitions are less common but create extreme risk when present. |
| Risk | ![Critical](https://img.shields.io/badge/-Critical-red?style=flat-square) | All matrix jobs can access secrets, dramatically increasing exposure. Secrets visible in YAML to all contributors. |
| Blast radius | ![Wide](https://img.shields.io/badge/-Wide-yellow?style=flat-square) | All matrix job combinations can access the secrets, and secrets are visible in workflow files to anyone with read access. |

## References

- GitHub Docs, "Encrypted secrets," https://docs.github.com/en/actions/security-guides/encrypted-secrets [^gh_secrets]

---

[^gh_secrets]: GitHub Docs, "Encrypted secrets," https://docs.github.com/en/actions/security-guides/encrypted-secrets
