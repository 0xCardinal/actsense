# Code Injection via Input

## Description

Workflows that accept `workflow_dispatch` inputs and interpolate them directly into shell commands give untrusted users a remote code execution primitive: an attacker can supply `foo; curl attacker` and the runner executes it with the workflow’s privileges. GitHub explicitly warns that user input must be validated before use in commands or file paths. [^gh_security]

## Vulnerable Instance

- Workflow exposes a free-form `workflow_dispatch` input (type `string`).
- A step calls the input inside `run: |` without quoting or validation.
- Runner inherits write/scoped permissions, so malicious commands can exfiltrate secrets or push commits.

```yaml
name: Manual Deploy
on:
  workflow_dispatch:
    inputs:
      target_env:
        description: "Environment name"
        required: true

jobs:
  deploy:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Run deploy script
        run: ./scripts/deploy.sh ${{ inputs.target_env }}
```

An attacker can trigger this workflow with `target_env: "prod && cat $GITHUB_TOKEN"` and arbitrary commands will run.

## Mitigation Strategies

1. **Validate inputs early**  
   Use bash regex/allowlists or `case` statements to restrict the accepted characters or values.
2. **Prefer enumerated choices**  
   Convert string inputs to `type: choice` where practical so GitHub enforces the set of allowed values.
3. **Quote and sanitize**  
   Always quote input references (e.g., `"${{ inputs.name }}"`) and strip unsafe characters before use.
4. **Separate logic from user input**  
   Avoid passing inputs to `eval`, command substitution, or scripts that construct shell pipelines.
5. **Limit workflow permissions**  
   Set minimal `permissions` so even if injection occurs, token scope minimizes damage.
6. **Audit dispatch triggers**  
   Periodically review `workflow_dispatch` workflows for unsafe `run` steps or missing validation blocks.

### Secure Version

- Input validation runs before any sensitive command.
- Input type is restricted to a known set of environments.
- Deployment script receives a sanitized, quoted argument only after validation passes. [^gh_security]

```yaml
name: Manual Deploy (Safe)
on:
  workflow_dispatch:
    inputs:
      target_env:
        type: choice
        options: [staging, production]
        required: true

jobs:
  deploy:
    permissions:
      contents: read
      deployments: write
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Validate environment
        run: |
          case "${{ inputs.target_env }}" in
            staging|production) ;;
            *) echo "Invalid env"; exit 1 ;;
          esac
      - name: Deploy
        run: ./scripts/deploy.sh "${{ inputs.target_env }}"
```

## Impact

| Dimension | Severity | Notes |
| --- | --- | --- |
| Likelihood | ![High](https://img.shields.io/badge/-High-orange?style=flat-square) | Manual workflows often expose unvalidated text inputs for convenience. |
| Risk | ![Critical](https://img.shields.io/badge/-Critical-red?style=flat-square) | Injected commands inherit the workflow token, enabling repo takeovers or secret theft. |
| Blast radius | ![Wide](https://img.shields.io/badge/-Wide-yellow?style=flat-square) | Any environment reachable by the deploy script (infra, registries, production) is exposed. |

## References

- GitHub Docs, “Security hardening for GitHub Actions,” https://docs.github.com/actions/security-guides/security-hardening-for-github-actions [^gh_security]
- GitHub Docs, “Events that trigger workflows: workflow_dispatch,” https://docs.github.com/actions/using-workflows/events-that-trigger-workflows#workflow_dispatch

---

[^gh_security]: GitHub Docs, “Security hardening for GitHub Actions,” https://docs.github.com/actions/security-guides/security-hardening-for-github-actions