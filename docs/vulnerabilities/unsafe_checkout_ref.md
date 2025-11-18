# Unsafe Checkout Ref

## Vulnerability Description


Checkout uses ref {ref} which contains variables that may not be properly validated.
This can be dangerous if:

- The ref comes from user input (workflow_dispatch, pull_request)

- The ref is not validated against an allowlist

- The ref could point to malicious code or branches


Security risks:

- Attackers could checkout arbitrary branches or commits

- Malicious code could be executed from untrusted refs

- Secrets could be exposed if checking out untrusted code


## Recommendation


Validate and sanitize ref inputs:


1. Validate refs against an allowlist:

- name: Validate ref

run: |

if [[ \${{{{ github.event.ref }}}}\ != \refs/heads/main\ && \${{{{ github.event.ref }}}}\ != \refs/heads/develop\ ]]; then

echo \Invalid ref\

exit 1

fi


2. Use fixed refs when possible:

- uses: actions/checkout@v4

with:

ref: refs/heads/main  # Fixed ref


3. For pull requests, checkout the base branch:

- uses: actions/checkout@v4

with:

ref: ${{{{ github.event.pull_request.base.ref }}}}  # Base branch, not PR branch


4. Sanitize ref inputs before use

5. Review all checkout refs in your workflows

