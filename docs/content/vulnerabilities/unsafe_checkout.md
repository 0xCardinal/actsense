# Unsafe Checkout

## Vulnerability Description


Checkout action uses persist-credentials=true, which persists Git credentials for subsequent steps.
This creates security risks:

- Credentials are stored in the runners Git configuration

- Subsequent steps can access and potentially misuse these credentials

- Credentials may be exposed in logs or artifacts

- If the runner is compromised, credentials are accessible


Security concerns:

- Credentials can be used by malicious steps or actions

- Credentials may be logged or exposed in error messages

- Unnecessary credential persistence increases attack surface


## Recommendation


Remove persist-credentials or set it to false:


1. Update the checkout step:

- uses: actions/checkout@v4

with:

persist-credentials: false  # Or remove this line (default is false)


2. If you need to push changes, use GITHUB_TOKEN with appropriate permissions:

permissions:

contents: write

steps:

- uses: actions/checkout@v4

with:

persist-credentials: false

- run: git push  # Uses GITHUB_TOKEN automatically


3. For external repositories, use a Personal Access Token (PAT) stored in secrets:

- uses: actions/checkout@v4

with:

token: ${{{{ secrets.PAT }}}}

persist-credentials: false


4. Review all checkout steps in your workflows

5. Use minimal permissions for GITHUB_TOKEN

