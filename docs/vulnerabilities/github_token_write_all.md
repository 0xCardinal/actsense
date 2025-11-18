# Github Token Write All

## Vulnerability Description


Workflow uses write-all permissions for GITHUB_TOKEN. This grants the workflow write access to:

- Repository contents (files, branches, commits)

- Pull requests and issues

- GitHub Actions

- Packages and registries

- Security alerts and advisories

- And many other resources


This violates the principle of least privilege and creates significant security risks:

- If the workflow is compromised, attackers have broad access to your repository

- Attackers can modify files, create backdoors, or exfiltrate data

- Attackers can create malicious actions or modify existing ones

- Attackers can manipulate pull requests, issues, and other resources


Most workflows only need read access or very specific write permissions.


## Recommendation


Replace write-all with specific, scoped permissions:


1. Identify what the workflow actually needs:

- Review each step to determine required permissions

- Most workflows only need read access


2. Use minimal permissions:

permissions:

contents: read  # For reading repository files

pull-requests: read  # For reading PRs


3. If write access is needed, scope it precisely:

permissions:

contents: write  # Only if you need to modify files

pull-requests: write  # Only if you need to create/update PRs


4. Use job-level permissions for specific jobs:

jobs:

deploy:

permissions:

contents: write  # Only this job needs write access


5. Avoid granting permissions you dont need

6. Regularly review and audit permissions

