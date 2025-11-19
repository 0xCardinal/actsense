# Insecure Pull Request Target

## Vulnerability Description


Workflow uses pull_request_target event with checkout of PR code. This is a CRITICAL vulnerability because:

- pull_request_target runs with write permissions to the repository

- Checking out PR code allows attackers from forks to execute arbitrary code

- The workflow runs in the context of the base branch but executes code from the PR

- Attackers can access secrets, modify files, or create backdoors

- This is one of the most dangerous GitHub Actions vulnerabilities


Attack scenario:

1. Attacker creates a PR from a fork

2. PR includes malicious code in .github/workflows or other files

3. Workflow triggers on pull_request_target event

4. Workflow checks out the PR branch (attackers code)

5. Malicious code executes with write permissions and access to secrets

6. Attacker can exfiltrate secrets, modify repository, or create backdoors

7. Even if PR is closed/not merged, the damage is already done


This is a well-known vulnerability pattern (CVE-2020-14188, etc.)


## Recommendation


NEVER checkout PR code in pull_request_target workflows:


1. Always checkout the BASE branch, not the PR branch:

on:

pull_request_target:

jobs:

build:

steps:

- uses: actions/checkout@v4

with:

ref: ${{{{ github.event.pull_request.base.ref }}}}  # BASE branch

# NOT: ref: ${{{{ github.event.pull_request.head.sha }}}}  # DANGEROUS


2. If you need PR code, use pull_request event instead:

on:

pull_request:  # Safer - read-only permissions

jobs:

build:

steps:

- uses: actions/checkout@v4  # Can safely checkout PR code


3. If you must use pull_request_target:

- Only checkout the base branch

- Never trust or execute code from the PR

- Use minimal permissions

- Validate all inputs

- Dont run any code from the PR branch


4. Review GitHubs security advisory: https://securitylab.github.com/research/github-actions-untrusted-input/

5. Consider using pull_request event for most use cases

