# Self Hosted Runner Issue Exposure

## Vulnerability Description


Self-hosted runner can be triggered by issue events in a public repository. This is dangerous because:

- Anyone can create issues in public repositories

- Issue events can trigger workflows on self-hosted runners

- Attackers can abuse this to execute code on your infrastructure

- Issue content may be used in workflow execution


Security risks:

- Unauthorized code execution on self-hosted runners

- Potential for abuse and DoS attacks

- Access to infrastructure through issue-triggered workflows


## Recommendation


Restrict self-hosted runners from issue triggers:


1. Use GitHub-hosted runners for issue-triggered workflows:

runs-on: ubuntu-latest


2. If self-hosted runners are necessary:

- Restrict to trusted events only (push, workflow_dispatch)

- Dont allow issue triggers

- Use runner groups with restricted access


3. For issue workflows in public repos:

- Always use GitHub-hosted runners

- Validate and sanitize all issue content

- Use minimal permissions

