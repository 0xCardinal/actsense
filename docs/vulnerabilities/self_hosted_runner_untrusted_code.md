# Self Hosted Runner Untrusted Code

## Vulnerability Description


Self-hosted runner executes potentially untrusted user input. This is CRITICAL because:

- User input from PRs, issues, or workflow inputs is executed on your infrastructure

- Attackers can inject malicious code through user input

- Injected code runs with full access to your self-hosted runner

- Attackers can access your network, secrets, and internal resources


Security risks:

- Code injection attacks on self-hosted runners

- Unauthorized access to infrastructure

- Secret exfiltration

- Network compromise


## Recommendation


Never execute untrusted user input on self-hosted runners:


1. Sanitize all user inputs:

- Validate inputs against allowlists

- Escape special characters

- Use parameterized commands


2. Use environment variables:

- Pass user input via environment variables

- Avoid direct interpolation in commands

- Use proper quoting and escaping


3. Switch to GitHub-hosted runners for untrusted input:

- Use GitHub-hosted runners for PR/issue workflows

- Only use self-hosted runners for trusted events


4. Implement input validation:

- Validate all user inputs before use

- Reject suspicious patterns

- Use type checking and constraints

