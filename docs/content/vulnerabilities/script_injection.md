# Script Injection

## Vulnerability Description


Detected PowerShell injection vulnerability: {description}. This is CRITICAL because:

- User input is used in dangerous PowerShell operations

- Invoke-Expression, Invoke-Command, or call operators can execute arbitrary code

- Attackers can inject malicious PowerShell commands

- Injected commands run with the workflows permissions

- Attackers can access secrets, modify files, or compromise the system


Attack scenario:

1. Attacker provides malicious input

2. Input contains PowerShell injection payload

3. PowerShell executes input in Invoke-Expression/Invoke-Command context

4. Malicious code executes, compromising the system


## Recommendation


Use PowerShell parameters or environment variables instead of direct string interpolation:


1. Use environment variables:

- name: Run PowerShell

env:

USER_INPUT: ${{{{ github.event.pull_request.title }}}}

shell: powershell

run: |

Write-Host \$env:USER_INPUT\  # Safer


2. Use PowerShell parameters:

- Use -ParameterName syntax

- Avoid string interpolation in commands

- Use proper parameter binding


3. Validate and sanitize inputs:

- Validate input types and formats

- Sanitize special characters

- Use allowlists for permitted values


4. Avoid dangerous patterns:

- Never use Invoke-Expression with user input

- Never use Invoke-Command with user input

- Never use call operator (&) with user input

- Never use dot sourcing (.) with user input


5. Use safe PowerShell practices:

- Use parameterized commands

- Use proper quoting

- Validate all user inputs


6. Review all PowerShell script usage for injection risks

