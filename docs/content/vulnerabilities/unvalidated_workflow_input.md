# Unvalidated Workflow Input

## Vulnerability Description


Workflow_dispatch input {input_name} is optional and may be used in shell commands without validation.
This creates security risks:

- Optional inputs may be used without proper validation

- Inputs can be used in shell commands or file operations

- Missing validation can lead to injection attacks

- Optional inputs may have unexpected default behavior


Security concerns:

- Code injection if input is used in shell commands

- Path traversal if input is used in file operations

- Unexpected behavior with unvalidated inputs

- Potential for security vulnerabilities


## Recommendation


Validate workflow_dispatch inputs:


1. Make inputs required when necessary:

on:

workflow_dispatch:

inputs:

{input_name}:

type: string

required: true  # Make required if needed


2. Validate inputs before use:

- name: Validate input

run: |

if [[ -z \${{{{ inputs.{input_name} }}}}\ ]]; then

echo \Input is required\

exit 1

fi

if [[ ! \${{{{ inputs.{input_name} }}}}\ =~ ^[a-zA-Z0-9 ]+$ ]]; then

echo \Invalid input format\

exit 1

fi


3. Use input types with validation:

on:

workflow_dispatch:

inputs:

{input_name}:

type: choice  # Use choice type when possible

options: [option1, option2]


4. Sanitize inputs used in shell commands

5. Review all workflow_dispatch inputs for validation

