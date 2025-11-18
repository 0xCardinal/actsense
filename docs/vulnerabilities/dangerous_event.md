# Dangerous Event

## Vulnerability Description


Workflow uses workflow_run event, which can create security risks:

- Creates dependency chains between workflows

- Can be triggered by other workflows, including potentially compromised ones

- May run with elevated permissions if the triggering workflow has them

- Can create cascading failures or security issues

- Makes workflow dependencies and execution flow harder to understand


Security concerns:

- If a triggering workflow is compromised, it can trigger this workflow

- Workflow chains can be used to bypass security controls

- Difficult to audit and understand the full execution path

- Can lead to unexpected behavior and security vulnerabilities


## Recommendation


Secure workflow_run usage or consider alternatives:


1. Review if workflow_run is necessary:

- Can the workflow be triggered directly instead?

- Can you use workflow_call for reusable workflows?


2. If you must use workflow_run, implement security controls:

- Validate the triggering workflow name

- Check the triggering workflows branch

- Use minimal permissions

- Validate all inputs and artifacts


3. Example secure pattern:

on:

workflow_run:

workflows: [\Specific Workflow Name\]  # Only specific workflows

types: [completed]

branches: [main]  # Only from specific branches

jobs:

deploy:

if: github.event.workflow_run.conclusion == success

permissions:

contents: read  # Minimal permissions


4. Consider using workflow_call for reusable workflows

5. Document workflow dependencies and execution flow

6. Regularly audit workflow chains for security issues

