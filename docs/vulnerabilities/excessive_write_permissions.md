# Excessive Write Permissions

## Vulnerability Description


Workflow has write permissions but job {job_name} appears to be read-only (contains {operation}).
This violates the principle of least privilege:

- Read-only workflows dont need write permissions

- Write permissions increase the attack surface

- If compromised, attackers have unnecessary write access

- Write permissions may be used maliciously


Security concerns:

- Unnecessary permissions increase attack surface

- Violation of least privilege principle

- Potential for privilege escalation

- Difficult to audit and control access


## Recommendation


Use minimal required permissions:


1. Use read-only permissions for read-only workflows:

permissions:

contents: read

pull-requests: read


2. Review workflow operations:

- Does the workflow actually need to write?

- Can operations be done with read-only access?

- Are write permissions truly necessary?


3. Use job-level permissions:

- Grant write permissions only to jobs that need them

- Use read-only permissions for test/build jobs

- Scope permissions to specific operations


4. Follow principle of least privilege:

- Grant minimum permissions required

- Review permissions regularly

- Remove unnecessary permissions


5. Consider using separate workflows:

- Read-only workflow for tests/builds

- Write workflow only for deployments

- Separate concerns and permissions

