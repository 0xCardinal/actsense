# Github Token Write Permissions

## Vulnerability Description


GITHUB_TOKEN has write permissions for: {, .join(write_permissions

## Recommendation


Review and minimize write permissions:


1. For each write permission, verify its necessary:

+
.join([   - {perm}: Is this needed for the workflow to function? for perm in write_permissions]) +


2. Remove unnecessary write permissions:

permissions:

contents: read  # Change from write to read if not needed

pull-requests: read  # Change from write to read if not needed


3. If write access is needed, scope it to specific operations:

- Use job-level permissions for jobs that need elevated access

- Consider using GitHub Apps with limited permissions


4. Document why each write permission is required

5. Regularly audit permissions and remove unused ones

