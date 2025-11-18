# Unpinned Version

## Vulnerability Description


Reference {ref} does not match standard pinning formats (version tag, commit SHA, or branch).
This may indicate an unpinned or incorrectly formatted reference that could be updated unexpectedly.


## Recommendation


Verify and pin {action_name} to a specific version:


1. Check the action repository for valid versions:

https://github.com/{action_name}/releases


2. Use one of these secure pinning formats:

- Version tag: {action_name}@v3.0.0

- Full commit SHA: {action_name}@8f4b7f84884ec3e152e95e913f196d7a537752ca

- Short SHA (min 7 chars): {action_name}@8f4b7f8


3. If {ref} is intended to be a version, ensure it follows semantic versioning (v1.2.3)
or is a valid commit SHA.

