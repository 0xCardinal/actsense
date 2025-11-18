# Runner Label Confusion

## Vulnerability Description


Runner label {runner} may be confusing and could lead to jobs running on unintended infrastructure.
{description}


This creates security risks:

- Jobs may run on unintended runners

- Confusion between self-hosted and GitHub-hosted runners

- Potential for misconfiguration and security issues

- Difficult to audit and verify runner selection


Security concerns:

- Unintended code execution on wrong infrastructure

- Potential for privilege escalation

- Difficult to track and audit runner usage


## Recommendation


Use distinct, clear labels for self-hosted runners:


1. Use unique labels for self-hosted runners:

runs-on: my-company-runner  # Clear, distinct label

# Not: runs-on: self-hosted-ubuntu  # Confusing


2. Avoid labels that match GitHub-hosted runners:

- Dont use ubuntu-latest, windows-latest, macos-latest

- Use company-specific or environment-specific labels

- Make labels clearly indicate self-hosted nature


3. Use runner groups for organization:

- Organize runners into groups

- Use descriptive group names

- Document runner labels and purposes


4. Review all runner labels:

- Ensure labels are unique and clear

- Document runner label conventions

- Avoid generic or confusing labels

