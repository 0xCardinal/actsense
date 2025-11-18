# Unpinnable Composite Subaction

## Vulnerability Description


Composite action uses sub-action {uses} with reference {ref} which is not a commit SHA.
This creates transitive dependency risks:

- Tags and branches can be moved or updated

- Sub-actions can be updated with malicious code

- Security vulnerabilities can be introduced through sub-actions

- Builds are not reproducible


Security concerns:

- Supply chain attacks through compromised sub-actions

- Transitive dependency vulnerabilities

- Non-reproducible builds

- Difficult to audit and track sub-action versions


## Recommendation


Pin all sub-actions to full 40-character commit SHA:


1. Find the commit SHA for the sub-action:

- Visit: https://github.com/{uses.split(@)[0]}/releases

- Or check the repository for the specific tag/branch

- Copy the full 40-character commit SHA


2. Update the composite action:

steps:

- uses: {uses.split(@)[0]}@<full-40-char-sha>

# Instead of: {uses}


3. Verify the SHA is correct:

- Should be exactly 40 hexadecimal characters

- Verify at: https://github.com/{uses.split(@)[0]}/commit/<sha>


4. Review all sub-actions in composite actions

5. Regularly update and audit sub-action SHAs

