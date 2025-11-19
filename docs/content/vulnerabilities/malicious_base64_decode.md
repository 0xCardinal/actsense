# Malicious Base64 Decode

## Vulnerability Description


Detected {description} in the workflow. This is a critical security vulnerability because:

- Base64 encoding is used to obfuscate malicious code

- The encoded content is not human-readable, making review difficult

- Attackers can hide malicious commands in base64-encoded strings

- The decoded content is executed directly without verification

- Security scanners may not detect malicious code in base64-encoded form


Attack scenarios:

- Attacker embeds malicious commands in base64-encoded string

- The encoded string looks harmless but decodes to dangerous commands

- Malicious code executes with workflow permissions

- Attackers can exfiltrate secrets, modify files, or perform unauthorized actions


This pattern is commonly used in supply chain attacks to hide malicious payloads.


## Recommendation


Never execute base64-decoded content directly. Instead:


1. Use readable, reviewable code:

- Write scripts in plain text

- Store scripts in the repository

- Review all code before execution


2. If you must use base64 (e.g., for binary data):

- Decode to a file first

- Review the decoded content

- Verify checksums

- Execute only after verification


3. Use GitHub Actions instead:

- Prefer trusted GitHub Actions over shell scripts

- Actions are more transparent and reviewable

- Actions can be pinned to specific versions


4. Review all base64 usage in workflows

5. Consider using secrets or encrypted values instead of base64 encoding

