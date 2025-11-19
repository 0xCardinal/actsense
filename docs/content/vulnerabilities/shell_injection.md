# Shell Injection

## Vulnerability Description


Detected dangerous shell command with user input: {description}. This is dangerous because:

- User-controlled input is piped directly to shell interpreters

- No validation or sanitization of input

- Attackers can inject malicious commands

- Injected commands execute with workflow permissions


Security risks:

- Code injection through user input

- Unauthorized command execution

- System compromise

- Secret exfiltration


## Recommendation


Avoid piping user input directly to shell interpreters:


1. Download and verify scripts first:

- Download script to file

- Verify checksum

- Review script content

- Then execute verified script


2. Validate and sanitize input:

- Validate input against allowlists

- Sanitize special characters

- Use parameterized commands


3. Use trusted sources:

- Only download from trusted sources

- Pin to specific versions

- Verify checksums


4. Consider alternatives:

- Store scripts in repository

- Use GitHub Actions instead

- Use containerized execution

