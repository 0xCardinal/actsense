# No File Tampering Protection

## Vulnerability Description


Build job {job_name} modifies files during the build process. This creates security risks:

- Files can be tampered with during build by malicious actions or dependencies

- Source code or artifacts can be modified before deployment

- Malicious code can be injected into build outputs

- Compromised dependencies can modify files

- Difficult to detect unauthorized file modifications


Security concerns:

- Supply chain attacks through file tampering

- Malicious code injection into build artifacts

- Unauthorized modifications to source code

- Compromised artifacts deployed to production


## Recommendation


Implement file tampering protection:


1. Use Endpoint Detection and Response (EDR) tools:

- Monitor file modifications during build

- Alert on unauthorized file changes

- Track file integrity throughout the build process


2. Implement file integrity checks:

- Calculate checksums before and after build steps

- Verify file integrity at critical points

- Compare checksums to detect tampering


3. Use read-only source checkouts when possible:

- Minimize file modifications during build

- Use separate directories for build outputs

- Isolate source code from build artifacts


4. Review and audit file modifications:

- Log all file write operations

- Review file changes in build logs

- Validate file modifications are expected


5. Use trusted build environments:

- GitHub-hosted runners when possible

- Secured and isolated self-hosted runners

- Minimal access to file system

