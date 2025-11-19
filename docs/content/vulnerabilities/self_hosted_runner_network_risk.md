# Self Hosted Runner Network Risk

## Vulnerability Description


Self-hosted runner performs risky network operation: {description}. This is dangerous because:

- Downloads and executes code from the internet

- No verification of downloaded code integrity

- Malicious code can compromise the runner

- Attackers can inject malicious payloads

- Runner environment can be fully compromised


Security risks:

- Code injection through downloaded scripts

- Runner compromise and persistence

- Access to runner network and resources

- Potential for lateral movement


## Recommendation


Avoid downloading and executing scripts from the internet on self-hosted runners:


1. Download and verify scripts first:

- Download script to file

- Verify checksum before execution

- Review script content if possible

- Then execute verified script


2. Use trusted sources:

- Only download from trusted sources

- Use HTTPS with certificate verification

- Pin to specific versions/commits

- Verify checksums


3. Implement network security controls:

- Use network segmentation

- Implement firewall rules

- Monitor outbound connections

- Use allowlists for permitted endpoints


4. Consider alternatives:

- Store scripts in repository

- Use GitHub Actions instead of shell scripts

- Use containerized execution


5. For Docker privileged mode:

- Avoid --privileged flag

- Use specific capabilities if needed

- Run containers with minimal privileges

