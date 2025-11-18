# Unfiltered Network Traffic

## Vulnerability Description


Job {job_name} performs network operations (curl, wget, nc, ssh, etc.) without filtering.
This creates security risks:

- Network traffic can be used to exfiltrate secrets and sensitive data

- Attackers can use network operations to send credentials to external servers

- Unfiltered outbound connections may violate security policies

- Network operations can be used to establish backdoors

- Difficult to detect and prevent credential exfiltration


Security concerns:

- Compromised workflows can exfiltrate secrets via network requests

- Unfiltered network access increases attack surface

- Network operations may bypass security controls

- Difficult to audit and monitor network traffic


## Recommendation


Implement network segmentation and traffic filtering:


1. Restrict outbound network access:

- Use network policies to limit allowed destinations

- Block access to external IPs except required services

- Use allowlists for permitted endpoints


2. Monitor network traffic:

- Log all outbound connections

- Set up alerts for suspicious network activity

- Review network logs regularly


3. Use network segmentation:

- Isolate workflows in separate network segments

- Use firewalls to control traffic flow

- Implement network access controls


4. Validate network operations:

- Review all curl/wget commands

- Ensure URLs are from trusted sources

- Avoid using user input in network commands


5. Consider using GitHub-hosted runners with network restrictions

6. Implement egress filtering for self-hosted runners

