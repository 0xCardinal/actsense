# Unfiltered Network Traffic

## Description

Workflows that perform network operations (curl, wget, ssh, etc.) without filtering or monitoring create security risks: network traffic can be used to exfiltrate secrets and sensitive data, attackers can use network operations to send credentials to external servers, and unfiltered outbound connections may violate security policies. Compromised workflows can exfiltrate secrets via network requests, and network operations can be used to establish backdoors or maintain persistent access. [^gh_actions_security]

## Vulnerable Instance

- Workflow performs network operations (curl, wget, ssh) without restrictions or monitoring.
- No filtering of outbound connections or allowed destinations.
- Compromised workflows can exfiltrate secrets via network requests.

```yaml
name: Build with Network Access
on: [push]
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - run: |
          curl https://example.com/data
          wget https://example.com/file
          # No filtering - can exfiltrate secrets
```

## Mitigation Strategies

1. **Restrict outbound network access**  
   Use network policies to limit allowed destinations, block access to external IPs except required services, and use allowlists for permitted endpoints.

2. **Monitor network traffic**  
   Log all outbound connections, set up alerts for suspicious network activity, and review network logs regularly.

3. **Use network segmentation**  
   Isolate workflows in separate network segments, use firewalls to control traffic flow, and implement network access controls.

4. **Validate network operations**  
   Review all curl/wget commands, ensure URLs are from trusted sources, and avoid using user input in network commands.

5. **Use GitHub-hosted runners with network restrictions**  
   GitHub-hosted runners have network restrictions, but be aware of what outbound connections are allowed.

6. **Implement egress filtering for self-hosted runners**  
   For self-hosted runners, implement egress filtering to block unauthorized outbound connections. Use allowlists for permitted endpoints.

### Secure Version

```yaml
name: Build with Filtered Network
on: [push]
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - name: Download from trusted source
        run: |
          # Only allowlisted endpoints
          curl -o data.json https://trusted-cdn.example.com/data
          # Verify checksum
          echo "expected_sha256" | sha256sum -c data.json
```

## Impact

| Dimension | Severity | Notes |
| --- | --- | --- |
| Likelihood | ![High](https://img.shields.io/badge/-High-orange?style=flat-square) | Network operations are common in workflows, but unfiltered access creates high risk for secret exfiltration. |
| Risk | ![High](https://img.shields.io/badge/-High-orange?style=flat-square) | Compromised workflows can exfiltrate secrets via network requests, enabling attackers to access systems and maintain persistent access. |
| Blast radius | ![Wide](https://img.shields.io/badge/-Wide-yellow?style=flat-square) | Exfiltrated secrets can affect all systems the secrets authorize, potentially including production infrastructure and services. |

## References

- GitHub Docs, "Security hardening for GitHub Actions," https://docs.github.com/en/actions/security-guides/security-hardening-for-github-actions [^gh_actions_security]

---

[^gh_actions_security]: GitHub Docs, "Security hardening for GitHub Actions," https://docs.github.com/en/actions/security-guides/security-hardening-for-github-actions
