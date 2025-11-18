# Self Hosted Runner

## Vulnerability Description


Job {job_name} uses self-hosted runner {runs_on_value}. Self-hosted runners pose significant security risks:

- Self-hosted runners have persistent access to your infrastructure

- If compromised, attackers can access your network and systems

- Runners can be used to exfiltrate secrets and sensitive data

- Runners may have access to internal resources and services

- Compromised runners can be used to attack other systems


Security concerns:

- Runners may not be properly isolated or secured

- Runners can be compromised through malicious workflows or actions

- Runners may have access to secrets and credentials

- Network access from runners may be unrestricted


## Recommendation


Secure self-hosted runners or use GitHub-hosted runners:


1. If possible, use GitHub-hosted runners:

runs-on: ubuntu-latest  # Or windows-latest, macos-latest


2. If self-hosted runners are necessary, implement strict security:

- Isolate runners in separate networks/VPCs

- Use minimal network access (only required endpoints)

- Regularly update and patch runner systems

- Use ephemeral runners that are destroyed after each job

- Implement network segmentation and firewall rules

- Monitor runner activity and access logs

- Use runner groups with restricted access


3. Limit secrets accessible to self-hosted runners:

- Use environment secrets with restricted access

- Rotate secrets regularly

- Use minimal permissions for GITHUB_TOKEN


4. Consider using GitHub Actions Runner Controller for better management

5. Regularly audit and review self-hosted runner security

