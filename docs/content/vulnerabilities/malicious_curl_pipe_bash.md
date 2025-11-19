# Malicious Curl Pipe Bash

## Vulnerability Description


Detected {description} in the workflow. This is a critical security vulnerability because:

- Code is downloaded from the internet and executed without verification

- If the remote server is compromised, malicious code will be executed

- Theres no way to verify the integrity of the downloaded script

- Attackers can inject arbitrary commands through the downloaded script

- The script runs with the workflows permissions, potentially accessing secrets


Attack scenarios:

- Attacker compromises the remote server hosting the script

- Attacker performs a man-in-the-middle attack during download

- Attacker redirects the URL to a malicious script

- Malicious script exfiltrates secrets, modifies files, or performs unauthorized actions


## Recommendation


Never pipe curl/wget directly to shell. Instead:


1. Download and verify the script first:

- name: Download script

run: |

curl -o script.sh https://example.com/script.sh

# Verify checksum

echo \expected_checksum script.sh\ | sha256sum -c

# Then execute

bash script.sh


2. Use pinned GitHub Actions instead:

- uses: actions/checkout@v4  # Pinned version

- uses: trusted-action@v1.0.0  # Use trusted actions


3. If you must download scripts:

- Use checksums to verify integrity

- Review the script content before execution

- Use HTTPS only

- Pin to specific script versions/commits

- Run in a sandboxed environment


4. Consider using GitHub Actions from trusted sources instead of shell scripts

