# Unpinned External Resources

## Vulnerability Description


Composite action downloads external resources without checksum verification.
This creates security risks:

- Downloaded resources can be tampered with

- Man-in-the-middle attacks can replace resources

- Compromised download servers can serve malicious files

- Cannot verify resource integrity


Security concerns:

- Supply chain attacks through compromised downloads

- Malicious files can be injected into builds

- Resource integrity cannot be verified

- Builds are vulnerable to network attacks


## Recommendation


Verify checksums for all downloaded external resources:


1. Download and verify checksum:

run: |

wget https://example.com/file.tar.gz

echo \abc123... file.tar.gz\ | sha256sum -c -

tar -xzf file.tar.gz


2. Use SHA256 checksums (preferred):

run: |

wget https://example.com/file.tar.gz

echo \<sha256-checksum> file.tar.gz\ | sha256sum -c -


3. Store checksums securely:

- Include checksums in the action code

- Or use a checksums file in the repository

- Verify checksums match expected values


4. Use HTTPS for all downloads

5. Review all external resource downloads

