# Unpinned Javascript Resources

## Vulnerability Description


JavaScript action downloads external resources without checksum verification.
This creates supply chain security risks:

- Downloaded resources can be tampered with

- Man-in-the-middle attacks can replace resources

- Compromised download servers can serve malicious files

- Cannot verify resource integrity

- Malicious code can be injected into the action


Security concerns:

- Supply chain attacks through compromised downloads

- Malicious files can be executed by the action

- Resource integrity cannot be verified

- Actions are vulnerable to network attacks


## Recommendation


Verify checksums for all downloaded external resources:


1. Download and verify checksum in JavaScript:

const crypto = require(crypto);

const fs = require(fs);

const https = require(https);



// Download file

// Calculate SHA256

const hash = crypto.createHash(sha256);

const data = fs.readFileSync(downloaded-file);

const calculatedHash = hash.update(data).digest(hex);



// Verify against expected hash

if (calculatedHash != expectedHash) {{

throw new Error(Checksum verification failed);

}}


2. Use SHA256 checksums (preferred):

- Store expected checksums securely

- Verify checksums before using downloaded files

- Fail the action if checksums dont match


3. Store checksums securely:

- Include checksums in the action code

- Or use a checksums file in the repository

- Verify checksums match expected values


4. Use HTTPS for all downloads

5. Review all external resource downloads in the action

