# No Hash Pinning

## Vulnerability Description


Version tag {ref} is mutable and can be updated by the action maintainer.
This means:

- The tag can be moved to point to a different commit

- The tag can be deleted and recreated

- If the action repository is compromised, an attacker could move the tag to malicious code

- Your workflow would automatically use the new (potentially malicious) version on the next run


Commit SHA hashes are immutable - once created, they cannot be changed. This provides
guaranteed immutability and prevents supply chain attacks through tag manipulation.


## Recommendation


Replace tag {ref} with the full 40-character commit SHA:


1. Find the commit SHA for tag {ref}:

- Visit: https://github.com/{action_name}/releases/tag/{ref}

- Or: https://github.com/{action_name}/tree/{ref}

- Click on the commit link to see the full SHA


2. Copy the full 40-character commit SHA (e.g., 8f4b7f84884ec3e152e95e913f196d7a537752ca)


3. Update your workflow:

Change: {action_ref}

To: {action_name}@8f4b7f84884ec3e152e95e913f196d7a537752ca


4. Verify the SHA is correct:

- The SHA should be exactly 40 hexadecimal characters

- You can verify by visiting: https://github.com/{action_name}/commit/<sha>


Alternative: Use GitHub CLI to get the SHA:

gh api repos/{action_name}/git/refs/tags/{ref} | jq -r .object.sha

