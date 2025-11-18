# Short Hash Pinning

## Vulnerability Description


Short SHA {ref} ({len(ref

## Recommendation


Upgrade from short SHA to full 40-character commit SHA:


1. Find the full SHA for {ref}:

- Visit: https://github.com/{action_name}/commit/{ref}

- The full SHA is displayed at the top of the commit page

- Or use: git rev-parse {ref}


2. Copy the full 40-character SHA (e.g., 8f4b7f84884ec3e152e95e913f196d7a537752ca)


3. Update your workflow:

Change: {action_ref}

To: {action_name}@8f4b7f84884ec3e152e95e913f196d7a537752ca


4. Verify the full SHA:

- Should be exactly 40 hexadecimal characters

- Verify at: https://github.com/{action_name}/commit/<full-sha>


Note: Short SHAs are acceptable but full SHAs are recommended for maximum security.

