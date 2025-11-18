# Checkout Full History

## Vulnerability Description


Checkout fetches the full git history (fetch-depth: 0). This may expose:

- Sensitive information from old commits

- Hardcoded secrets that were removed in later commits

- Historical code that may contain vulnerabilities

- Large repository size, slowing down workflows


While not always a security issue, fetching full history:

- Increases the attack surface

- May expose information that should remain in history

- Slows down workflow execution


## Recommendation


Use fetch-depth: 1 to only fetch the latest commit:


1. Update the checkout step:

- uses: actions/checkout@v4

with:

fetch-depth: 1  # Only fetch latest commit


2. If you need history for specific operations:

- Use fetch-depth: 1 by default

- Fetch additional history only when needed

- Consider using shallow clones with specific depth


3. If full history is required:

- Document why its necessary

- Ensure no sensitive data is in history

- Consider cleaning history if secrets were committed


4. Review if full history is truly needed for the workflow

