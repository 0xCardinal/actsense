# Long Artifact Retention

## Vulnerability Description


Artifact retention is set to {retention_days} days, which exceeds the recommended 90-day limit.
This may:

- Violate data retention policies and compliance requirements

- Increase storage costs unnecessarily

- Expose artifacts containing sensitive data for extended periods

- Make it harder to comply with data deletion requests


While not a direct security vulnerability, long artifact retention:

- May contain sensitive information that should be deleted sooner

- Increases the window of exposure if artifacts are compromised

- May violate GDPR, CCPA, or other data protection regulations


## Recommendation


Set artifact retention to 90 days or less:


1. Update the upload-artifact step:

- uses: actions/upload-artifact@v4

with:

retention-days: 90  # Or less


2. If longer retention is required:

- Document the business justification

- Ensure compliance with data retention policies

- Consider using external storage for long-term retention


3. Review all artifact retention settings

4. Ensure artifacts dont contain sensitive data

