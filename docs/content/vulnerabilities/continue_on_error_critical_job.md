# Continue On Error Critical Job

## Vulnerability Description


Critical step {step_name} in job {job_name} has continue-on-error enabled.
This is dangerous because failures in critical operations are silently ignored.


## Recommendation


Remove continue-on-error from critical step {step_name}:


1. Update the step:

- name: {step_name}

# Remove: continue-on-error: true

run: |

# Your commands


2. If the step is truly optional, consider using conditional execution instead

