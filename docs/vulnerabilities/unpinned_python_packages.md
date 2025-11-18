# Unpinned Python Packages

## Vulnerability Description


Composite action installs Python packages without version pinning.
This creates security risks:

- Package versions can change between runs

- Newer versions may introduce security vulnerabilities

- Builds are not reproducible

- Difficult to track and fix security issues


Security concerns:

- Supply chain attacks through compromised packages

- Unintended package updates with vulnerabilities

- Non-reproducible builds

- Difficult to audit package versions


## Recommendation


Pin all Python package versions:


1. Pin packages to specific versions:

run: pip install package==1.2.3

# Instead of: pip install package


2. Use requirements.txt with pinned versions:

run: |

pip install -r requirements.txt

# requirements.txt:

# package1==1.2.3

# package2==2.3.4


3. Use pip-tools to generate requirements:

pip-compile requirements.in

# Generates requirements.txt with pinned versions


4. Regularly update and review pinned versions

5. Use security scanning tools to check for vulnerabilities

