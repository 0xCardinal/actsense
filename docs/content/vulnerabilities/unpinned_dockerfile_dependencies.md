# Unpinned Dockerfile Dependencies

## Vulnerability Description


Docker action Dockerfile installs Python packages without version pinning.
This creates security risks:

- Package versions can change between builds

- Newer versions may introduce security vulnerabilities

- Builds are not reproducible

- Difficult to track and fix security issues


Security concerns:

- Supply chain attacks through compromised packages

- Unintended package updates with vulnerabilities

- Non-reproducible builds

- Difficult to audit package versions


## Recommendation


Pin all Python package versions in Dockerfile:


1. Pin packages to specific versions:

RUN pip install package==1.2.3

# Instead of: RUN pip install package


2. Use requirements.txt with pinned versions:

COPY requirements.txt .

RUN pip install -r requirements.txt

# requirements.txt:

# package1==1.2.3

# package2==2.3.4


3. Use pip-tools to generate requirements:

pip-compile requirements.in

# Generates requirements.txt with pinned versions


4. Regularly update and review pinned versions

5. Use security scanning tools to check for vulnerabilities

