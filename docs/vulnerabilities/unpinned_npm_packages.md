# Unpinned Npm Packages

## Vulnerability Description


Composite action installs NPM packages without version locking.
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


Lock NPM package versions:


1. Use package-lock.json:

- Commit package-lock.json to the repository

- Use npm ci instead of npm install

- Ensures exact versions are installed


2. Specify exact versions in package.json:

\dependencies\: {{

\package\: \1.2.3\  # Exact version, not ^1.2.3

}}


3. Use npm ci for CI/CD:

run: npm ci  # Instead of npm install

# npm ci uses package-lock.json for exact versions


4. Regularly update and review package versions

5. Use security scanning tools to check for vulnerabilities

