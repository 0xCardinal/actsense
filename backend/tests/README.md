# Test Suite for GitHub Actions Security Auditor

This directory contains comprehensive tests for all vulnerability checks in the security auditor.

## Test Structure

- `conftest.py` - Pytest fixtures and configuration
- `test_security_rules.py` - Tests for security vulnerability checks
- `test_best_practices.py` - Tests for best practice checks
- `test_security_auditor.py` - Integration tests for SecurityAuditor facade

## Running Tests

### Setup

1. Activate the virtual environment:
```bash
cd backend
source venv/bin/activate
```

2. Install test dependencies (if not already installed):
```bash
pip install -r requirements.txt
```

### Run All Tests

```bash
cd backend
source venv/bin/activate
pytest
```

### Run Specific Test Files

```bash
# Security rules tests
pytest tests/test_security_rules.py

# Best practices tests
pytest tests/test_best_practices.py

# Integration tests
pytest tests/test_security_auditor.py
```

### Run Specific Test Classes

```bash
pytest tests/test_security_rules.py::TestSecretsInWorkflow
```

### Run Specific Tests

```bash
pytest tests/test_security_rules.py::TestSecretsInWorkflow::test_potential_hardcoded_secret
```

### Verbose Output

```bash
pytest -v
```

### With Coverage

```bash
pip install pytest-cov
pytest --cov=. --cov-report=html
```

## Test Coverage

The test suite covers all 65+ vulnerability types:

### Security Vulnerabilities
- Hardcoded secrets
- Long-term credentials (AWS, Azure, GCP)
- Self-hosted runner vulnerabilities
- Dangerous workflow events
- Unsafe checkout actions
- Script injection (shell, PowerShell, JavaScript)
- Malicious patterns (curl pipe bash, base64 decode)
- Artifact vulnerabilities
- Token permission escalation
- Cross-repository access
- Environment bypass
- Secrets access to untrusted actions
- Network traffic filtering
- File tampering protection
- Branch protection bypass
- Code injection via inputs
- Typosquatting actions
- Untrusted third-party actions
- And more...

### Best Practices
- Unpinned action versions
- Hash pinning
- Older action versions
- Inconsistent versions
- Permission checks
- Matrix strategy
- Workflow dispatch inputs
- Artifact retention
- Environment secrets
- Deprecated actions
- Continue-on-error
- Audit logging
- Unpinnable actions (Docker, composite, JavaScript)
- Unpinned packages (npm, Python)
- And more...

## Writing New Tests

When adding new vulnerability checks:

1. Add a fixture in `conftest.py` if needed
2. Add test class in appropriate test file
3. Test both positive (vulnerability detected) and negative (no vulnerability) cases
4. Verify that the vulnerability link to actsense.dev is present
5. Check severity levels are appropriate

Example:

```python
def test_new_vulnerability(self, workflow_with_new_vulnerability):
    """Test detection of new vulnerability."""
    issues = security_rules.check_new_vulnerability(workflow_with_new_vulnerability)
    
    vuln_issues = [i for i in issues if i["type"] == "new_vulnerability"]
    assert len(vuln_issues) > 0
    assert vuln_issues[0]["severity"] == "high"
    assert "actsense.dev/vulnerabilities/new_vulnerability" in vuln_issues[0]["evidence"]["vulnerability"]
```


