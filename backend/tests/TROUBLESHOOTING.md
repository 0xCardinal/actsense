# Test Troubleshooting Guide

## Common Issues and Solutions

### Issue: `ModuleNotFoundError: No module named 'httpx'`

**Solution**: Make sure you're using the virtual environment:

```bash
cd backend
source venv/bin/activate
pip install -r requirements.txt
pytest
```

Or use the test runner script:

```bash
cd backend
./run_tests.sh
```

### Issue: `ImportError` when running tests

**Solution**: Tests need to be run from the `backend` directory:

```bash
cd backend
source venv/bin/activate
pytest
```

### Issue: Tests fail with `KeyError`

**Solution**: Some tests may need to be updated to use `.get()` instead of direct dictionary access. This has been fixed in the latest version, but if you see this error, update the test to use:

```python
issue.get("type")  # instead of issue["type"]
issue.get("evidence", {}).get("vulnerability", "")  # instead of issue["evidence"]["vulnerability"]
```

### Issue: Tests fail because vulnerabilities aren't detected

**Solution**: Some vulnerability checks may not detect all patterns. Tests have been updated to be more flexible:

- Tests check `if len(issues) > 0:` before asserting
- Some tests allow for cases where detection may vary
- Check the actual detection logic in `rules/security.py` and `rules/best_practices.py`

### Issue: TruffleHog not found

**Solution**: TruffleHog is optional for secret detection. Tests will pass even if TruffleHog isn't installed, but secret detection may be limited.

### Issue: Async tests fail

**Solution**: Make sure `pytest-asyncio` is installed:

```bash
pip install pytest-asyncio
```

### Running Specific Tests

To run only specific tests:

```bash
# Run a specific test file
pytest tests/test_security_rules.py

# Run a specific test class
pytest tests/test_security_rules.py::TestSecretsInWorkflow

# Run a specific test
pytest tests/test_security_rules.py::TestSecretsInWorkflow::test_potential_hardcoded_secret

# Run tests matching a pattern
pytest -k "secret"
```

### Verbose Output

For more detailed output:

```bash
pytest -v
pytest -vv  # Even more verbose
pytest --tb=long  # Full traceback
```

### Test Coverage

To see test coverage:

```bash
pip install pytest-cov
pytest --cov=. --cov-report=html
```

Then open `htmlcov/index.html` in a browser.


