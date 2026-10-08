# Agent Documentation for action-auditor

This document provides comprehensive information for AI agents working with the actsense codebase.

## Project Overview

**actsense** is a Workflow Security Auditor. It currently supports GitHub Actions and is structured so other CI workflow platforms can be added. For GitHub Actions it:
- Analyzes GitHub Actions workflows and their dependencies
- Detects 65+ security vulnerabilities and best practice violations
- Visualizes action dependencies in an interactive graph
- Provides detailed security recommendations with links to comprehensive documentation

## Architecture

### Backend (Python/FastAPI)
- **FastAPI** web framework
- **Async/await** for concurrent operations
- **GitHub API** integration for fetching repository data
- **YAML parsing** for workflow files
- **Graph-based** dependency tracking
- **Facade pattern** for security checks (SecurityAuditor delegates to rules module)

### Frontend (React)
- **React 18** with functional components
- **ReactFlow** for graph visualization
- **Vite** for build tooling
- **Modern CSS** with component-scoped styles

### Documentation (Hugo)
- **Hugo static site generator** (Hextra theme)
- **Markdown-based** vulnerability documentation
- **Hosted at actsense.dev**

## Code Generation and Structure

### Code is Manually Written (Not Auto-Generated)

All code in this project is **manually written**, not auto-generated. The architecture follows these patterns:

1. **Rules Module Pattern**: Security checks are implemented in `backend/rules/security.py`
2. **Facade Pattern**: `backend/security_auditor.py` provides a facade that delegates to the rules module
3. **Separation of Concerns**: 
   - Rules contain the actual check logic
   - SecurityAuditor provides a clean API and orchestrates checks
   - Tests verify both layers independently

### Project Structure

```
backend/
├── main.py                 # FastAPI application entry point
├── security_auditor.py     # Facade for security checks (delegates to rules)
├── rules/
│   └── security.py         # Actual security check implementations (65+ checks)
├── github_client.py        # GitHub API client
├── workflow_parser.py      # YAML parsing and action extraction
├── graph_builder.py        # Dependency graph construction
├── repo_cloner.py          # Git repository cloning
├── analysis_storage.py     # JSON-based analysis persistence
├── config_loader.py        # Configuration loading (trusted publishers)
├── config.yaml             # Configuration file (trusted action publishers)
└── tests/                  # Comprehensive test suite
    ├── conftest.py         # Pytest fixtures
    ├── test_security_rules.py    # Tests for rules module
    ├── test_best_practices.py     # Tests for best practices
    ├── test_security_auditor.py   # Integration tests for facade
    └── ...

frontend/
└── src/
    ├── App.jsx                    # Main application
    └── components/
        ├── ActionGraph.jsx        # Graph visualization
        ├── NodeDetailsPanel.jsx  # Node details display
        ├── IssueDetailsModal.jsx  # Issue details modal
        └── ...

docs/
├── hugo.yaml                      # Hugo site configuration
├── content/
│   └── vulnerabilities/           # Markdown files for each vulnerability (67 files)
│       ├── unpinned_version.md
│       ├── potential_hardcoded_secret.md
│       └── ...
└── public/                        # Generated static site (gitignored)
```

## Key Components

### Backend Modules

#### `main.py`
- FastAPI application entry point
- API endpoints: `/api/audit`, `/api/analyses`, `/api/health`
- Repository and action auditing orchestration
- Dependency resolution logic
- Serves frontend static files in production

#### `github_client.py`
- GitHub API client with authentication
- Methods:
  - `get_repo_contents()` - Get repository files
  - `get_file_content()` - Get file content
  - `get_workflows()` - Get workflow files
  - `get_action_metadata()` - Get action.yml files
  - `get_latest_tag()` - Get latest version tag
  - `get_commit_date()` - Get commit date for SHA
  - `get_latest_tag_commit_date()` - Get latest tag's commit date
  - `parse_action_reference()` - Parse action references

#### `security_auditor.py` (Facade)
- **Facade pattern** that delegates to `rules/security.py`
- Provides clean API for security checks
- Main methods:
  - `audit_workflow()` - Audit a workflow file (async, orchestrates all checks)
  - `audit_action()` - Audit a single action
  - All `check_*()` methods delegate to `rules.security` module
- **Note**: This file contains mostly delegation code. Actual check logic is in `rules/security.py`

#### `rules/security.py` (Implementation)
- **Contains all actual security check implementations**
- 65+ security check functions
- Each check function:
  - Takes workflow/action data as input
  - Returns list of issue dictionaries
  - Each issue includes: type, severity, message, evidence, recommendation
  - Evidence includes link to actsense.dev documentation
- Functions are organized by category (secrets, permissions, injection, etc.)

#### `workflow_parser.py`
- YAML parsing and extraction
- Action reference detection
- Dependency extraction from composite actions
- Parses both workflow files and action.yml files

#### `graph_builder.py`
- Dependency graph construction
- Node and edge management
- Issue attachment to nodes
- Statistics calculation
- Redundant edge removal

#### `repo_cloner.py`
- Git repository cloning (alternative to API method)
- Local file access
- Cleanup management

#### `analysis_storage.py`
- JSON-based analysis persistence
- UUID-based storage
- Query and deletion operations

#### `config_loader.py` & `config.yaml`
- Loads trusted action publishers from `config.yaml`
- Used by security checks to determine if actions are trusted
- Format: list of publisher prefixes (e.g., "actions/", "github/")

### Frontend Components

#### `App.jsx`
- Main application state management
- API communication
- View mode switching
- Share link parsing

#### `ActionGraph.jsx`
- ReactFlow graph visualization
- Node selection and filtering
- Interactive controls

#### `NodeDetailsPanel.jsx`
- Detailed node information display
- Security issues list
- Issue details modal integration
- GitHub link generation

#### `IssueDetailsModal.jsx`
- Security issue details display
- Evidence display
- Links to actsense.dev documentation
- Custom display sections for specific issue types

## Dependency Graph Resolution

`resolve_action_dependencies()` in `main.py` builds the graph. Keep these invariants:

- **Fetch at the pinned ref.** `action.yml`, reusable workflows and Dockerfiles are read at the ref the workflow pins (`get_file_content(..., ref=ref)`), never the default branch.
- **Local references are followed.** `./.github/actions/x` and `./.github/workflows/y.yml` in the audited repo resolve at its default branch; nested local reusable workflows resolve in the called workflow's repo and ref. `./` inside a composite action refers to the caller's workspace and is not followed.
- **API errors are not "missing".** Only a confirmed 404 produces `missing_action_repository`; rate limits and network errors continue resolution.
- **Direct edges are kept.** `GraphBuilder.get_graph_data()` does not apply transitive reduction; an edge means "A directly references B".
- **One `GitHubClient` per audit** memoizes GET responses and pools connections; close it with `_close_client()`.
- Depth limit: `DEFAULT_MAX_DEPTH` (10, matching GitHub's reusable-workflow nesting cap).

## Auto-fix Pinning (pin.actsense.dev)

`/api/audit/fix` resolves tags to commit SHAs and images to digests through `pin_client.py` (`GET https://pin.actsense.dev/api/resolve?q=...`), falling back to the GitHub API. Unresolvable pins are emitted with `"manual": true` and a `<SHA>`/`<digest>` placeholder, and the editor's Apply All skips them. Set `PIN_API_URL=""` to disable the service.

## Security Checks Reference

### Severity Levels
- **critical**: Immediate security risk
- **high**: Significant security concern
- **medium**: Moderate security issue
- **low**: Minor security concern

### Issue Types by Category

#### Action Pinning & Immutability
- `unpinned_version` (high) - Action not pinned to version/tag/SHA
- `no_hash_pinning` (medium) - Uses tag instead of commit SHA
- `short_hash_pinning` (low) - Uses short SHA instead of full SHA
- `older_action_version` (medium) - Action uses older version than latest
- `inconsistent_action_version` (low) - Same action with different versions across workflows
- `unpinnable_docker_image` (high) - Docker action with mutable tag
- `unpinnable_composite_subaction` (high) - Composite action with unpinned sub-actions
- `unpinnable_javascript_resources` (high) - JavaScript action downloads without checksums

#### Permissions & Access Control
- `overly_permissive` (high) - Write permissions to contents
- `github_token_write_all` (high) - GITHUB_TOKEN write-all permissions
- `github_token_write_permissions` (medium) - GITHUB_TOKEN write permissions
- `excessive_write_permissions` (medium) - Excessive write permissions on read-only workflows
- `self_hosted_runner` (low) - Self-hosted runners
- `branch_protection_bypass` (high) - Branch protection bypass

#### Secrets & Credentials
- `potential_hardcoded_secret` (critical) - Hardcoded secrets detected
- `potential_hardcoded_cloud_credentials` (critical) - Hardcoded cloud credentials
- `optional_secret_input` (low) - Optional secret inputs without a safe default
- `long_term_aws_credentials` (high) - AWS credentials instead of OIDC
- `long_term_azure_credentials` (high) - Azure credentials instead of OIDC
- `long_term_gcp_credentials` (high) - GCP credentials instead of OIDC
- `environment_with_secrets` (low) - Environment used with secrets
- `secret_in_environment` (medium) - Secrets in environment variables

#### Workflow Security
- `dangerous_event` (high) - pull_request_target, workflow_run events
- `insecure_pull_request_target` (critical) - Insecure pull_request_target usage
- `unsafe_checkout` (high; medium when left at the default in a job that uploads artifacts) - Checkout with persisted credentials
- `unsafe_checkout_ref` (medium) - Potentially unsafe checkout ref
- `checkout_full_history` (low) - Fetches full git history
- `potential_script_injection` (high) - Script injection risk
- `script_injection` (critical) - Injection into github-script or PowerShell
- `shell_injection` (high/critical) - Shell injection vulnerability
- `code_injection_via_input` (high) - Code injection via workflow inputs
- `unvalidated_workflow_input` (medium) - Unvalidated workflow dispatch inputs
- `unsafe_shell` (medium) - Custom bash shell template (`bash {0}`) without -e; `shell: bash` is already safe
- `malicious_curl_pipe_bash` (critical) - Curl/wget piped to bash
- `malicious_base64_decode` (critical) - Base64 decode execution
- `obfuscation_detection` (high) - Code obfuscation patterns

#### Supply Chain Security
- `untrusted_third_party_action` (medium) - Third-party action from untrusted publisher
- `untrusted_action_unpinned` (high) - Untrusted action not pinned
- `untrusted_action_source` (medium) - Action from untrusted source
- `typosquatting_action` (high) - Potential typosquatting in action names
- `deprecated_action` (medium) - Retired action majors, archived repositories, node12/node16 runtimes
- `missing_action_repository` (critical) - Action repository doesn't exist
- `unpinned_dockerfile_dependencies` (medium) - Dockerfile installs unpinned packages
- `unpinned_dockerfile_resources` (medium) - Dockerfile downloads without checksums
- `unpinned_npm_packages` (medium) - NPM packages without version locking
- `unpinned_python_packages` (medium) - Python packages without version pinning
- `unpinned_external_resources` (medium) - External resources without checksums
- `unfiltered_network_traffic` (low) - Network operations without egress filtering (informational)
- `no_file_tampering_protection` (medium) - File modifications without protection

#### Self-Hosted Runner Security
- `self_hosted_runner_pr_exposure` (critical) - Self-hosted runner exposed to PRs in public repo
- `self_hosted_runner_issue_exposure` (high) - Self-hosted runner exposed to issues
- `self_hosted_runner_write_all` (high) - Self-hosted runner with write-all permissions
- `runner_label_confusion` (high) - Runner label confusion attack
- `public_repo_self_hosted_secrets` (critical) - Secrets in self-hosted runner in public repo
- `self_hosted_runner_secrets_in_run` (high) - Secrets in run commands
- `self_hosted_runner_network_risk` (medium) - Network access risks

#### Best Practices
- `long_artifact_retention` (low) - Artifact retention > 90 days
- `secrets_in_matrix` (high) - Secrets used in matrix strategy
- `large_matrix` (low) - Matrix with > 100 combinations
- `insufficient_audit_logging` (medium) - Missing audit logs
- `continue_on_error_critical_job` (medium) - Continue-on-error in critical jobs
- `artifact_exposure_risk` (high) - Artifact exposure risk from unsafe upload configurations
- `token_permission_escalation` (high) - Token permission escalation
- `cross_repository_access` (high) - Unauthorized cross-repository access
- `environment_bypass_risk` (high) - Environment protection bypass

## How to Add a New Security Check

### Complete Workflow

Adding a new security check requires changes in **4 places**:

1. **Implement the check in `backend/rules/security.py`**
2. **Add facade method in `backend/security_auditor.py`**
3. **Add the check to `audit_workflow()` or `audit_action()`**
4. **Write tests in `backend/tests/`**
5. **Create documentation in `docs/content/vulnerabilities/`**

### Step-by-Step Guide

#### Step 1: Implement Check in `rules/security.py`

Add a new function in `backend/rules/security.py`:

```python
def check_your_new_vulnerability(workflow: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Check for your new security vulnerability."""
    issues = []
    
    # Your check logic here
    jobs = workflow.get("jobs", {})
    for job_name, job in jobs.items():
        # Check for vulnerability condition
        if vulnerability_condition:
            issues.append({
                "type": "your_vulnerability_type",
                "severity": "high",  # or "critical", "medium", "low"
                "message": f"Job '{job_name}' has vulnerability X",
                "job": job_name,
                "evidence": {
                    "job": job_name,
                    "specific_evidence": "...",
                    "vulnerability": f"For detailed information about this vulnerability, visit: https://actsense.dev/vulnerabilities/your_vulnerability_type"
                },
                "recommendation": f"For mitigation steps, visit: https://actsense.dev/vulnerabilities/your_vulnerability_type"
            })
    
    return issues
```

**Key Requirements:**
- Function must return `List[Dict[str, Any]]`
- Each issue dict must include:
  - `type`: Unique identifier (snake_case)
  - `severity`: "critical", "high", "medium", or "low"
  - `message`: Human-readable description
  - `evidence`: Dict with details and link to actsense.dev
  - `recommendation`: Link to actsense.dev for mitigation

#### Step 2: Add Facade Method in `security_auditor.py`

Add a static method that delegates to the rules module:

```python
@staticmethod
def check_your_new_vulnerability(workflow: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Check for your new security vulnerability."""
    return security_rules.check_your_new_vulnerability(workflow)
```

#### Step 3: Integrate into Audit Flow

Add the check to `audit_workflow()` in `security_auditor.py`:

```python
# In audit_workflow() method, add:
your_issues = SecurityAuditor.check_your_new_vulnerability(workflow)
if content and your_issues:
    for issue in your_issues:
        # Add line number if possible
        line_num = security_rules._find_line_number(content, "search_term", issue.get("job", ""))
        if line_num:
            issue["line_number"] = line_num
issues.extend(your_issues)
```

For **async checks** (require GitHub API):

```python
# In audit_workflow() method:
your_async_issues = await SecurityAuditor.check_your_async_check(workflow, client)
if content and your_async_issues:
    # Add line numbers...
issues.extend(your_async_issues)
```

For **action-level checks**, add to `audit_action()`:

```python
# In audit_action() method:
issues.extend(security_rules.check_your_action_check(action_yml, action_ref))
```

#### Step 4: Write Tests

Create tests in `backend/tests/test_security_rules.py` or appropriate test file:

```python
class TestYourNewVulnerability:
    """Tests for your new vulnerability check."""
    
    def test_vulnerability_detected(self):
        """Test detection of vulnerability."""
        workflow = {
            "name": "Test Workflow",
            "on": ["push"],
            "jobs": {
                "test": {
                    "runs-on": "ubuntu-latest",
                    "steps": [
                        {
                            "name": "Test",
                            "run": "vulnerable_command"
                        }
                    ]
                }
            }
        }
        
        issues = security_rules.check_your_new_vulnerability(workflow)
        
        vuln_issues = [i for i in issues if i["type"] == "your_vulnerability_type"]
        assert len(vuln_issues) > 0
        assert vuln_issues[0]["severity"] == "high"
        assert "actsense.dev/vulnerabilities/your_vulnerability_type" in vuln_issues[0]["evidence"]["vulnerability"]
    
    def test_no_vulnerability(self):
        """Test workflow without vulnerability."""
        workflow = {
            "name": "Safe Workflow",
            "on": ["push"],
            "jobs": {
                "test": {
                    "runs-on": "ubuntu-latest",
                    "steps": [
                        {
                            "name": "Test",
                            "run": "safe_command"
                        }
                    ]
                }
            }
        }
        
        issues = security_rules.check_your_new_vulnerability(workflow)
        vuln_issues = [i for i in issues if i["type"] == "your_vulnerability_type"]
        assert len(vuln_issues) == 0
```

**Test Requirements:**
- Test both positive (vulnerability detected) and negative (no vulnerability) cases
- Verify severity level
- Verify actsense.dev link is present
- Use fixtures from `conftest.py` when possible

#### Step 5: Create Documentation

Create a new markdown file in `docs/content/vulnerabilities/your_vulnerability_type.md`:

```markdown
# Your Vulnerability Type

## Description

Clear explanation of the vulnerability, why it's dangerous, and what it allows attackers to do.

## Vulnerable Instance

- Condition 1 that makes workflow vulnerable
- Condition 2 that makes workflow vulnerable

```yaml
name: Vulnerable Workflow
on: [push]
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - run: vulnerable_command
```

## Mitigation Strategies

1. **Strategy 1**: Detailed explanation
2. **Strategy 2**: Detailed explanation
3. **Strategy 3**: Detailed explanation

### Secure Version

```diff
 name: Secure Workflow
 on: [push]
 jobs:
   build:
     runs-on: ubuntu-latest
     steps:
-      - run: vulnerable_command
+      - run: secure_command
```

## Impact

| Dimension | Severity | Notes |
| --- | --- | --- |
| Likelihood | ![High](https://img.shields.io/badge/-High-orange?style=flat-square) | Explanation |
| Risk | ![High](https://img.shields.io/badge/-High-orange?style=flat-square) | Explanation |
| Blast radius | ![Wide](https://img.shields.io/badge/-Wide-yellow?style=flat-square) | Explanation |

## References

- Reference 1
- Reference 2
```

**Documentation Requirements:**
- File name must match issue type exactly: `your_vulnerability_type.md`
- Include vulnerable and secure examples
- Include impact assessment table
- Include references to authoritative sources

#### Step 5b: Add it to the checks explorer

Add a `- [Title](/vulnerabilities/your_vulnerability_type/)` line under the right `###` category in `docs/content/vulnerabilities/_index.md`, then regenerate the data behind the explorer and the check-page rail:

```bash
python3 docs/scripts/build_checks_data.py
```

It reads categories from `_index.md`, titles and summaries from each check page, and severities from the backend rules, and writes `docs/data/checks.json`. If a rule's severity is computed at runtime, add it to `DYNAMIC_SEVERITIES` in the script (it fails loudly otherwise).

#### Step 6: Build Documentation

After creating the markdown file, build the Hugo site:

```bash
cd docs
hugo --config hugo.yaml
```

The documentation will be available at `https://actsense.dev/vulnerabilities/your_vulnerability_type` once deployed.

### Frontend Integration

The frontend automatically links to documentation based on issue type. The `IssueDetailsModal.jsx` component:

1. Formats issue type as title (converts snake_case to Title Case)
2. Generates actsense.dev URL: `https://actsense.dev/vulnerabilities/{issue_type}`
3. Displays evidence fields
4. Shows link to documentation

**No frontend changes needed** unless you want custom display for specific issue types. To add custom display:

```javascript
// In IssueDetailsModal.jsx
{issue.type === 'your_vulnerability_type' && issue.customData && (
  <div className="issue-modal-section">
    <h4>Custom Display</h4>
    {/* Your custom display */}
  </div>
)}
```

## Testing

### Test Structure

Tests are organized in `backend/tests/`:

- `conftest.py` - Pytest fixtures for creating test workflows
- `test_security_rules.py` - Tests for security vulnerability checks
- `test_best_practices.py` - Tests for best practice checks
- `test_security_auditor.py` - Integration tests for SecurityAuditor facade
- `test_*.py` - Tests for other modules

### Running Tests

```bash
cd backend
source venv/bin/activate
pytest
```

### Test Coverage

The test suite covers:
- **65+ vulnerability types**
- **Positive cases** (vulnerability detected)
- **Negative cases** (no vulnerability)
- **Severity verification**
- **Documentation link verification**
- **Integration tests** for facade pattern

### Writing Tests

1. **Use fixtures** from `conftest.py` when possible
2. **Test both positive and negative cases**
3. **Verify severity levels**
4. **Verify actsense.dev links**
5. **Test edge cases** (empty workflows, missing fields, etc.)

Example test structure:

```python
class TestYourCheck:
    def test_vulnerability_detected(self, workflow_fixture):
        issues = security_rules.check_your_check(workflow_fixture)
        assert len([i for i in issues if i["type"] == "your_type"]) > 0
    
    def test_no_vulnerability(self, safe_workflow_fixture):
        issues = security_rules.check_your_check(safe_workflow_fixture)
        assert len([i for i in issues if i["type"] == "your_type"]) == 0
```

## Documentation System

### Hugo Static Site Generator

Documentation is built using **Hugo** with the **Hextra** theme:

- **Source**: `docs/content/vulnerabilities/*.md`
- **Config**: `docs/hugo.yaml`
- **Output**: `docs/public/` (gitignored, generated)
- **Hosted**: actsense.dev

### Documentation Structure

Each vulnerability has a markdown file:
- **Location**: `docs/content/vulnerabilities/{issue_type}.md`
- **Format**: Markdown with YAML front matter (optional)
- **Required sections**: Description, Vulnerable Instance, Mitigation Strategies, Impact, References

### Building Documentation

```bash
cd docs
hugo --config hugo.yaml
```

Output goes to `docs/public/` directory.

### Documentation Features

- **Search**: FlexSearch integration
- **Dark mode**: Theme toggle
- **Edit links**: Links to GitHub for editing
- **Last modified**: Git-based last modified dates
- **Responsive**: Mobile-friendly design

### Adding Documentation

1. Create markdown file: `docs/content/vulnerabilities/your_type.md`
2. Follow the template structure
3. Build with Hugo: `hugo --config hugo.yaml`
4. Verify locally: `hugo server --config hugo.yaml`
5. Deploy to actsense.dev

## Data Flow

### Audit Request Flow

1. User submits repository/action via frontend
2. Backend receives request at `/api/audit`
3. `audit_repository()` or `resolve_action_dependencies()` called
4. Workflows parsed using `WorkflowParser`
5. Actions extracted from workflows
6. Security checks run via `SecurityAuditor.audit_workflow()`:
   - Orchestrates all checks from `rules/security.py`
   - Handles async checks (GitHub API calls)
   - Adds line numbers to issues when content available
7. Dependency graph built using `GraphBuilder`
8. Issues attached to nodes
9. Results stored via `AnalysisStorage`
10. Results returned to frontend

### Version Checking Flow

1. During workflow audit, actions collected
2. `check_older_action_versions()` called (async)
3. For each action with version tag:
   - Fetch latest tag from GitHub API
   - Compare versions semantically
   - Flag if outdated
4. For each action with commit hash:
   - Fetch commit date
   - Compare to latest tag's commit date
   - Flag if >1 year old
5. After all workflows processed:
   - `check_inconsistent_action_versions()` called
   - Detects version inconsistencies
   - Creates repository-level issues

## API Endpoints

### POST `/api/audit`
Audit a repository or action.

**Request**:
```json
{
  "repository": "owner/repo",
  "action": "owner/repo@v1",
  "github_token": "ghp_...",
  "use_clone": false
}
```

**Response**:
```json
{
  "id": "uuid",
  "graph": {
    "nodes": [...],
    "edges": [...],
    "issues": {...}
  },
  "statistics": {...}
}
```

### GET `/api/analyses`
List saved analyses (optional: filter by repository, limit results).

### GET `/api/analyses/{id}`
Get specific analysis by ID.

### DELETE `/api/analyses/{id}`
Delete analysis by ID.

### POST `/api/analyses/{id}/dismissals`
Dismiss a finding (`{"fingerprint": "...", "reason": "..."}`) for the analysis's repository or action. Returns the analysis with dismissals applied.

### DELETE `/api/analyses/{id}/dismissals/{fingerprint}`
Restore a dismissed finding. Returns the analysis with dismissals applied.

### GET `/api/dismissals?target=owner/repo`
List dismissals for a repository or action.

### GET `/api/orgs/{org}/repos`
Repositories of an organization (falling back to a user account) for the repository picker, most recently pushed first, with `owner_type` (`organization` or `user`) and `private_included`. A user's listing holds only repositories they own, and their private ones only when the token is theirs (`/user/repos`). The token goes in the `X-GitHub-Token` header, never the URL.

### POST `/api/audit/org` and `/api/audit/org/stream`
Scan selected repositories of an organization or user: `{"org": "acme", "repositories": ["api", "acme/web"], "github_token": "...", "use_clone": false, "owner_type": "organization"}`. `owner_type` comes from the listing and only labels the scan. The stream sends `log`, one `progress` event per finished repository and a final `result`.

### GET `/api/org-scans`, GET/DELETE `/api/org-scans/{id}`
List, read or delete stored org scans. Reading one refreshes each repository's counts from its stored analysis, so later dismissals show.

### GET `/api/org-scans/{id}/findings`
Every finding and workflow file across the scan's repositories, read from the stored analyses (current dismissals apply). Each workflow file has its GitHub `url`, the `uses` it calls, and `findings`: the findings located in it, including those on the actions and images it uses. Each carries `location` (the GitHub file and `#L<line>` it comes from; findings on actions, images and packages point at the workflow line that uses them), `target` (the action at its pinned ref, for "via" findings) and `docs_url`. Findings mirrored onto several nodes appear once, by fingerprint.

## Organization Scans

`_run_org_scan()` in `main.py` runs the existing `audit_repository()` for each selected repository: at most `ORG_SCAN_CONCURRENCY` (4) at a time, at most `MAX_ORG_SCAN_REPOS` (200) per scan, all sharing one `GitHubClient` so common actions are fetched once. Each repository is stored as an ordinary analysis (graph, dismissals and history work unchanged), and the org scan record in `data/analyses/org_scans/` keeps each repository's status (`ok`, `no_workflows`, `error`, `skipped`), analysis id and counts, the totals, and an action inventory. One failing repository never stops the scan, and a workflow that could not be fetched marks its repository `error` rather than `no_workflows`. Once the GitHub rate limit is hit, repositories not yet started are `skipped` and the scan is saved with `rate_limited: true`. `backend/org_scan.py` holds the pure parts (input parsing, `summarize()`, `collect_findings()`, `build_action_inventory()`; each inventory entry has a `kind` (`action` or `reusable_workflow`) and a `publisher` (`internal`, `github` for `actions/` and `github/`, `allowlisted` for other trusted publishers in `config.yaml`, or `third_party`), and each ref lists its `usages` with file and line; the summary counts `workflow_files`), which ranks actions from untrusted publishers that are not pinned by SHA everywhere first, then actions used at more than one ref. In the UI, entering a bare name (`acme`, `@acme`, `github.com/acme`) opens the picker, and `?org-scan=<id>` links reopen a scan.

## Dismissed Findings

`backend/dismissals.py` gives every issue a `fingerprint`: a hash of its node id, type, identifying fields and message, leaving out what shifts between runs (`line_number`, `latest_version`, `days_old`, `commit_date`, digits in the message). Dismissals are stored per audit target in `data/dismissals.json` and applied when an audit is built and whenever a stored analysis is read, so one dismissal covers every run of that target. A dismissed issue carries `"dismissed": {"reason", "dismissed_at"}` and is left out of `issue_count`, node `severity` and the statistics (`dismissed_issues` counts them). If you add a volatile field to an issue, add it to `_VOLATILE_FIELDS` or dismissals of that finding won't survive a re-run.

## Configuration

### Trusted Action Publishers

Configure trusted publishers in `backend/config.yaml`:

```yaml
trusted_publishers:
  - "actions/"              # GitHub official actions
  - "github/"              # GitHub official organization
  - "microsoft/"          # Microsoft
  # Add more...
```

Actions from trusted publishers won't trigger warnings when secrets are passed to them.

## Common Patterns

### Extracting Actions from Workflow
```python
actions = parser.extract_actions(workflow)
```

### Parsing Action Reference
```python
owner, repo, ref, subdir = client.parse_action_reference(action_ref)
```

### Adding Issues to Node
```python
graph.add_issues_to_node(node_id, issues)
```

### Version Comparison
```python
# Parse version
version_tuple = (major, minor, patch)
# Compare
if current_version < latest_version:
    # Flag as outdated
```

### Finding Line Numbers
```python
line_num = security_rules._find_line_number(content, "search_term", context)
if line_num:
    issue["line_number"] = line_num
```

## File Locations

- **Security check implementations**: `backend/rules/security.py`
- **Security check facade**: `backend/security_auditor.py`
- **GitHub API client**: `backend/github_client.py`
- **Workflow parsing**: `backend/workflow_parser.py`
- **Main API**: `backend/main.py`
- **Frontend components**: `frontend/src/components/`
- **Issue details modal**: `frontend/src/components/IssueDetailsModal.jsx`
- **Vulnerability documentation**: `docs/content/vulnerabilities/`
- **Test fixtures**: `backend/tests/conftest.py`
- **Test files**: `backend/tests/test_*.py`
- **Configuration**: `backend/config.yaml`

## Key Design Decisions

1. **Facade Pattern**: SecurityAuditor provides clean API, rules module contains implementation
2. **Async version checking**: Version checks require GitHub API calls, so they're async
3. **Repository-level issues**: Inconsistency checks span multiple workflows, so attached to repo node
4. **Fallback heuristics**: When API calls fail, use heuristics (e.g., flag v1/v2 as potentially outdated)
5. **Semantic version comparison**: Properly compares version numbers, not just strings
6. **Commit date comparison**: For hashes, compares commit dates rather than trying to determine version
7. **Evidence-based issues**: All issues include evidence dict with link to actsense.dev documentation
8. **Line number tracking**: Issues include line numbers when workflow content is available
9. **Modular rules**: Each check is a separate function, easy to test and maintain
10. **Documentation-driven**: Each vulnerability has comprehensive markdown documentation

## Testing Considerations

- **Async operations**: Ensure proper awaiting of async checks
- **API rate limits**: Be mindful of GitHub API rate limits
- **Error handling**: Gracefully handle API failures
- **Edge cases**: Empty workflows, missing actions, invalid versions
- **Fixtures**: Use conftest.py fixtures for common workflow patterns
- **Coverage**: Test both positive and negative cases

## Future Enhancements

- Caching of version lookups to reduce API calls
- Batch API requests for better performance
- More granular version comparison (e.g., flag if >6 months old)
- Support for action version policies (e.g., "must use v3+")
- Automated documentation generation from code
- More comprehensive test coverage reporting
