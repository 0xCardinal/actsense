"""Regression tests for rule correctness: crashes, false positives, false negatives."""
import pytest
from unittest.mock import AsyncMock, MagicMock

from rules import security as r
from security_auditor import SecurityAuditor
from workflow_parser import WorkflowParser


def _wf(steps, on="push", **job):
    return {"on": on, "jobs": {"a": {"runs-on": "ubuntu-latest", "steps": steps, **job}}}


def _types(issues):
    return [i["type"] for i in issues]


class TestNoCrashOnValidShapes:
    """Valid GitHub Actions YAML must never abort the whole workflow audit."""

    @pytest.mark.asyncio
    @pytest.mark.parametrize("yaml_text", [
        "on:\n  workflow_call:\njobs:\n  a:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo\n",
        "on: [push, workflow_call]\njobs:\n  a:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo\n",
        "on: push\njobs:\n  a:\n    runs-on: ubuntu-latest\n    strategy:\n      matrix: ${{ fromJSON(needs.x.outputs.m) }}\n    steps:\n      - run: echo\n",
        "on: push\njobs:\n  a:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/upload-artifact@v4\n        with:\n          retention-days: ${{ inputs.days }}\n",
        "on:\n  workflow_dispatch:\n    inputs:\njobs:\n  a:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo\n",
        "on: push\njobs:\n  a:\n    runs-on:\n      group: large\n      labels: [linux]\n    steps:\n      - run: echo\n",
    ])
    async def test_audit_workflow_does_not_raise(self, yaml_text):
        workflow = WorkflowParser.parse_workflow(yaml_text)
        issues = await SecurityAuditor.audit_workflow(workflow, content=yaml_text)
        assert isinstance(issues, list)


class TestPullRequestTarget:
    def test_default_checkout_is_base_commit_and_safe(self):
        wf = _wf([{"uses": "actions/checkout@v4"}], on={"pull_request_target": {}})
        issues = r.check_dangerous_events(wf)
        assert "insecure_pull_request_target" not in _types(issues)
        assert "dangerous_event" in _types(issues)

    @pytest.mark.parametrize("ref", [
        "${{ github.event.pull_request.head.sha }}",
        "${{ github.head_ref }}",
        "refs/pull/${{ github.event.number }}/merge",
    ])
    def test_checkout_of_pr_code_is_critical(self, ref):
        wf = _wf([{"uses": "actions/checkout@v4", "with": {"ref": ref}}], on={"pull_request_target": {}})
        found = [i for i in r.check_dangerous_events(wf) if i["type"] == "insecure_pull_request_target"]
        assert found and found[0]["severity"] == "critical"


class TestShellAndPipes:
    def test_shell_bash_already_has_errexit(self):
        assert "unsafe_shell" not in _types(r.check_script_injection(_wf([{"run": "x", "shell": "bash"}])))

    def test_custom_bash_template_without_e(self):
        assert "unsafe_shell" in _types(r.check_script_injection(_wf([{"run": "x", "shell": "bash {0}"}])))

    def test_pipe_to_checksum_is_not_pipe_to_shell(self):
        wf = _wf([{"run": "curl -sL https://x/y.tgz | sha256sum -c sums"}])
        assert r.check_malicious_curl_pipe_bash(wf) == []

    @pytest.mark.parametrize("cmd", [
        "curl -fsSL https://x/install.sh | bash",
        "curl -fsSL https://x/install.sh | sudo -E bash -",
        "wget -qO- https://x | sh",
    ])
    def test_real_pipe_to_shell(self, cmd):
        assert _types(r.check_malicious_curl_pipe_bash(_wf([{"run": cmd}]))) == ["malicious_curl_pipe_bash"]

    def test_echo_pipe_with_non_user_expression_is_not_injection(self):
        wf = _wf([{"run": 'echo "${{ matrix.os }}" | shasum'}])
        assert "shell_injection" not in _types(r.check_script_injection(wf))


class TestObfuscation:
    def test_array_expansion_and_colour_codes_are_not_obfuscation(self):
        wf = _wf([{"run": 'echo "${FILES[*]}"\nprintf "\\033[0;31mred\\033[0m"\necho -e "\\x1b[1m"'}])
        assert r.check_obfuscation_detection(wf) == []

    def test_encoded_string_is_obfuscation(self):
        wf = _wf([{"run": 'printf "\\x63\\x75\\x72\\x6c\\x20" | sh'}])
        assert "obfuscation_detection" in _types(r.check_obfuscation_detection(wf))


class TestInjectionContexts:
    def test_head_ref_in_run_is_detected(self):
        wf = _wf([{"run": "echo ${{ github.head_ref }}"}], on="pull_request")
        found = r.check_risky_context_usage(wf)
        assert found and found[0]["severity"] == "critical"

    def test_expression_with_fallback_is_detected(self):
        wf = _wf([{"run": "echo \"${{ github.event.issue.title || 'none' }}\""}], on="issues")
        assert r.check_risky_context_usage(wf)[0]["severity"] == "critical"

    @pytest.mark.parametrize("expr", [
        "${{ github.event.pull_request.number }}",
        "${{ github.event.pull_request.head.sha }}",
        "${{ github.event.repository.name }}",
        "${{ github.event.repository.default_branch }}",
    ])
    def test_non_attacker_controlled_contexts_are_not_flagged(self, expr):
        wf = _wf([{"run": f"echo {expr} >> $GITHUB_ENV"}], on="pull_request_target")
        assert r.check_risky_context_usage(wf) == []
        assert r.check_github_env_injection(wf) == []

    def test_env_passthrough_is_low(self):
        wf = _wf([{"env": {"T": "${{ github.event.issue.title }}"}, "run": 'echo "$T"'}], on="issues")
        assert [i["severity"] for i in r.check_risky_context_usage(wf)] == ["low"]

    def test_github_script_interpolation_is_script_injection(self):
        wf = _wf([{"uses": "actions/github-script@v7",
                   "with": {"script": "console.log('${{ github.event.issue.title }}')"}}], on="issues")
        found = r.check_github_script_injection(wf)
        assert found and found[0]["severity"] == "critical"
        # Not double-reported as a generic action-parameter finding.
        assert r.check_risky_context_usage(wf) == []

    def test_powershell_with_matrix_value_is_not_injection(self):
        wf = _wf([{"shell": "pwsh", "run": "Copy-Item out.${{ matrix.ext }} dist/"}])
        assert r.check_powershell_injection(wf) == []

    def test_event_inputs_form_is_detected(self):
        wf = {
            "on": {"workflow_dispatch": {"inputs": {"cmd": {"type": "string"}}}},
            "jobs": {"a": {"runs-on": "ubuntu-latest", "steps": [{"run": "${{ github.event.inputs.cmd }}"}]}},
        }
        assert "code_injection_via_input" in _types(r.check_code_injection_via_workflow_inputs(wf))


class TestCredentials:
    def test_azure_oidc_is_not_long_term(self):
        wf = _wf([{"uses": "azure/login@v2",
                   "with": {"client-id": "${{ secrets.ID }}", "tenant-id": "${{ secrets.T }}"},
                   "env": {"AZURE_CLIENT_ID": "${{ secrets.ID }}", "AZURE_TENANT_ID": "${{ secrets.T }}"}}])
        assert r.check_secrets_in_workflow(wf) == []

    def test_aws_static_keys_via_action_input(self):
        wf = _wf([{"uses": "aws-actions/configure-aws-credentials@v4",
                   "with": {"aws-access-key-id": "${{ secrets.K }}", "aws-secret-access-key": "${{ secrets.S }}"}}])
        assert "long_term_aws_credentials" in _types(r.check_secrets_in_workflow(wf))

    def test_aws_keys_in_job_env(self):
        wf = _wf([{"run": "aws s3 ls"}], env={"AWS_ACCESS_KEY_ID": "${{ secrets.K }}"})
        assert "long_term_aws_credentials" in _types(r.check_secrets_in_workflow(wf))

    def test_aws_configure_with_variable_is_not_hardcoded(self):
        wf = _wf([{"run": 'aws configure set aws_access_key_id "$KEY"'}])
        assert "potential_hardcoded_cloud_credentials" not in _types(r.check_secrets_in_workflow(wf))

    def test_literal_access_key_is_hardcoded(self):
        wf = _wf([{"run": "export AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE"}])
        assert "potential_hardcoded_cloud_credentials" in _types(r.check_secrets_in_workflow(wf))

    def test_readable_cache_key_is_not_a_secret(self):
        wf = _wf([{"uses": "actions/cache@v4", "with": {"key": "linux-node-modules-build-cache"}}])
        assert r.check_secrets_in_workflow(wf) == []


class TestPinningAndVersions:
    def test_docker_digest_is_pinned(self):
        assert r.check_pinned_version("docker://alpine@sha256:" + "a" * 64) is None

    def test_docker_tag_is_unpinned(self):
        assert r.check_pinned_version("docker://alpine:3.20")["type"] == "unpinned_version"

    def test_subpath_action_is_not_typosquatting(self):
        assert r.check_typosquatting_actions(_wf([{"uses": "someorg/deploy-action/sub@v1"}])) == []

    def test_singular_action_owner_is_typosquatting(self):
        assert r.check_typosquatting_actions(_wf([{"uses": "action/checkout@v4"}]))

    @pytest.mark.asyncio
    @pytest.mark.parametrize("ref,latest,expected", [
        ("v4", "v4.2.2", False),   # floating major tracks 4.x
        ("v3", "v4.2.2", True),
        ("v4.1", "v4.2.2", True),
        ("v4.2.2", "v4.2.2", False),
    ])
    async def test_older_version_compares_at_tag_precision(self, ref, latest, expected):
        client = MagicMock()
        client.parse_action_reference = MagicMock(return_value=("actions", "checkout", ref, None))
        client.get_repository_info = AsyncMock(return_value={"name": "checkout"})
        client.get_latest_tag = AsyncMock(return_value=latest)
        wf = _wf([{"uses": f"actions/checkout@{ref}"}])
        issues = await r.check_older_action_versions(wf, client)
        assert ("older_action_version" in _types(issues)) is expected

    @pytest.mark.asyncio
    async def test_generic_v1_is_not_deprecated(self):
        issues = await r.check_deprecated_actions(_wf([{"uses": "dtolnay/rust-toolchain@v1"}]))
        assert issues == []

    @pytest.mark.asyncio
    async def test_shut_down_artifact_major_is_deprecated(self):
        issues = await r.check_deprecated_actions(_wf([{"uses": "actions/upload-artifact@v3"}]))
        assert _types(issues) == ["deprecated_action"]


class TestPermissions:
    def test_named_workflow_is_checked(self):
        wf = {"name": "CI", "on": "push", "permissions": "write-all",
              "jobs": {"test": {"runs-on": "ubuntu-latest", "steps": [{"run": "x"}]}}}
        assert "excessive_write_permissions" in _types(r.check_excessive_write_permissions(wf))

    def test_job_level_permissions_override_workflow(self):
        wf = {"on": "push", "permissions": "write-all",
              "jobs": {"test": {"runs-on": "ubuntu-latest", "permissions": {"contents": "read"}, "steps": []}}}
        assert r.check_excessive_write_permissions(wf) == []


class TestMisc:
    def test_rsync_is_not_netcat(self):
        assert r.check_network_traffic_filtering(_wf([{"run": "rsync -a src/ dst 2"}])) == []

    def test_local_action_with_secret_is_not_untrusted(self):
        wf = _wf([{"uses": "./.github/actions/deploy", "with": {"token": "${{ secrets.T }}"}}])
        assert r.check_secrets_access_untrusted(wf) == []

    def test_plain_bearer_token_use_is_not_escalation(self):
        wf = _wf([{"run": 'curl -H "Authorization: Bearer $GITHUB_TOKEN" https://api.github.com/user'}])
        assert r.check_token_permission_escalation(wf) == []

    def test_base64_encoding_the_token_is_escalation(self):
        wf = _wf([{"run": 'echo "$GITHUB_TOKEN" | base64'}])
        assert "token_permission_escalation" in _types(r.check_token_permission_escalation(wf))

    def test_persist_credentials_default_with_artifact_upload(self):
        wf = _wf([{"uses": "actions/checkout@v4"},
                  {"uses": "actions/upload-artifact@v4", "with": {"path": "dist"}}])
        found = [i for i in r.check_checkout_actions(wf) if i["type"] == "unsafe_checkout"]
        assert found and found[0]["severity"] == "medium"


class TestCompositeActionAudit:
    def test_composite_input_interpolated_into_run(self):
        action_yml = {"runs": {"using": "composite", "steps": [
            {"name": "Greet", "shell": "bash", "run": "echo ${{ inputs.title }}"}]}}
        issues = SecurityAuditor.audit_action("o/r@" + "a" * 40, action_yml)
        found = [i for i in issues if i["type"] == "code_injection_via_input"]
        assert found and found[0]["evidence"]["inputs"] == ["title"]

    def test_deprecated_node_runtime(self):
        issues = SecurityAuditor.audit_action("o/r@v1", {"runs": {"using": "node16", "main": "index.js"}})
        assert "deprecated_action" in _types(issues)
