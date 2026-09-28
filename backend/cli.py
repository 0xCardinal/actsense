"""Headless command-line scanner: ``actsense scan <path>``.

Runs the same SecurityAuditor the web app uses against a local checkout and
prints the findings as text, JSON, SARIF or Markdown. Offline by default;
``--online`` passes a GitHubClient to the checks that consult the GitHub API.

With ``--baseline FILE`` or ``--diff-base REF`` only findings missing from the
baseline count toward ``--fail-on``, so adopting the scanner does not fail
every pull request on findings that were already there.
"""
import argparse
import asyncio
import json
import logging
import os
import subprocess
import sys
import tempfile
from collections import Counter
from dataclasses import dataclass, field
from importlib import metadata
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, TextIO

from baseline import SKIP_DIRS, BaselineError, baseline_document, load_baseline, mark_new, materialize_ref
from dismissals import fingerprint
from security_auditor import SecurityAuditor
from workflow_parser import WorkflowParser

SEVERITIES = ("critical", "high", "medium", "low")
_SEVERITY_RANK = {s: i for i, s in enumerate(SEVERITIES)}

EXIT_OK = 0
EXIT_FINDINGS = 1
EXIT_ERROR = 2

DOCS_URL = "https://actsense.dev/vulnerabilities/{}"

parser = WorkflowParser()


@dataclass
class Finding:
    path: str  # relative to the scan root, POSIX separators
    issue: Dict[str, Any]
    # None when no baseline was given; otherwise whether the baseline lacks it.
    new: Optional[bool] = None

    @property
    def severity(self) -> str:
        sev = str(self.issue.get("severity", "low")).lower()
        return sev if sev in _SEVERITY_RANK else "low"

    @property
    def line(self) -> Optional[int]:
        line = self.issue.get("line_number")
        return line if isinstance(line, int) and line > 0 else None

    @property
    def type(self) -> str:
        return str(self.issue.get("type", "unknown"))

    @property
    def fingerprint(self) -> str:
        return fingerprint(self.path, self.issue)

    @property
    def gating(self) -> bool:
        """Counts toward --fail-on: every finding, or only new ones under a baseline."""
        return self.new is not False


@dataclass
class ScanResult:
    root: Path
    findings: List[Finding] = field(default_factory=list)
    scanned: List[str] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)
    baseline_source: Optional[str] = None

    @property
    def has_baseline(self) -> bool:
        return self.baseline_source is not None


def _version() -> str:
    try:
        return metadata.version("actsense-backend")
    except metadata.PackageNotFoundError:
        return "0.0.0"


def _rel(path: Path, root: Path) -> str:
    try:
        return path.resolve().relative_to(root.resolve()).as_posix()
    except ValueError:
        return path.as_posix()


def discover(root: Path) -> Dict[str, List[Path]]:
    """Find workflow files and action metadata files under ``root``.

    ``root`` may also be a single file, which is classified by its name.
    """
    if root.is_file():
        if root.name in ("action.yml", "action.yaml"):
            return {"workflows": [], "actions": [root]}
        return {"workflows": [root], "actions": []}

    wf_dir = root / ".github" / "workflows"
    workflows = sorted(
        p for p in wf_dir.glob("*") if p.is_file() and p.suffix in (".yml", ".yaml")
    ) if wf_dir.is_dir() else []

    actions: List[Path] = []
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = sorted(
            d for d in dirnames
            if d not in SKIP_DIRS and (not d.startswith(".") or d == ".github")
        )
        for name in ("action.yml", "action.yaml"):
            if name in filenames:
                actions.append(Path(dirpath) / name)
                break
    ignored = _git_ignored([*workflows, *actions], root)
    return {
        "workflows": [p for p in workflows if p not in ignored],
        "actions": [p for p in actions if p not in ignored],
    }


def _git_ignored(paths: List[Path], cwd: Path) -> set:
    """The subset of ``paths`` that git ignores; empty outside a git checkout."""
    if not paths:
        return set()
    try:
        proc = subprocess.run(
            ["git", "check-ignore", "--stdin", "-z"], cwd=cwd,
            input="\0".join(str(p) for p in paths), capture_output=True, text=True, timeout=30,
        )
    except (OSError, subprocess.SubprocessError):
        return set()
    # Exit status 1 means nothing is ignored; 128 means not a git checkout.
    if proc.returncode != 0:
        return set()
    return {Path(p) for p in proc.stdout.split("\0") if p}


def _git_remote_repo(root: Path) -> Optional[str]:
    """Best-effort ``owner/repo`` from the checkout's origin remote."""
    cwd = root if root.is_dir() else root.parent
    try:
        url = subprocess.run(
            ["git", "remote", "get-url", "origin"], cwd=cwd,
            capture_output=True, text=True, timeout=5, check=True,
        ).stdout.strip()
    except (OSError, subprocess.SubprocessError):
        return None
    for prefix in ("git@github.com:", "https://github.com/", "ssh://git@github.com/"):
        if url.startswith(prefix):
            slug = url[len(prefix):].removesuffix(".git").strip("/")
            if slug.count("/") == 1:
                return slug
    return None


def _read(path: Path) -> Optional[str]:
    try:
        return path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError):
        return None


def _local_ref(action_file: Path, root: Path) -> str:
    rel = _rel(action_file.parent, root)
    return "./" if rel in ("", ".") else f"./{rel}"


def _sibling(action_file: Path, name: str) -> Optional[str]:
    if not isinstance(name, str) or not name or name.startswith("docker://"):
        return None
    candidate = (action_file.parent / name).resolve()
    if not candidate.is_relative_to(action_file.parent.resolve()) or not candidate.is_file():
        return None
    return _read(candidate)


async def scan(
    root: Path,
    client: Any = None,
    repository: Optional[str] = None,
    is_public_repo: bool = False,
) -> ScanResult:
    """Audit every workflow and local action under ``root``."""
    root = root.resolve()
    base = root if root.is_dir() else root.parent
    result = ScanResult(root=base)
    if not root.exists():
        return result
    files = discover(root)
    workflow_actions_data = []

    for wf_path in files["workflows"]:
        rel = _rel(wf_path, base)
        content = _read(wf_path)
        workflow = parser.parse_workflow(content) if content is not None else None
        if not isinstance(workflow, dict) or "error" in workflow:
            result.errors.append(f"{rel}: could not parse workflow YAML")
            continue
        result.scanned.append(rel)
        issues = await SecurityAuditor.audit_workflow(
            workflow, content=content, client=client,
            current_repo=repository, is_public_repo=is_public_repo,
        )
        result.findings.extend(Finding(rel, i) for i in issues)
        workflow_actions_data.append({
            "workflow_name": wf_path.name,
            "workflow_path": rel,
            "actions": parser.extract_actions(workflow),
        })

    if len(workflow_actions_data) > 1:
        for issue in SecurityAuditor.check_inconsistent_action_versions(workflow_actions_data):
            workflows = issue.get("workflows") or []
            path = workflows[0].get("workflow_path") if workflows else None
            result.findings.append(Finding(path or ".github/workflows", issue))

    for action_path in files["actions"]:
        rel = _rel(action_path, base)
        content = _read(action_path)
        action_yml = parser.parse_action_yml(content) if content is not None else None
        if not isinstance(action_yml, dict) or not action_yml or "error" in action_yml:
            result.errors.append(f"{rel}: could not parse action metadata")
            continue
        result.scanned.append(rel)
        runs = action_yml.get("runs") if isinstance(action_yml.get("runs"), dict) else {}
        using = str(runs.get("using", "")).lower()
        js_code = dockerfile = None
        if using.startswith("node"):
            js_code = _sibling(action_path, runs.get("main") or "index.js") or _sibling(action_path, "dist/index.js")
        elif using == "docker":
            dockerfile = _sibling(action_path, runs.get("image", "")) or _sibling(action_path, "Dockerfile")
        issues = SecurityAuditor.audit_action(_local_ref(action_path, base), action_yml, js_code, dockerfile)
        result.findings.extend(Finding(rel, i) for i in issues)

    result.findings.sort(key=lambda f: (_SEVERITY_RANK[f.severity], f.path, f.line or 0))
    return result


def _at_or_above(severity: str, threshold: str) -> bool:
    return _SEVERITY_RANK[severity] <= _SEVERITY_RANK[threshold]


def _counts(findings: List[Finding]) -> Dict[str, int]:
    c = Counter(f.severity for f in findings)
    return {s: c[s] for s in SEVERITIES}


def _count_phrase(findings: List[Finding]) -> str:
    return ", ".join(f"{n} {s}" for s, n in _counts(findings).items() if n) or "none"


# --------------------------------------------------------------------------
# Output formats
# --------------------------------------------------------------------------

_COLORS = {"critical": "\033[1;35m", "high": "\033[1;31m", "medium": "\033[33m", "low": "\033[36m"}
_DIM, _RESET = "\033[2m", "\033[0m"


def format_text(result: ScanResult, color: bool = False) -> str:
    def c(code: str, text: str) -> str:
        return f"{code}{text}{_RESET}" if color else text

    shown = [f for f in result.findings if f.gating]
    lines: List[str] = []
    current = None
    for f in sorted(shown, key=lambda f: (f.path, f.line or 0, _SEVERITY_RANK[f.severity])):
        if f.path != current:
            if current is not None:
                lines.append("")
            lines.append(c("\033[1m", f.path))
            current = f.path
        loc = f"{f.line}" if f.line else "-"
        sev = c(_COLORS[f.severity], f"{f.severity.upper():<8}")
        lines.append(f"  {loc:>5}  {sev} {f.type}")
        lines.append(f"         {f.issue.get('message', '')}")
        lines.append(c(_DIM, f"         {DOCS_URL.format(f.type)}"))
    if lines:
        lines.append("")

    if result.has_baseline:
        existing = len(result.findings) - len(shown)
        lines.append(
            f"Scanned {len(result.scanned)} file(s): {len(shown)} new finding(s) ({_count_phrase(shown)}); "
            f"{existing} already in baseline {result.baseline_source}"
        )
    else:
        lines.append(f"Scanned {len(result.scanned)} file(s): {_count_phrase(shown).replace('none', 'no findings')}")
    return "\n".join(lines) + "\n"


def format_json(result: ScanResult) -> str:
    payload = {
        "version": _version(),
        "root": str(result.root),
        "baseline": result.baseline_source,
        "scanned": result.scanned,
        "errors": result.errors,
        "findings": [
            {
                "path": f.path, "line": f.line, "fingerprint": f.fingerprint,
                **({"new": f.new} if result.has_baseline else {}),
                **f.issue,
            }
            for f in result.findings
        ],
    }
    return json.dumps(payload, indent=2, default=str) + "\n"


_MD_ROW_LIMIT = 50


def _md_cell(text: Any) -> str:
    return str(text).replace("|", "\\|").replace("\n", " ")


def format_markdown(result: ScanResult) -> str:
    """Summary for a pull request comment or $GITHUB_STEP_SUMMARY."""
    shown = [f for f in result.findings if f.gating]
    lines = ["## actsense", ""]
    if result.has_baseline:
        existing = len(result.findings) - len(shown)
        lines.append(
            f"**{len(shown)} new finding(s)** ({_count_phrase(shown)}) across {len(result.scanned)} file(s). "
            f"{existing} existing finding(s) are already in the baseline ({_md_cell(result.baseline_source)})."
        )
    else:
        lines.append(f"**{len(shown)} finding(s)** ({_count_phrase(shown)}) across {len(result.scanned)} file(s).")
    if shown:
        lines += ["", "| Severity | Finding | Location |", "| --- | --- | --- |"]
        for f in shown[:_MD_ROW_LIMIT]:
            loc = f"{f.path}:{f.line}" if f.line else f.path
            lines.append(
                f"| {f.severity} | [`{f.type}`]({DOCS_URL.format(f.type)}) {_md_cell(f.issue.get('message', ''))} "
                f"| `{_md_cell(loc)}` |"
            )
        if len(shown) > _MD_ROW_LIMIT:
            lines += ["", f"…and {len(shown) - _MD_ROW_LIMIT} more."]
    if result.errors:
        lines += ["", "Could not read: " + ", ".join(f"`{_md_cell(e)}`" for e in result.errors)]
    return "\n".join(lines) + "\n"


_SARIF_LEVEL = {"critical": "error", "high": "error", "medium": "warning", "low": "note"}
# GitHub code scanning maps this score to its own Critical/High/Medium/Low labels.
_SECURITY_SEVERITY = {"critical": "9.5", "high": "8.0", "medium": "5.5", "low": "3.0"}


def _title(issue_type: str) -> str:
    return issue_type.replace("_", " ").strip().capitalize()


def format_sarif(result: ScanResult, srcroot: Optional[Path] = None) -> str:
    """SARIF 2.1.0. URIs are relative to ``srcroot`` (default: the working
    directory, which is the checkout root in GitHub Actions) when the scanned
    tree is inside it, so code scanning can place findings on files."""
    srcroot = (srcroot or Path.cwd()).resolve()
    try:
        prefix = result.root.resolve().relative_to(srcroot).as_posix()
    except ValueError:
        srcroot, prefix = result.root.resolve(), "."

    rules: Dict[str, Dict[str, Any]] = {}
    results = []
    for f in result.findings:
        rule_id = f.type
        rule = rules.get(rule_id)
        if rule is None or _SEVERITY_RANK[f.severity] < _SEVERITY_RANK[rule["_sev"]]:
            rules[rule_id] = {
                "_sev": f.severity,
                "id": rule_id,
                "name": "".join(p.capitalize() for p in rule_id.split("_")),
                "shortDescription": {"text": _title(rule_id)},
                "helpUri": DOCS_URL.format(rule_id),
                "help": {"text": f"See {DOCS_URL.format(rule_id)}"},
                "defaultConfiguration": {"level": _SARIF_LEVEL[f.severity]},
                "properties": {
                    "tags": ["security", "github-actions"],
                    "security-severity": _SECURITY_SEVERITY[f.severity],
                },
            }
        uri = f.path if prefix == "." else f"{prefix}/{f.path}"
        entry: Dict[str, Any] = {
            "ruleId": rule_id,
            "level": _SARIF_LEVEL[f.severity],
            "message": {"text": str(f.issue.get("message", rule_id))},
            "locations": [{"physicalLocation": {
                "artifactLocation": {"uri": uri, "uriBaseId": "%SRCROOT%"},
                "region": {"startLine": f.line or 1},
            }}],
            "partialFingerprints": {"actsenseFingerprint/v1": f.fingerprint},
            "properties": {"severity": f.severity},
        }
        if result.has_baseline:
            entry["baselineState"] = "new" if f.new else "unchanged"
        results.append(entry)

    for rule in rules.values():
        rule.pop("_sev")
    sarif = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {
                "name": "actsense",
                "informationUri": "https://actsense.dev",
                "version": _version(),
                "rules": sorted(rules.values(), key=lambda r: r["id"]),
            }},
            "originalUriBaseIds": {"%SRCROOT%": {"uri": srcroot.as_uri() + "/"}},
            "results": results,
        }],
    }
    return json.dumps(sarif, indent=2) + "\n"


FORMATTERS = {"text": format_text, "json": format_json, "sarif": format_sarif, "markdown": format_markdown}


# --------------------------------------------------------------------------
# Entry point
# --------------------------------------------------------------------------

def build_arg_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(prog="actsense", description="Workflow security auditor for GitHub Actions.")
    ap.add_argument("--version", action="version", version=f"%(prog)s {_version()}")
    sub = ap.add_subparsers(dest="command", required=True)

    s = sub.add_parser(
        "scan", help="Scan a local checkout, workflow file or action.yml.",
        description="Exit status: 0 passed, 1 findings at or above --fail-on, 2 usage or input error.",
    )
    s.add_argument("path", nargs="?", default=".", help="Repository root, workflow file or action.yml (default: .)")
    s.add_argument("-f", "--format", choices=sorted(FORMATTERS), default="text")
    s.add_argument("-o", "--output", help="Write the report to this file instead of stdout.")
    s.add_argument("--summary-file", help="Also write a Markdown summary here (e.g. $GITHUB_STEP_SUMMARY).")
    s.add_argument(
        "--fail-on", choices=[*SEVERITIES, "none"], default="high",
        help="Exit 1 if any (new) finding is at or above this severity (default: high).",
    )
    s.add_argument(
        "--min-severity", choices=SEVERITIES, default="low",
        help="Leave findings below this severity out of the report (default: low).",
    )

    b = s.add_argument_group("baseline (only new findings fail)")
    ex = b.add_mutually_exclusive_group()
    ex.add_argument("--baseline", metavar="FILE", help="Findings in this file (from --write-baseline or -f json) don't fail the scan.")
    ex.add_argument("--diff-base", metavar="REF", help="Scan this git ref too; only findings it doesn't have fail the scan.")
    b.add_argument("--write-baseline", metavar="FILE", help="Write the current findings as a baseline file and exit 0.")

    s.add_argument(
        "--online", action="store_true",
        help="Query the GitHub API (uses GITHUB_TOKEN) for version, deprecation and missing-repository checks.",
    )
    s.add_argument("--repo", help="owner/repo of the checkout (default: from the origin remote).")
    s.add_argument("--public", action="store_true", help="Treat the repository as public (default: detected with --online).")
    s.add_argument("--no-color", action="store_true", help="Disable colored text output.")
    return ap


async def _run_scan(args: argparse.Namespace) -> ScanResult:
    root = Path(args.path)
    repository = args.repo or _git_remote_repo(root)
    is_public = args.public
    client = None
    if args.online:
        from github_client import GitHubClient
        client = GitHubClient(token=os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN"))
    try:
        if client and repository and not is_public:
            owner, repo = repository.split("/", 1)
            try:
                info = await client.get_repository_info(owner, repo)
                is_public = bool(info) and not info.get("private", True)
            except Exception:
                pass

        async def run(path: Path) -> ScanResult:
            return await scan(path, client=client, repository=repository, is_public_repo=is_public)

        result = await run(root)
        if args.baseline:
            mark_new(result.findings, load_baseline(Path(args.baseline)))
            result.baseline_source = args.baseline
        elif args.diff_base:
            with tempfile.TemporaryDirectory(prefix="actsense-base-") as tmp:
                base = await run(materialize_ref(root, args.diff_base, Path(tmp)))
            mark_new(result.findings, Counter(f.fingerprint for f in base.findings))
            result.baseline_source = args.diff_base
        return result
    finally:
        if client is not None:
            await client.aclose()


def main(argv: Optional[Sequence[str]] = None, stdout: TextIO = sys.stdout, stderr: TextIO = sys.stderr) -> int:
    args = build_arg_parser().parse_args(argv)

    if not Path(args.path).exists():
        print(f"actsense: {args.path}: no such file or directory", file=stderr)
        return EXIT_ERROR

    # Parse failures are reported as warnings below; keep library tracebacks quiet.
    previous = logging.root.manager.disable
    logging.disable(logging.ERROR)
    try:
        result = asyncio.run(_run_scan(args))
    except BaselineError as exc:
        print(f"actsense: {exc}", file=stderr)
        return EXIT_ERROR
    finally:
        logging.disable(previous)

    for err in result.errors:
        print(f"actsense: warning: {err}", file=stderr)
    if not result.scanned and not result.errors:
        print(f"actsense: no workflows or action.yml files found under {args.path}", file=stderr)

    result.findings = [f for f in result.findings if _at_or_above(f.severity, args.min_severity)]

    if args.write_baseline:
        Path(args.write_baseline).write_text(baseline_document(result.findings), encoding="utf-8")
        print(f"actsense: wrote {len(result.findings)} finding(s) to {args.write_baseline}", file=stderr)
        return EXIT_OK

    if args.format == "text":
        color = (
            not args.no_color and not args.output and "NO_COLOR" not in os.environ
            and getattr(stdout, "isatty", lambda: False)()
        )
        report = format_text(result, color=color)
    else:
        report = FORMATTERS[args.format](result)

    if args.output:
        Path(args.output).write_text(report, encoding="utf-8")
    else:
        stdout.write(report)
    if args.summary_file:
        with open(args.summary_file, "a", encoding="utf-8") as fh:
            fh.write(format_markdown(result))

    failing = [f for f in result.findings if f.gating and args.fail_on != "none" and _at_or_above(f.severity, args.fail_on)]
    return EXIT_FINDINGS if failing else EXIT_OK


def main_entry() -> None:
    sys.exit(main())


if __name__ == "__main__":
    main_entry()
