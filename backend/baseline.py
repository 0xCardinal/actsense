"""Baselines for ``actsense scan``: only new findings fail a build.

A baseline is a multiset of finding fingerprints (see ``dismissals.fingerprint``),
taken either from a JSON file or by scanning another git ref of the same
checkout. Fingerprints leave out line numbers and other volatile fields, so a
finding keeps its identity when unrelated lines move.
"""
import io
import json
import subprocess
import tarfile
from collections import Counter
from pathlib import Path, PurePosixPath
from typing import Any, Iterable, List

BASELINE_VERSION = 1

# Directories never searched for workflow or action files.
SKIP_DIRS = {".git", "node_modules", "vendor", ".venv", "venv", "__pycache__"}
_ACTION_FILES = {"action.yml", "action.yaml"}
_ACTION_SIDE_FILES = {".js", ".cjs", ".mjs"}


class BaselineError(Exception):
    """The baseline file or git ref could not be read."""


def load_baseline(path: Path) -> Counter:
    """Read fingerprints from a baseline file or from ``--format json`` output."""
    try:
        data = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise BaselineError(f"cannot read baseline {path}: {exc}") from exc
    entries = data.get("findings") if isinstance(data, dict) else None
    if not isinstance(entries, list):
        raise BaselineError(f"{path} has no 'findings' list")
    return Counter(
        e["fingerprint"] for e in entries
        if isinstance(e, dict) and isinstance(e.get("fingerprint"), str)
    )


def baseline_document(findings: Iterable[Any]) -> str:
    """Serialize findings as a baseline file (fingerprint plus context for reviewers)."""
    entries = sorted(
        (
            {
                "fingerprint": f.fingerprint,
                "path": f.path,
                "type": f.issue.get("type"),
                "severity": f.severity,
                "message": f.issue.get("message"),
            }
            for f in findings
        ),
        key=lambda e: (e["path"], str(e["type"]), e["fingerprint"]),
    )
    return json.dumps({"actsense_baseline": BASELINE_VERSION, "findings": entries}, indent=2) + "\n"


def mark_new(findings: Iterable[Any], baseline: Counter) -> None:
    """Set ``finding.new`` on each finding; a fingerprint seen N times in the
    baseline covers N occurrences."""
    remaining = Counter(baseline)
    for f in findings:
        if remaining[f.fingerprint] > 0:
            remaining[f.fingerprint] -= 1
            f.new = False
        else:
            f.new = True


def _git(cwd: Path, *args: str, binary: bool = False) -> subprocess.CompletedProcess:
    return subprocess.run(
        ["git", *args], cwd=cwd, capture_output=True, text=not binary, timeout=120,
    )


def _wanted_paths(names: List[str]) -> List[str]:
    """Workflow and action files a scan reads, out of a tree listing."""
    kept, action_dirs = [], set()
    for name in names:
        parts = PurePosixPath(name).parts
        if any(p in SKIP_DIRS for p in parts):
            continue
        if parts[-1] in _ACTION_FILES:
            action_dirs.add(PurePosixPath(name).parent)
    for name in names:
        p = PurePosixPath(name)
        if any(part in SKIP_DIRS for part in p.parts):
            continue
        if p.parts[0] == ".github" or p.name in _ACTION_FILES or p.name == "Dockerfile":
            kept.append(name)
        elif p.suffix in _ACTION_SIDE_FILES and (
            p.parent in action_dirs or (p.parent.name == "dist" and p.parent.parent in action_dirs)
        ):
            kept.append(name)
    return kept


def materialize_ref(scan_path: Path, ref: str, dest: Path) -> Path:
    """Write the workflow/action files of ``ref`` into ``dest``.

    Returns the path inside ``dest`` that corresponds to ``scan_path``. Fetches
    the commit from ``origin`` when a shallow checkout does not have it.
    """
    scan_path = scan_path.resolve()
    cwd = scan_path if scan_path.is_dir() else scan_path.parent
    top = _git(cwd, "rev-parse", "--show-toplevel")
    if top.returncode != 0:
        raise BaselineError(f"{scan_path} is not inside a git repository")
    toplevel = Path(top.stdout.strip()).resolve()

    commit = f"{ref}^{{commit}}"
    if _git(toplevel, "rev-parse", "--verify", "--quiet", commit).returncode != 0:
        _git(toplevel, "fetch", "--no-tags", "--depth=1", "origin", ref)
        if _git(toplevel, "rev-parse", "--verify", "--quiet", commit).returncode != 0:
            raise BaselineError(f"cannot resolve git ref {ref!r} (not present locally or on origin)")

    listing = _git(toplevel, "ls-tree", "-r", "-z", "--name-only", commit)
    if listing.returncode != 0:
        raise BaselineError(f"cannot list files at {ref}: {listing.stderr.strip()}")
    paths = _wanted_paths([n for n in listing.stdout.split("\0") if n])

    dest.mkdir(parents=True, exist_ok=True)
    if paths:
        archive = _git(toplevel, "archive", "--format=tar", commit, "--", *paths, binary=True)
        if archive.returncode != 0:
            raise BaselineError(f"cannot read files at {ref}: {archive.stderr.decode(errors='replace').strip()}")
        with tarfile.open(fileobj=io.BytesIO(archive.stdout)) as tar:
            tar.extractall(dest, filter="data")

    return dest / scan_path.relative_to(toplevel)
