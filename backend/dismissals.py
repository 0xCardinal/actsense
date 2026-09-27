"""Dismissed findings: stable issue fingerprints and a per-target store.

A dismissal is recorded against an audit target (``owner/repo`` or an action
reference) and an issue fingerprint, so it carries over to later audits of the
same target. The fingerprint identifies a finding by the node it sits on, its
type, its identifying fields and its message, and leaves out what shifts
between runs without changing the finding: line numbers, the latest available
version, commit ages, and numbers in the message.
"""
import datetime
import hashlib
import json
import re
import threading
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional

# Fields that change between runs (or carry presentation only) and so must not
# change a finding's identity.
_VOLATILE_FIELDS = {
    "severity", "message", "evidence", "recommendation", "line_number",
    "latest_version", "days_old", "commit_date",
    "versions", "version_count", "workflows", "workflow_count",
    # Set by this module.
    "fingerprint", "dismissed",
}

# Node types a finding is mirrored onto from the node it was raised on, so
# the graph is navigable (see main._add_package_dependency_nodes). The last two
# are the names analyses stored by older versions use for image nodes.
MIRROR_NODE_TYPES = {"package", "image", "container_image", "docker_image"}

_MAX_REASON_LENGTH = 500


def _normalized_message(issue: Dict[str, Any]) -> str:
    message = str(issue.get("message", ""))
    for field in ("latest_version", "days_old", "commit_date", "line_number"):
        value = issue.get(field)
        if value not in (None, ""):
            message = message.replace(str(value), f"<{field}>")
    return re.sub(r"\d+", "#", message)


def _content_key(issue: Dict[str, Any]) -> str:
    identity = {k: v for k, v in issue.items() if k not in _VOLATILE_FIELDS}
    return json.dumps([identity, _normalized_message(issue)], sort_keys=True, default=str)


def fingerprint(node_id: str, issue: Dict[str, Any]) -> str:
    """Stable identifier for a finding on a node."""
    digest = hashlib.sha256(f"{node_id}\n{_content_key(issue)}".encode()).hexdigest()
    return digest[:20]


def apply_dismissals(nodes: Iterable[Dict[str, Any]], dismissed: Dict[str, Dict[str, Any]]) -> None:
    """Tag every issue with its fingerprint and, when dismissed, the dismissal.

    Mutates the issues in place. A finding mirrored onto a package or image
    node shares the fingerprint of the finding it mirrors, so dismissing one
    dismisses both.
    """
    nodes = list(nodes)
    source_fingerprints: Dict[str, str] = {}
    ordered = sorted(nodes, key=lambda n: n.get("type") in MIRROR_NODE_TYPES)
    for node in ordered:
        mirror = node.get("type") in MIRROR_NODE_TYPES
        for issue in node.get("issues", []):
            key = _content_key(issue)
            fp = source_fingerprints.get(key) if mirror else None
            if fp is None:
                fp = fingerprint(node["id"], issue)
            if not mirror:
                source_fingerprints.setdefault(key, fp)
            issue["fingerprint"] = fp
            record = dismissed.get(fp)
            if record:
                issue["dismissed"] = {k: record.get(k) for k in ("reason", "dismissed_at")}
            else:
                issue.pop("dismissed", None)


def is_dismissed(issue: Dict[str, Any]) -> bool:
    return bool(issue.get("dismissed"))


class DismissalStore:
    """Dismissals keyed by audit target, persisted as one JSON file."""

    def __init__(self, path: Optional[str] = None):
        self.path = Path(path) if path else Path(__file__).parent.parent / "data" / "dismissals.json"
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()

    def _read(self) -> Dict[str, Dict[str, Dict[str, Any]]]:
        if not self.path.exists():
            return {}
        with open(self.path, "r") as f:
            return json.load(f)

    def _write(self, data: Dict[str, Dict[str, Dict[str, Any]]]) -> None:
        tmp_path = self.path.with_suffix(".tmp")
        try:
            with open(tmp_path, "w") as f:
                json.dump(data, f, indent=2)
            tmp_path.replace(self.path)
        except Exception:
            tmp_path.unlink(missing_ok=True)
            raise

    def get(self, target: Optional[str]) -> Dict[str, Dict[str, Any]]:
        """Dismissals for a target, keyed by fingerprint."""
        if not target:
            return {}
        with self._lock:
            return self._read().get(target, {})

    def list(self, target: str) -> List[Dict[str, Any]]:
        return [{"fingerprint": fp, **record} for fp, record in self.get(target).items()]

    def add(self, target: str, fp: str, issue: Dict[str, Any], node_id: str, reason: str = "") -> Dict[str, Any]:
        record = {
            "reason": reason.strip()[:_MAX_REASON_LENGTH],
            "dismissed_at": datetime.datetime.now(datetime.UTC).isoformat(),
            "type": issue.get("type"),
            "node": node_id,
            "message": issue.get("message"),
        }
        with self._lock:
            data = self._read()
            data.setdefault(target, {})[fp] = record
            self._write(data)
        return record

    def remove(self, target: str, fp: str) -> bool:
        with self._lock:
            data = self._read()
            if fp not in data.get(target, {}):
                return False
            del data[target][fp]
            if not data[target]:
                del data[target]
            self._write(data)
        return True
