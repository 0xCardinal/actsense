"""Aggregation for organization-wide scans.

An org scan audits each selected repository on its own (one stored analysis
per repository) and then summarises them here: totals across repositories and
an inventory of every action the organization's workflows reference.
"""
import re
from collections import defaultdict
from typing import Any, Dict, Iterable, List, Optional, Tuple

from config_loader import get_trusted_publishers

# Upper bound on repositories per scan, to keep one request within the
# GitHub API budget of a single token (5000 requests/hour).
MAX_ORG_SCAN_REPOS = 200

# Repositories audited at the same time within one org scan.
ORG_SCAN_CONCURRENCY = 4

SEVERITIES = ("critical", "high", "medium", "low")

_OWNER_RE = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9-]{0,38})$")
_REPO_RE = re.compile(r"^[A-Za-z0-9._-]{1,100}$")
_FULL_SHA_RE = re.compile(r"^[0-9a-f]{40}$")


def parse_owner(value: str) -> Optional[str]:
    """Accept 'org', '@org' or 'https://github.com/org'; return the login or None."""
    value = (value or "").strip().rstrip("/")
    for prefix in ("https://github.com/", "http://github.com/", "https://www.github.com/", "github.com/"):
        if value.lower().startswith(prefix):
            value = value[len(prefix):]
            break
    value = value.lstrip("@")
    return value if _OWNER_RE.match(value) else None


def normalize_repositories(owner: str, repositories: Iterable[str]) -> Tuple[List[str], List[str]]:
    """Map 'repo' or 'owner/repo' entries to repo names under ``owner``.

    Returns (names, rejected): de-duplicated names in input order, and the
    entries that are malformed or belong to another owner.
    """
    names: List[str] = []
    seen = set()
    rejected: List[str] = []
    for entry in repositories:
        raw = (entry or "").strip()
        parts = raw.split("/")
        if len(parts) == 2 and parts[0].lower() == owner.lower():
            name = parts[1]
        elif len(parts) == 1:
            name = parts[0]
        else:
            rejected.append(raw)
            continue
        if not _REPO_RE.match(name) or name in (".", ".."):
            rejected.append(raw)
            continue
        if name.lower() not in seen:
            seen.add(name.lower())
            names.append(name)
    return names, rejected


def summarize(results: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Totals across the per-repository results of an org scan."""
    severity_counts = {s: 0 for s in SEVERITIES}
    total_issues = 0
    dismissed = 0
    by_status: Dict[str, int] = defaultdict(int)
    repos_with_issues = 0
    for r in results:
        by_status[r.get("status", "error")] += 1
        stats = r.get("statistics") or {}
        issues = stats.get("total_issues", 0) or 0
        total_issues += issues
        dismissed += stats.get("dismissed_issues", 0) or 0
        if issues:
            repos_with_issues += 1
        for sev, count in (stats.get("severity_counts") or {}).items():
            severity_counts[sev] = severity_counts.get(sev, 0) + count
    return {
        "total_repositories": len(results),
        "scanned_repositories": by_status.get("ok", 0) + by_status.get("no_workflows", 0),
        "failed_repositories": by_status.get("error", 0),
        "skipped_repositories": by_status.get("skipped", 0),
        "repositories_without_workflows": by_status.get("no_workflows", 0),
        "repositories_with_issues": repos_with_issues,
        "total_issues": total_issues,
        "dismissed_issues": dismissed,
        "severity_counts": severity_counts,
    }


def _pinning(ref: str) -> str:
    if _FULL_SHA_RE.match(ref.lower()):
        return "sha"
    return "tag"


def _is_trusted(action: str, trusted: List[str]) -> bool:
    lowered = action.lower()
    return any(lowered.startswith(t.lower()) for t in trusted)


def build_action_inventory(
    workflow_data: Dict[str, List[Dict[str, Any]]],
    branches: Optional[Dict[str, str]] = None,
    owner: Optional[str] = None,
) -> List[Dict[str, Any]]:
    """Every action referenced across the org, with where and how it is pinned.

    ``workflow_data`` maps 'owner/repo' to what ``audit_repository`` returned
    for it. Docker image references are left out; they are not actions.
    Ordered riskiest first: untrusted publishers not pinned by SHA everywhere,
    then actions with diverging refs, then by how many repositories use them.
    """
    trusted = get_trusted_publishers()
    branches = branches or {}
    uses: Dict[str, Dict[str, set]] = defaultdict(lambda: defaultdict(set))
    usages: Dict[Tuple[str, str], List[Dict[str, Any]]] = defaultdict(list)
    workflow_counts: Dict[str, int] = defaultdict(int)
    for repository, workflows in workflow_data.items():
        branch = branches.get(repository) or "main"
        for wf in workflows or []:
            lines = wf.get("uses_lines") or {}
            for action_ref in set(wf.get("actions") or []):
                if not isinstance(action_ref, str) or action_ref.startswith("docker://") or "@" not in action_ref:
                    continue
                name, ref = action_ref.rsplit("@", 1)
                uses[name][ref].add(repository)
                workflow_counts[name] += 1
                path = wf.get("workflow_path")
                if path:
                    for line in lines.get(action_ref) or [None]:
                        usages[(name, ref)].append({
                            "repository": repository, "path": path, "line": line,
                            "url": _blob_url(repository, branch, path, line),
                        })

    inventory = []
    for name, refs in uses.items():
        repositories = sorted({repo for repos in refs.values() for repo in repos})
        kinds = {_pinning(ref) for ref in refs}
        pinning = "sha" if kinds == {"sha"} else "tag" if kinds == {"tag"} else "mixed"
        internal = bool(owner) and name.lower().startswith(f"{owner.lower()}/")
        inventory.append({
            "action": name,
            "internal": internal,
            "trusted": internal or _is_trusted(name, trusted),
            "pinning": pinning,
            "repository_count": len(repositories),
            "workflow_count": workflow_counts[name],
            "repositories": repositories,
            "refs": [
                {
                    "ref": ref, "pinning": _pinning(ref), "repositories": sorted(repos),
                    "usages": sorted(usages.get((name, ref), []), key=lambda u: (u["repository"], u["path"], u["line"] or 0)),
                }
                for ref, repos in sorted(refs.items(), key=lambda kv: (-len(kv[1]), kv[0]))
            ],
        })

    inventory.sort(key=lambda a: (
        not (not a["trusted"] and a["pinning"] != "sha"),
        len(a["refs"]) <= 1,
        -a["repository_count"],
        a["action"].lower(),
    ))
    return inventory


# ---------------------------------------------------------------------------
# References: where a finding or an action use lives, as GitHub links.
# ---------------------------------------------------------------------------

DOCS_BASE = "https://actsense.dev/vulnerabilities/"
_USES_RE = re.compile(r"""^\s*-?\s*uses:\s*['"]?([^'"\s#]+)""")


def find_uses_lines(content: str) -> Dict[str, List[int]]:
    """Line numbers (1-based) of every ``uses:`` reference in a workflow file."""
    lines: Dict[str, List[int]] = defaultdict(list)
    for number, line in enumerate((content or "").splitlines(), start=1):
        match = _USES_RE.match(line)
        if match:
            lines[match.group(1)].append(number)
    return dict(lines)


def _blob_url(repository: str, branch: str, path: str, line: Optional[int] = None) -> str:
    url = f"https://github.com/{repository}/blob/{branch}/{path}"
    return f"{url}#L{line}" if line else url


def _line(value: Any) -> Optional[int]:
    try:
        number = int(value)
    except (TypeError, ValueError):
        return None
    return number if number > 0 else None


def _action_url(node: Dict[str, Any]) -> Optional[str]:
    """The action's directory at its pinned ref (action.yml vs action.yaml varies)."""
    meta = node.get("metadata") or {}
    owner, repo = meta.get("owner"), meta.get("repo")
    ref, subdir = meta.get("ref"), meta.get("subdir")
    if not (owner and repo) and "@" in node.get("id", ""):
        repo_part, ref = node["id"].rsplit("@", 1)
        parts = repo_part.split("/")
        if len(parts) >= 2:
            owner, repo = parts[0], parts[1]
            subdir = "/".join(parts[2:]) or None
    if not (owner and repo):
        return None
    url = f"https://github.com/{owner}/{repo}/tree/{ref or 'main'}"
    return f"{url}/{subdir}" if subdir else url


def collect_findings(repository: str, graph_data: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Flatten one repository's graph into findings with resolvable locations.

    Line numbers on workflow, image and action findings refer to the workflow
    file in the audited repository, so those link there; findings that belong
    to an action itself link to the action at its pinned ref.
    """
    nodes = {n["id"]: n for n in graph_data.get("nodes", [])}
    repo_node = nodes.get(repository) or {}
    branch = (repo_node.get("metadata") or {}).get("default_branch") or "main"

    parents: Dict[str, List[str]] = defaultdict(list)
    for edge in graph_data.get("edges", []):
        parents[edge.get("target")].append(edge.get("source"))

    def workflow_parents(node_id: str) -> List[Dict[str, Any]]:
        return [nodes[p] for p in parents.get(node_id, []) if nodes.get(p, {}).get("type") == "workflow"]

    def workflow_ref(wf: Dict[str, Any], line: Optional[int]) -> Optional[Dict[str, Any]]:
        path = (wf.get("metadata") or {}).get("path")
        if not path:
            return None
        return {"label": path, "path": path, "line": line, "url": _blob_url(repository, branch, path, line)}

    findings: List[Dict[str, Any]] = []
    # Findings are mirrored onto related nodes (an unpinned image onto the
    # image node) but are one finding: keep one, with the richer reference.
    by_fingerprint: Dict[str, Dict[str, Any]] = {}
    for node in graph_data.get("nodes", []):
        node_type = node.get("type")
        for issue in node.get("issues") or []:
            line = _line(issue.get("line_number"))
            location = None
            target = None
            if node_type == "workflow":
                location = workflow_ref(node, line)
            elif node_type == "repository":
                location = {"label": repository, "url": f"https://github.com/{repository}"}
            elif node_type == "reusable_workflow":
                meta = node.get("metadata") or {}
                if meta.get("owner") and meta.get("repo") and meta.get("subdir"):
                    remote = f"{meta['owner']}/{meta['repo']}"
                    location = {
                        "label": f"{remote}/{meta['subdir']}",
                        "path": meta["subdir"], "line": line,
                        "url": _blob_url(remote, meta.get("ref") or "main", meta["subdir"], line),
                    }
            else:
                # Actions, images and packages: the line is in the workflow using them.
                users = workflow_parents(node["id"])
                if len(users) == 1:
                    location = workflow_ref(users[0], line)
                elif users:
                    location = workflow_ref(users[0], None)
                if node_type == "action":
                    target = {"label": node.get("label") or node["id"], "url": _action_url(node)}
                else:
                    target = {"label": node.get("label") or node["id"], "url": None}
            fingerprint = issue.get("fingerprint")
            seen = by_fingerprint.get(fingerprint) if fingerprint else None
            if seen is not None:
                seen["target"] = seen["target"] or target
                if not (seen["location"] or {}).get("line") and (location or {}).get("line"):
                    seen["location"] = location
                continue
            finding = {
                "repository": repository,
                "fingerprint": issue.get("fingerprint"),
                "type": issue.get("type"),
                "severity": issue.get("severity", "low"),
                "message": issue.get("message", ""),
                "job": issue.get("job"),
                "dismissed": bool(issue.get("dismissed")),
                "node": {"id": node["id"], "type": node_type, "label": node.get("label") or node["id"]},
                "location": location,
                "target": target,
                "docs_url": f"{DOCS_BASE}{issue.get('type')}" if issue.get("type") else None,
            }
            findings.append(finding)
            if fingerprint:
                by_fingerprint[fingerprint] = finding
    return findings
