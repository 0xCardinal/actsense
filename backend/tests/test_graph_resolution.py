"""Tests for dependency-graph resolution depth and fidelity."""
import pytest
from fastapi import HTTPException

import main
from github_client import GitHubClient
from graph_builder import GraphBuilder


class FakeGitHub(GitHubClient):
    """In-memory GitHub: files keyed by (owner, repo, path, ref)."""

    def __init__(self, files, missing_repos=(), rate_limited_repo_info=False):
        super().__init__()
        self.files = files
        self.missing_repos = set(missing_repos)
        self.rate_limited_repo_info = rate_limited_repo_info
        self.fetches = []

    async def get_repository_info(self, owner, repo):
        if self.rate_limited_repo_info:
            raise HTTPException(status_code=403, detail="rate limit")
        if f"{owner}/{repo}" in self.missing_repos:
            return None
        return {"name": repo, "private": False, "default_branch": "main"}

    async def get_file_content(self, owner, repo, path, ref=None):
        self.fetches.append((owner, repo, path, ref))
        key = (owner, repo, path, ref)
        if key not in self.files:
            raise HTTPException(status_code=404, detail="not found")
        return self.files[key]

    async def get_workflows(self, owner, repo):
        prefix = ".github/workflows/"
        return [
            {"name": path[len(prefix):], "path": path}
            for (o, r, path, ref) in self.files
            if o == owner and r == repo and ref is None and path.startswith(prefix)
        ]

    async def get_latest_tag(self, owner, repo):
        return None

    async def get_commit_date(self, owner, repo, sha):
        return None

    async def resolve_tag_to_sha(self, owner, repo, tag):
        return None


def _depths(graph):
    return {n["id"]: n["depth"] for n in graph.get_graph_data()["nodes"]}


COMPOSITE = """
runs:
  using: composite
  steps:
    - uses: actions/setup-node@v4
    - uses: org/inner@v2
"""
INNER = """
runs:
  using: composite
  steps:
    - uses: org/leaf@v3
"""
LEAF = """
runs:
  using: node20
  main: dist/index.js
"""


@pytest.mark.asyncio
async def test_metadata_is_fetched_at_the_pinned_ref():
    client = FakeGitHub({("org", "leaf", "action.yml", "v3"): LEAF})
    graph = GraphBuilder()
    await main.resolve_action_dependencies(client, "org/leaf@v3", graph, set())
    assert ("org", "leaf", "action.yml", "v3") in client.fetches
    assert all(ref == "v3" for (_, _, _, ref) in client.fetches)


@pytest.mark.asyncio
async def test_repository_to_nested_composite_actions_goes_deep():
    workflow = """
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: ./.github/actions/setup
"""
    client = FakeGitHub({
        ("o", "r", ".github/workflows/ci.yml", None): workflow,
        ("o", "r", ".github/actions/setup/action.yml", "main"): COMPOSITE,
        ("org", "inner", "action.yml", "v2"): INNER,
        ("org", "leaf", "action.yml", "v3"): LEAF,
        ("actions", "setup-node", "action.yml", "v4"): LEAF,
    })
    graph = GraphBuilder()
    await main.audit_repository(client, "o", "r", graph)

    depths = _depths(graph)
    local_id = "o/r/.github/actions/setup@main"
    assert depths["o/r"] == 0
    assert depths["o/r:ci.yml"] == 1
    assert depths[local_id] == 2
    assert depths["org/inner@v2"] == 3
    assert depths["org/leaf@v3"] == 4
    assert graph.nodes[local_id]["label"] == "./.github/actions/setup"
    assert graph.nodes[local_id]["metadata"]["local"] is True
    assert graph.get_statistics()["max_depth"] == 4


@pytest.mark.asyncio
async def test_nested_local_reusable_workflows_resolve_in_called_repo():
    caller = """
on: push
jobs:
  call:
    uses: ./.github/workflows/build.yml
"""
    build = """
on: workflow_call
jobs:
  inner:
    uses: ./.github/workflows/steps.yml
"""
    steps = """
on: workflow_call
jobs:
  s:
    runs-on: ubuntu-latest
    steps:
      - uses: org/leaf@v3
"""
    client = FakeGitHub({
        ("o", "r", ".github/workflows/ci.yml", None): caller,
        ("o", "r", ".github/workflows/build.yml", "main"): build,
        ("o", "r", ".github/workflows/steps.yml", "main"): steps,
        ("org", "leaf", "action.yml", "v3"): LEAF,
    })
    graph = GraphBuilder()
    await main.audit_repository(client, "o", "r", graph)

    depths = _depths(graph)
    assert graph.nodes["o/r/.github/workflows/build.yml@main"]["type"] == "reusable_workflow"
    assert depths["o/r/.github/workflows/steps.yml@main"] == 3
    assert depths["org/leaf@v3"] == 4


@pytest.mark.asyncio
async def test_rate_limited_existence_check_does_not_stop_resolution():
    client = FakeGitHub({
        ("org", "inner", "action.yml", "v2"): INNER,
        ("org", "leaf", "action.yml", "v3"): LEAF,
    }, rate_limited_repo_info=True)
    graph = GraphBuilder()
    await main.resolve_action_dependencies(client, "org/inner@v2", graph, set())
    assert "org/leaf@v3" in graph.nodes
    assert not any(i["type"] == "missing_action_repository" for i in graph.nodes["org/inner@v2"]["issues"])


@pytest.mark.asyncio
async def test_docker_action_links_registry_image_and_dockerfile_base():
    client = FakeGitHub({
        ("org", "img", "action.yml", "v1"): "runs:\n  using: docker\n  image: docker://ghcr.io/org/tool:1.2\n",
        ("org", "df", "action.yml", "v1"): "runs:\n  using: docker\n  image: Dockerfile\n",
        ("org", "df", "Dockerfile", "v1"): "FROM golang:1.22 AS build\nFROM build AS test\nFROM alpine@sha256:" + "b" * 64 + "\n",
    })
    graph = GraphBuilder()
    await main.resolve_action_dependencies(client, "org/img@v1", graph, set())
    await main.resolve_action_dependencies(client, "org/df@v1", graph, set())

    edges = {(e["source"], e["target"]) for e in graph.edges}
    assert ("org/img@v1", "image://ghcr.io/org/tool:1.2") in edges
    assert ("org/df@v1", "image://golang:1.22") in edges
    assert ("org/df@v1", "image://build") not in edges  # build stage, not an image
    assert graph.nodes["image://golang:1.22"]["issues"]
    assert graph.nodes["image://golang:1.22"]["metadata"]["roles"] == ["Dockerfile base"]
    assert graph.nodes["image://ghcr.io/org/tool:1.2"]["metadata"]["roles"] == ["Action image"]
    assert not graph.nodes["image://alpine@sha256:" + "b" * 64]["issues"]


@pytest.mark.asyncio
async def test_same_image_in_two_roles_is_one_node():
    workflow = """
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    container: alpine:3.20
    services:
      cache:
        image: redis:7
    steps:
      - uses: docker://alpine:3.20
"""
    client = FakeGitHub({("o", "r", ".github/workflows/ci.yml", None): workflow})
    graph = GraphBuilder()
    await main.audit_repository(client, "o", "r", graph)

    image_nodes = [n for n in graph.nodes.values() if n["type"] == "image"]
    assert sorted(n["id"] for n in image_nodes) == ["image://alpine:3.20", "image://redis:7"]
    assert sorted(graph.nodes["image://alpine:3.20"]["metadata"]["roles"]) == ["Job container", "Step image"]
    assert graph.nodes["image://redis:7"]["metadata"]["roles"] == ["Service"]
    assert not any(n["type"] in ("docker_image", "container_image") for n in graph.nodes.values())


def test_direct_edges_are_kept_when_also_reachable_transitively():
    graph = GraphBuilder()
    for n in ("wf", "composite", "actions/checkout@v4"):
        graph.add_node(n, n)
    graph.add_edge("wf", "composite")
    graph.add_edge("composite", "actions/checkout@v4")
    graph.add_edge("wf", "actions/checkout@v4")
    edges = {(e["source"], e["target"]) for e in graph.get_graph_data()["edges"]}
    assert ("wf", "actions/checkout@v4") in edges


def test_statistics_count_mirrored_issues_once():
    graph = GraphBuilder()
    graph.add_node("wf", "wf")
    graph.add_node("package://npm/x", "x", "package")
    issue = {"type": "unpinned_npm_packages", "severity": "high"}
    graph.add_issues_to_node("wf", [issue])
    graph.add_issues_to_node("package://npm/x", [issue])
    graph.add_issues_to_node("wf", [])
    stats = graph.get_statistics()
    assert stats["total_issues"] == 1
    assert stats["severity_counts"] == {"high": 1}
    assert stats["nodes_with_issues"] == 2


def test_inline_yaml_audit_records_step_image_role():
    from fastapi.testclient import TestClient
    yaml_text = (
        "on: push\njobs:\n  build:\n    runs-on: ubuntu-latest\n    container: alpine:3.20\n"
        "    steps:\n      - uses: docker://alpine:3.20\n"
    )
    body = TestClient(main.app).post("/api/audit/yaml", json={"yaml_content": yaml_text}).json()
    nodes = {n["id"]: n for n in body["graph"]["nodes"]}
    assert sorted(nodes["image://alpine:3.20"]["metadata"]["roles"]) == ["Job container", "Step image"]
    # Every edge points at a real node.
    assert all(e["target"] in nodes and e["source"] in nodes for e in body["graph"]["edges"])
