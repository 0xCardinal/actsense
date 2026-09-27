"""Tests for dismissing findings (fingerprints, store, stats and API)."""
import copy
import json

import pytest
from fastapi.testclient import TestClient

import main
from analysis_storage import AnalysisStorage
from dismissals import DismissalStore, apply_dismissals, fingerprint
from graph_builder import GraphBuilder


def _older_version_issue(latest="v5", line=12):
    return {
        "type": "older_action_version",
        "severity": "medium",
        "message": f"Action 'actions/checkout@v3' uses version 'v3', but the latest version is '{latest}'.",
        "action": "actions/checkout@v3",
        "version": "v3",
        "latest_version": latest,
        "line_number": line,
        "evidence": {"latest": latest},
        "recommendation": "See docs",
    }


class TestFingerprint:
    def test_ignores_line_numbers_and_latest_version(self):
        a = fingerprint("o/r:ci.yml", _older_version_issue("v5", 12))
        b = fingerprint("o/r:ci.yml", _older_version_issue("v6", 40))
        assert a == b

    def test_depends_on_node(self):
        issue = _older_version_issue()
        assert fingerprint("o/r:ci.yml", issue) != fingerprint("o/r:release.yml", issue)

    def test_depends_on_identifying_fields(self):
        other = dict(_older_version_issue(), version="v2", action="actions/checkout@v2")
        assert fingerprint("n", _older_version_issue()) != fingerprint("n", other)

    def test_distinguishes_findings_that_differ_only_in_message(self):
        a = {"type": "optional_secret_input", "severity": "low", "message": "Input 'token' is optional"}
        b = {"type": "optional_secret_input", "severity": "low", "message": "Input 'api_key' is optional"}
        assert fingerprint("n", a) != fingerprint("n", b)

    def test_ignores_severity_changes(self):
        issue = _older_version_issue()
        assert fingerprint("n", issue) == fingerprint("n", dict(issue, severity="high"))


def _graph_with_mirror():
    """A workflow finding mirrored onto a package node, as main.py does."""
    graph = GraphBuilder()
    graph.add_node("o/r:ci.yml", "ci.yml", "workflow")
    graph.add_node("pkg:npm/left-pad", "left-pad", "package")
    shared = {"type": "unpinned_npm_packages", "severity": "medium", "message": "npm install left-pad"}
    other = {"type": "dangerous_event", "severity": "high", "message": "pull_request_target"}
    graph.add_issues_to_node("o/r:ci.yml", [shared, other])
    graph.add_issues_to_node("pkg:npm/left-pad", [shared])
    graph.add_edge("o/r:ci.yml", "pkg:npm/left-pad")
    return graph, shared, other


class TestApplyAndStatistics:
    def test_tags_fingerprints_without_dismissals(self):
        graph, shared, other = _graph_with_mirror()
        apply_dismissals(graph.nodes.values(), {})
        assert shared["fingerprint"] == fingerprint("o/r:ci.yml", shared)
        assert "dismissed" not in other
        stats = graph.get_statistics()
        assert stats["total_issues"] == 2
        assert stats["dismissed_issues"] == 0

    def test_dismissed_issue_leaves_counts_and_node_severity(self):
        graph, shared, other = _graph_with_mirror()
        apply_dismissals(graph.nodes.values(), {})
        fp = other["fingerprint"]
        apply_dismissals(graph.nodes.values(), {fp: {"reason": "intended", "dismissed_at": "t"}})

        assert other["dismissed"] == {"reason": "intended", "dismissed_at": "t"}
        stats = graph.get_statistics()
        assert stats["total_issues"] == 1
        assert stats["dismissed_issues"] == 1
        assert stats["severity_counts"] == {"medium": 1}

        data = graph.get_graph_data()
        workflow = next(n for n in data["nodes"] if n["id"] == "o/r:ci.yml")
        assert workflow["issue_count"] == 1
        assert workflow["severity"] == "medium"

    def test_mirrored_finding_is_dismissed_with_its_source(self):
        graph, shared, _ = _graph_with_mirror()
        data = json.loads(json.dumps(graph.get_graph_data()))  # a stored copy: no shared objects
        rebuilt = GraphBuilder.from_graph_data(data)
        apply_dismissals(rebuilt.nodes.values(), {})
        mirror = rebuilt.nodes["pkg:npm/left-pad"]["issues"][0]
        source = rebuilt.nodes["o/r:ci.yml"]["issues"][0]
        assert mirror["fingerprint"] == source["fingerprint"]

        apply_dismissals(rebuilt.nodes.values(), {source["fingerprint"]: {"reason": "", "dismissed_at": "t"}})
        assert rebuilt.get_statistics()["dismissed_issues"] == 1
        package = next(n for n in rebuilt.get_graph_data()["nodes"] if n["id"] == "pkg:npm/left-pad")
        assert package["issue_count"] == 0
        assert package["severity"] == "none"

    def test_stored_copy_counts_mirrors_once(self):
        graph, _, _ = _graph_with_mirror()
        apply_dismissals(graph.nodes.values(), {})
        fresh = graph.get_statistics()
        rebuilt = GraphBuilder.from_graph_data(json.loads(json.dumps(graph.get_graph_data())))
        apply_dismissals(rebuilt.nodes.values(), {})
        assert rebuilt.get_statistics() == fresh

    def test_restoring_clears_the_flag(self):
        graph, _, other = _graph_with_mirror()
        apply_dismissals(graph.nodes.values(), {})
        apply_dismissals(graph.nodes.values(), {other["fingerprint"]: {"reason": "", "dismissed_at": "t"}})
        apply_dismissals(graph.nodes.values(), {})
        assert "dismissed" not in other


class TestDismissalStore:
    def test_add_list_remove(self, tmp_path):
        store = DismissalStore(str(tmp_path / "dismissals.json"))
        issue = _older_version_issue()
        store.add("o/r", "abc", issue, "o/r:ci.yml", "  test workflow  ")

        [record] = store.list("o/r")
        assert record["fingerprint"] == "abc"
        assert record["reason"] == "test workflow"
        assert record["type"] == "older_action_version"
        assert record["node"] == "o/r:ci.yml"
        assert store.get("other/repo") == {}
        assert store.get(None) == {}

        # Persisted across instances.
        assert "abc" in DismissalStore(str(tmp_path / "dismissals.json")).get("o/r")

        assert store.remove("o/r", "abc") is True
        assert store.remove("o/r", "abc") is False
        assert store.list("o/r") == []

    def test_reason_is_capped(self, tmp_path):
        store = DismissalStore(str(tmp_path / "d.json"))
        record = store.add("o/r", "abc", {}, "n", "x" * 5000)
        assert len(record["reason"]) == 500


@pytest.fixture
def api(tmp_path, monkeypatch):
    monkeypatch.setattr(main, "storage", AnalysisStorage(str(tmp_path / "analyses")))
    monkeypatch.setattr(main, "dismissals", DismissalStore(str(tmp_path / "dismissals.json")))
    return TestClient(main.app)


def _store_analysis(repository="o/r"):
    graph, _, _ = _graph_with_mirror()
    return main.storage.save_analysis(
        repository=repository,
        action=None,
        graph_data=copy.deepcopy(graph.get_graph_data()),
        statistics=graph.get_statistics(),
    )


def _issue(analysis, node_id, issue_type):
    node = next(n for n in analysis["graph"]["nodes"] if n["id"] == node_id)
    return next(i for i in node["issues"] if i["type"] == issue_type)


class TestDismissalEndpoints:
    def test_dismiss_and_restore(self, api):
        analysis_id = _store_analysis()
        analysis = api.get(f"/api/analyses/{analysis_id}").json()
        fp = _issue(analysis, "o/r:ci.yml", "dangerous_event")["fingerprint"]

        response = api.post(f"/api/analyses/{analysis_id}/dismissals", json={"fingerprint": fp, "reason": "intended"})
        assert response.status_code == 200
        updated = response.json()
        assert _issue(updated, "o/r:ci.yml", "dangerous_event")["dismissed"]["reason"] == "intended"
        assert updated["statistics"]["total_issues"] == 1
        assert updated["statistics"]["dismissed_issues"] == 1

        [record] = api.get("/api/dismissals", params={"target": "o/r"}).json()
        assert record["fingerprint"] == fp

        response = api.delete(f"/api/analyses/{analysis_id}/dismissals/{fp}")
        assert response.status_code == 200
        restored = response.json()
        assert "dismissed" not in _issue(restored, "o/r:ci.yml", "dangerous_event")
        assert restored["statistics"]["dismissed_issues"] == 0

    def test_dismissal_carries_over_to_other_runs_of_the_target(self, api):
        first = _store_analysis()
        second = _store_analysis()
        other_repo = _store_analysis("someone/else")
        fp = _issue(api.get(f"/api/analyses/{first}").json(), "o/r:ci.yml", "dangerous_event")["fingerprint"]
        api.post(f"/api/analyses/{first}/dismissals", json={"fingerprint": fp})

        assert _issue(api.get(f"/api/analyses/{second}").json(), "o/r:ci.yml", "dangerous_event").get("dismissed")
        assert not _issue(api.get(f"/api/analyses/{other_repo}").json(), "o/r:ci.yml", "dangerous_event").get("dismissed")

    def test_unknown_fingerprint(self, api):
        analysis_id = _store_analysis()
        response = api.post(f"/api/analyses/{analysis_id}/dismissals", json={"fingerprint": "nope"})
        assert response.status_code == 404
        assert api.delete(f"/api/analyses/{analysis_id}/dismissals/nope").status_code == 404

    def test_unknown_analysis(self, api):
        response = api.post("/api/analyses/missing/dismissals", json={"fingerprint": "x"})
        assert response.status_code == 404

    def test_inline_yaml_analysis_cannot_dismiss(self, api):
        analysis_id = _store_analysis(repository=None)
        analysis = api.get(f"/api/analyses/{analysis_id}").json()
        fp = _issue(analysis, "o/r:ci.yml", "dangerous_event")["fingerprint"]
        response = api.post(f"/api/analyses/{analysis_id}/dismissals", json={"fingerprint": fp})
        assert response.status_code == 400
