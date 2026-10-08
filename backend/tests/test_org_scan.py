"""Tests for organization-wide scans: repo listing, aggregation, storage and endpoints."""
import json
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from fastapi import HTTPException
from fastapi.testclient import TestClient

import main
import org_scan
from analysis_storage import AnalysisStorage
from dismissals import DismissalStore
from github_client import GitHubClient, RATE_LIMIT_DETAIL

SHA = "a" * 40


def _response(status, body=None, headers=None):
    resp = MagicMock()
    resp.status_code = status
    resp.json.return_value = body
    resp.headers = headers or {}
    resp.raise_for_status = MagicMock()
    return resp


def _repo(name, pushed="2026-01-01T00:00:00Z", **extra):
    return {"name": name, "full_name": f"acme/{name}", "private": False, "archived": False,
            "fork": False, "default_branch": "main", "pushed_at": pushed, **extra}


class TestParsing:
    @pytest.mark.parametrize("value,expected", [
        ("acme", "acme"),
        ("@acme", "acme"),
        ("https://github.com/acme", "acme"),
        ("https://github.com/acme/", "acme"),
        ("github.com/acme", "acme"),
        ("acme/repo", None),
        ("-bad", None),
        ("", None),
    ])
    def test_parse_owner(self, value, expected):
        assert org_scan.parse_owner(value) == expected

    def test_normalize_repositories(self):
        names, rejected = org_scan.normalize_repositories(
            "acme", ["api", "acme/web", "ACME/api", "other/x", "a/b/c", ".."]
        )
        assert names == ["api", "web"]
        assert rejected == ["other/x", "a/b/c", ".."]


class TestListOwnerRepositories:
    @pytest.mark.asyncio
    async def test_paginates_org_and_sorts_by_push(self):
        client = GitHubClient()
        page1 = [_repo(f"r{i}", pushed=f"2026-01-{i % 28 + 1:02d}T00:00:00Z") for i in range(100)]
        page2 = [_repo("newest", pushed="2026-09-01T00:00:00Z")]
        calls = []

        async def fake_get(url):
            calls.append(url)
            return _response(200, page1 if url.endswith("page=1") else page2)

        client._get = fake_get
        repos = await client.list_owner_repositories("acme")
        assert len(repos) == 101
        assert repos[0]["full_name"] == "acme/newest"
        assert all("/orgs/acme/repos" in u for u in calls)
        assert len(calls) == 2

    @pytest.mark.asyncio
    async def test_falls_back_to_user(self):
        client = GitHubClient()

        async def fake_get(url):
            if "/orgs/" in url:
                return _response(404)
            return _response(200, [_repo("dotfiles")])

        client._get = fake_get
        repos = await client.list_owner_repositories("someone")
        assert [r["name"] for r in repos] == ["dotfiles"]

    @pytest.mark.asyncio
    async def test_token_owner_uses_user_repos(self):
        client = GitHubClient(token="test-token")
        seen = []

        async def fake_get(url):
            seen.append(url)
            if "/orgs/" in url:
                return _response(404)
            if url.endswith("/user"):
                return _response(200, {"login": "Me"})
            return _response(200, [_repo("secret", private=True)])

        client._get = fake_get
        repos = await client.list_owner_repositories("me")
        assert repos[0]["private"] is True
        assert any("/user/repos?affiliation=owner" in u for u in seen)

    @pytest.mark.asyncio
    async def test_unknown_owner_returns_none(self):
        client = GitHubClient()
        client._get = AsyncMock(return_value=_response(404))
        assert await client.list_owner_repositories("nobody") is None

    @pytest.mark.asyncio
    async def test_rate_limit_raises(self):
        client = GitHubClient()
        client._get = AsyncMock(return_value=_response(403, headers={"X-RateLimit-Remaining": "0"}))
        with pytest.raises(HTTPException) as exc:
            await client.list_owner_repositories("acme")
        assert exc.value.detail == RATE_LIMIT_DETAIL

    @pytest.mark.asyncio
    async def test_bad_credentials_raise(self):
        client = GitHubClient(token="not-a-real-token")
        client._get = AsyncMock(return_value=_response(401, {"message": "Bad credentials"}))
        with pytest.raises(HTTPException) as exc:
            await client.list_owner_repositories("acme")
        assert exc.value.status_code == 403


class TestAggregation:
    def test_summarize(self):
        results = [
            {"status": "ok", "statistics": {"total_issues": 3, "dismissed_issues": 1,
                                            "severity_counts": {"high": 2, "low": 1}}},
            {"status": "no_workflows", "statistics": {"total_issues": 0}},
            {"status": "error", "statistics": {}},
            {"status": "skipped", "statistics": {}},
        ]
        s = org_scan.summarize(results)
        assert s["total_repositories"] == 4
        assert s["scanned_repositories"] == 2
        assert s["failed_repositories"] == 1
        assert s["skipped_repositories"] == 1
        assert s["repositories_with_issues"] == 1
        assert s["total_issues"] == 3
        assert s["dismissed_issues"] == 1
        assert s["severity_counts"] == {"critical": 0, "high": 2, "medium": 0, "low": 1}

    def test_action_inventory(self):
        data = {
            "acme/a": [{"actions": ["actions/checkout@v4", "evil/thing@v1", "docker://alpine:3"]}],
            "acme/b": [{"actions": ["actions/checkout@v3", f"evil/thing@{SHA}"]},
                       {"actions": ["actions/checkout@v3"]}],
            "acme/c": [{"actions": [f"safe-ish/tool@{SHA}"]}],
        }
        inv = {a["action"]: a for a in org_scan.build_action_inventory(data)}
        assert "docker://alpine:3" not in inv and "docker://alpine" not in inv

        checkout = inv["actions/checkout"]
        assert checkout["trusted"] is True
        assert checkout["pinning"] == "tag"
        assert checkout["repository_count"] == 2
        assert checkout["workflow_count"] == 3
        assert {r["ref"] for r in checkout["refs"]} == {"v3", "v4"}
        assert checkout["refs"][0]["ref"] == "v3"  # equal use, so ordered by ref

        assert inv["evil/thing"]["pinning"] == "mixed"
        assert inv["evil/thing"]["trusted"] is False
        assert inv["safe-ish/tool"]["pinning"] == "sha"

        order = [a["action"] for a in org_scan.build_action_inventory(data)]
        # Untrusted and not fully SHA-pinned sorts first.
        assert order[0] == "evil/thing"


class TestOrgScanStorage:
    def test_save_get_list_delete(self, tmp_path):
        storage = AnalysisStorage(storage_dir=str(tmp_path))
        scan_id = storage.save_org_scan({"org": "acme", "repositories": [], "statistics": {"total_issues": 0}})
        assert storage.get_org_scan(scan_id)["org"] == "acme"
        assert [s["id"] for s in storage.list_org_scans()] == [scan_id]
        assert storage.list_org_scans(org="ACME")[0]["id"] == scan_id
        assert storage.list_org_scans(org="other") == []
        # Org scans never show up as analyses.
        assert storage.list_analyses() == []
        assert storage.delete_org_scan(scan_id) is True
        assert storage.get_org_scan(scan_id) is None

    def test_rejects_non_uuid_ids(self, tmp_path):
        storage = AnalysisStorage(storage_dir=str(tmp_path))
        assert storage.get_org_scan("../../etc/passwd") is None
        assert storage.delete_org_scan("../x") is False


@pytest.fixture
def api(tmp_path):
    storage = AnalysisStorage(storage_dir=str(tmp_path / "analyses"))
    store = DismissalStore(path=str(tmp_path / "dismissals.json"))
    fake_client = MagicMock()
    fake_client.aclose = AsyncMock()
    with patch.object(main, "storage", storage), patch.object(main, "dismissals", store), \
            patch.object(main, "GitHubClient", return_value=fake_client):
        yield TestClient(main.app), storage, fake_client


async def _fake_audit(client, owner, repo, graph, use_clone=False, token=None, log_fn=None):
    """Stand-in for audit_repository: one workflow with one issue, except special names."""
    if repo == "broken":
        raise RuntimeError("boom")
    if repo == "limited":
        raise HTTPException(status_code=403, detail=RATE_LIMIT_DETAIL)
    repo_id = f"{owner}/{repo}"
    graph.add_node(repo_id, repo_id, "repository", {})
    if repo == "empty":
        return []
    if repo.startswith("unreadable"):
        graph.add_issues_to_node(repo_id, [{
            "type": "workflow_processing_error", "severity": "low",
            "message": "Failed to process workflow 'ci.yml': " + (
                f"403: {RATE_LIMIT_DETAIL}" if repo == "unreadable-limited" else "bad YAML"),
        }])
        return []
    wf_id = f"{repo_id}:ci.yml"
    graph.add_node(wf_id, "ci.yml", "workflow", {"path": ".github/workflows/ci.yml"})
    graph.add_edge(repo_id, wf_id, "contains")
    graph.add_issues_to_node(wf_id, [{"type": "unpinned_version", "severity": "high", "message": f"x in {repo}"}])
    log_fn and log_fn("Found 1 workflow(s)")
    return [{"workflow_name": "ci.yml", "workflow_path": ".github/workflows/ci.yml",
             "actions": ["actions/checkout@v4", "third/party@main"]}]


class TestOrgEndpoints:
    def test_list_repos_passes_header_token(self, api):
        client, _, fake = api
        fake.list_owner_repositories = AsyncMock(return_value=[_repo("api")])
        with patch.object(main, "GitHubClient", return_value=fake) as cls:
            resp = client.get("/api/orgs/acme/repos", headers={"X-GitHub-Token": "test-token"})
        assert resp.status_code == 200
        body = resp.json()
        assert body["org"] == "acme"
        assert body["repositories"][0]["name"] == "api"
        assert body["max_selectable"] == org_scan.MAX_ORG_SCAN_REPOS
        cls.assert_called_once_with(token="test-token")
        fake.aclose.assert_awaited()

    def test_list_repos_unknown_owner(self, api):
        client, _, fake = api
        fake.list_owner_repositories = AsyncMock(return_value=None)
        assert client.get("/api/orgs/nobody/repos").status_code == 404

    def test_list_repos_invalid_name(self, api):
        client, _, _ = api
        assert client.get("/api/orgs/-bad/repos").status_code == 400

    def test_scan_validates_input(self, api):
        client, _, _ = api
        assert client.post("/api/audit/org", json={"org": "acme", "repositories": []}).status_code == 400
        resp = client.post("/api/audit/org", json={"org": "acme", "repositories": ["other/x"]})
        assert resp.status_code == 400 and "other/x" in resp.json()["detail"]
        too_many = [f"r{i}" for i in range(org_scan.MAX_ORG_SCAN_REPOS + 1)]
        assert client.post("/api/audit/org", json={"org": "acme", "repositories": too_many}).status_code == 400

    def test_scan_stores_each_repo_and_summary(self, api):
        client, storage, fake = api
        with patch.object(main, "audit_repository", side_effect=_fake_audit):
            resp = client.post("/api/audit/org", json={
                "org": "https://github.com/acme",
                "repositories": ["api", "acme/web", "empty", "broken"],
            })
        assert resp.status_code == 200
        body = resp.json()
        by_repo = {r["repository"]: r for r in body["repositories"]}
        assert by_repo["acme/api"]["status"] == "ok"
        assert by_repo["acme/api"]["workflows"] == 1
        assert by_repo["acme/api"]["statistics"]["total_issues"] == 1
        assert by_repo["acme/empty"]["status"] == "no_workflows"
        assert by_repo["acme/broken"]["status"] == "error"
        assert by_repo["acme/broken"]["analysis_id"] is None

        stats = body["statistics"]
        assert stats["total_repositories"] == 4
        assert stats["failed_repositories"] == 1
        assert stats["total_issues"] == 2
        assert stats["severity_counts"]["high"] == 2

        inv = {a["action"]: a for a in body["action_inventory"]}
        assert inv["third/party"]["repository_count"] == 2

        # Each repository's analysis opens like a normal repository audit.
        analysis = client.get(f"/api/analyses/{by_repo['acme/api']['analysis_id']}").json()
        assert analysis["repository"] == "acme/api"
        assert storage.get_org_scan(body["id"])["org"] == "acme"
        assert client.get("/api/org-scans").json()[0]["id"] == body["id"]
        # One shared client for the whole scan, closed at the end.
        assert main.GitHubClient.call_count == 1
        fake.aclose.assert_awaited()

    def test_rate_limit_skips_remaining(self, api):
        client, _, _ = api
        repos = ["limited"] + [f"r{i}" for i in range(org_scan.ORG_SCAN_CONCURRENCY + 2)]
        with patch.object(main, "audit_repository", side_effect=_fake_audit), \
                patch.object(org_scan, "ORG_SCAN_CONCURRENCY", 1):
            body = client.post("/api/audit/org", json={"org": "acme", "repositories": repos}).json()
        statuses = [r["status"] for r in body["repositories"]]
        assert statuses[0] == "error"
        assert set(statuses[1:]) == {"skipped"}
        assert body["rate_limited"] is True

    def test_unprocessable_workflows_are_an_error_not_empty(self, api):
        client, _, _ = api
        with patch.object(main, "audit_repository", side_effect=_fake_audit):
            body = client.post("/api/audit/org", json={"org": "acme", "repositories": ["unreadable", "empty"]}).json()
        by_repo = {r["repository"]: r for r in body["repositories"]}
        assert by_repo["acme/unreadable"]["status"] == "error"
        assert "could not be processed" in by_repo["acme/unreadable"]["error"]
        assert by_repo["acme/empty"]["status"] == "no_workflows"
        assert body["rate_limited"] is False

    def test_rate_limited_workflow_fetch_stops_the_scan(self, api):
        client, _, _ = api
        with patch.object(main, "audit_repository", side_effect=_fake_audit), \
                patch.object(org_scan, "ORG_SCAN_CONCURRENCY", 1):
            body = client.post("/api/audit/org", json={
                "org": "acme", "repositories": ["unreadable-limited", "api"],
            }).json()
        assert [r["status"] for r in body["repositories"]] == ["error", "skipped"]
        assert body["rate_limited"] is True

    def test_dismissal_refreshes_org_scan_counts(self, api):
        client, _, _ = api
        with patch.object(main, "audit_repository", side_effect=_fake_audit):
            body = client.post("/api/audit/org", json={"org": "acme", "repositories": ["api"]}).json()
        analysis_id = body["repositories"][0]["analysis_id"]
        analysis = client.get(f"/api/analyses/{analysis_id}").json()
        fp = next(i["fingerprint"] for n in analysis["graph"]["nodes"] for i in n.get("issues", []))
        client.post(f"/api/analyses/{analysis_id}/dismissals", json={"fingerprint": fp, "reason": "ok"})

        scan = client.get(f"/api/org-scans/{body['id']}").json()
        assert scan["statistics"]["total_issues"] == 0
        assert scan["statistics"]["dismissed_issues"] == 1

    def test_deleted_analysis_is_reported(self, api):
        client, _, _ = api
        with patch.object(main, "audit_repository", side_effect=_fake_audit):
            body = client.post("/api/audit/org", json={"org": "acme", "repositories": ["api"]}).json()
        client.delete(f"/api/analyses/{body['repositories'][0]['analysis_id']}")
        scan = client.get(f"/api/org-scans/{body['id']}").json()
        assert scan["repositories"][0]["analysis_id"] is None
        assert "deleted" in scan["repositories"][0]["error"]

    def test_org_scan_not_found_and_delete(self, api):
        client, _, _ = api
        assert client.get("/api/org-scans/00000000-0000-0000-0000-000000000000").status_code == 404
        with patch.object(main, "audit_repository", side_effect=_fake_audit):
            scan_id = client.post("/api/audit/org", json={"org": "acme", "repositories": ["api"]}).json()["id"]
        assert client.delete(f"/api/org-scans/{scan_id}").status_code == 200
        assert client.get(f"/api/org-scans/{scan_id}").status_code == 404

    def test_stream_emits_progress_and_result(self, api):
        client, _, _ = api
        with patch.object(main, "audit_repository", side_effect=_fake_audit):
            resp = client.post("/api/audit/org/stream", json={"org": "acme", "repositories": ["api", "web"]})
        events = [block for block in resp.text.split("\n\n") if block.strip()]
        kinds = [e.split("\n")[0].removeprefix("event: ") for e in events]
        assert kinds.count("progress") == 2
        assert kinds[-1] == "result"
        assert "log" in kinds
        result = json.loads(events[-1].split("data: ", 1)[1])
        assert result["statistics"]["scanned_repositories"] == 2

    def test_single_repo_stream_still_works(self, api):
        client, _, _ = api
        with patch.object(main, "audit_repository", side_effect=_fake_audit):
            resp = client.post("/api/audit/stream", json={"repository": "acme/api"})
        assert "event: result" in resp.text
        with patch.object(main, "audit_repository", side_effect=_fake_audit):
            resp = client.post("/api/audit/stream", json={"repository": "acme/broken"})
        assert "event: error" in resp.text


class TestReferences:
    def test_find_uses_lines(self):
        content = (
            "jobs:\n  build:\n    steps:\n"
            "      - uses: actions/checkout@v4\n"
            "      - name: x\n        uses: 'evil/thing@v1' # comment\n"
            "      - uses: actions/checkout@v4\n"
        )
        assert org_scan.find_uses_lines(content) == {
            "actions/checkout@v4": [4, 7],
            "evil/thing@v1": [6],
        }

    def _graph(self):
        repo = "acme/api"
        wf = f"{repo}:ci.yml"
        action = "evil/thing/sub@v1"
        image = "image://alpine:3"
        return {
            "nodes": [
                {"id": repo, "label": repo, "type": "repository", "metadata": {"default_branch": "trunk"},
                 "issues": [{"type": "inconsistent_action_version", "severity": "low", "message": "m"}]},
                {"id": wf, "label": "ci.yml", "type": "workflow", "metadata": {"path": ".github/workflows/ci.yml"},
                 "issues": [{"type": "shell_injection", "severity": "high", "message": "inj", "line_number": 12,
                             "fingerprint": "fp1", "dismissed": {"reason": "ok"}}]},
                {"id": action, "label": action, "type": "action",
                 "metadata": {"owner": "evil", "repo": "thing", "ref": "v1", "subdir": "sub"},
                 "issues": [{"type": "unpinned_version", "severity": "high", "message": "tag", "line_number": "8"}]},
                {"id": image, "label": "alpine:3", "type": "image", "metadata": {},
                 "issues": [{"type": "unpinned_container_image", "severity": "medium", "message": "img", "line_number": 20}]},
            ],
            "edges": [
                {"source": repo, "target": wf, "type": "contains"},
                {"source": wf, "target": action, "type": "uses"},
                {"source": wf, "target": image, "type": "uses"},
            ],
        }

    def test_collect_findings_resolves_locations(self):
        findings = {f["type"]: f for f in org_scan.collect_findings("acme/api", self._graph())}
        blob = "https://github.com/acme/api/blob/trunk/.github/workflows/ci.yml"

        wf = findings["shell_injection"]
        assert wf["location"]["url"] == f"{blob}#L12"
        assert wf["location"]["line"] == 12
        assert wf["dismissed"] is True
        assert wf["docs_url"] == "https://actsense.dev/vulnerabilities/shell_injection"

        action = findings["unpinned_version"]
        assert action["location"]["url"] == f"{blob}#L8"
        assert action["target"]["url"] == "https://github.com/evil/thing/tree/v1/sub"

        image = findings["unpinned_container_image"]
        assert image["location"]["url"] == f"{blob}#L20"
        assert image["target"]["url"] is None

        repo = findings["inconsistent_action_version"]
        assert repo["location"]["url"] == "https://github.com/acme/api"

    def test_org_owned_actions_are_internal(self):
        data = {"acme/api": [{"actions": ["acme/shared/.github/workflows/ci.yml@main", "evil/thing@v1"]}]}
        inv = {a["action"]: a for a in org_scan.build_action_inventory(data, owner="ACME")}
        assert inv["acme/shared/.github/workflows/ci.yml"]["internal"] is True
        assert inv["acme/shared/.github/workflows/ci.yml"]["trusted"] is True
        assert inv["evil/thing"]["internal"] is False

    def test_mirrored_findings_count_once(self):
        graph = self._graph()
        issue = {"type": "unpinned_container_image", "severity": "medium", "message": "img",
                 "line_number": 20, "fingerprint": "same"}
        graph["nodes"][1]["issues"].append(dict(issue))
        graph["nodes"][3]["issues"] = [dict(issue)]
        findings = [f for f in org_scan.collect_findings("acme/api", graph) if f["type"] == "unpinned_container_image"]
        assert len(findings) == 1
        assert findings[0]["target"]["label"] == "alpine:3"

    def test_inventory_usages_link_to_lines(self):
        data = {"acme/api": [{
            "workflow_path": ".github/workflows/ci.yml",
            "actions": ["actions/checkout@v4"],
            "uses_lines": {"actions/checkout@v4": [4, 9]},
        }]}
        inv = org_scan.build_action_inventory(data, {"acme/api": "trunk"})
        usages = inv[0]["refs"][0]["usages"]
        assert [u["line"] for u in usages] == [4, 9]
        assert usages[0]["url"] == "https://github.com/acme/api/blob/trunk/.github/workflows/ci.yml#L4"


class TestOrgFindingsEndpoint:
    def test_findings_across_repositories(self, api):
        client, _, _ = api
        with patch.object(main, "audit_repository", side_effect=_fake_audit):
            body = client.post("/api/audit/org", json={"org": "acme", "repositories": ["api", "web", "broken"]}).json()
        resp = client.get(f"/api/org-scans/{body['id']}/findings")
        assert resp.status_code == 200
        findings = resp.json()["findings"]
        assert {f["repository"] for f in findings} == {"acme/api", "acme/web"}
        assert all(f["location"]["url"].startswith("https://github.com/acme/") for f in findings)

    def test_findings_unknown_scan(self, api):
        client, _, _ = api
        assert client.get("/api/org-scans/00000000-0000-0000-0000-000000000000/findings").status_code == 404
