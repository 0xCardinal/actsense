"""Tests for the pin.actsense.dev integration used by the auto-fix endpoint."""
import pytest
from unittest.mock import AsyncMock, MagicMock, patch

import pin_client

SHA = "11d5960a326750d5838078e36cf38b85af677262"
DIGEST = "sha256:" + "a" * 64


@pytest.fixture(autouse=True)
def _clear_cache():
    pin_client._cache.clear()
    yield
    pin_client._cache.clear()


def _response(status=200, json_body=None, content_type="application/json"):
    resp = MagicMock()
    resp.status_code = status
    resp.headers = {"content-type": content_type}
    resp.json.return_value = json_body
    return resp


def _http(response):
    http = MagicMock()
    http.get = AsyncMock(return_value=response)
    return http


@pytest.mark.parametrize("ref,expected", [
    ("actions/checkout@v4", "actions/checkout@v4"),
    ("github/codeql-action/init@v3", "github/codeql-action@v3"),
    ("./local/action", None),
    ("docker://alpine:3", None),
    ("noslash@v1", None),
])
def test_action_query(ref, expected):
    assert pin_client.action_query(ref) == expected


def test_image_query_strips_docker_scheme_and_skips_pinned():
    assert pin_client.image_query("docker://alpine:3.20") == "alpine:3.20"
    assert pin_client.image_query("alpine@sha256:" + "b" * 64) is None
    assert pin_client.image_query("${{ matrix.image }}") is None


@pytest.mark.asyncio
async def test_resolves_commit_sha():
    http = _http(_response(json_body={"ok": True, "result": {"hash": SHA, "hashKind": "commit-sha"}}))
    assert await pin_client.resolve("actions/checkout@v4", http) == {"hash": SHA, "kind": "commit-sha"}


@pytest.mark.asyncio
async def test_resolves_oci_digest():
    http = _http(_response(json_body={"ok": True, "result": {"hash": DIGEST, "hashKind": "oci-digest"}}))
    assert await pin_client.resolve("nginx:1.27", http) == {"hash": DIGEST, "kind": "oci-digest"}


@pytest.mark.asyncio
@pytest.mark.parametrize("response", [
    _response(502, None, "text/html"),                                   # Cloudflare error page
    _response(400, {"ok": False, "error": "unparseable"}),
    _response(200, {"ok": True, "result": {"hash": "not-a-sha", "hashKind": "commit-sha"}}),
])
async def test_failures_return_none(response):
    assert await pin_client.resolve("x/y@v1", _http(response)) is None


@pytest.mark.asyncio
async def test_results_are_cached():
    http = _http(_response(json_body={"ok": True, "result": {"hash": SHA, "hashKind": "commit-sha"}}))
    await pin_client.resolve("actions/checkout@v4", http)
    await pin_client.resolve("actions/checkout@v4", http)
    assert http.get.await_count == 1


def test_fix_endpoint_uses_pin_and_marks_unresolved_as_manual():
    from fastapi.testclient import TestClient
    import main

    async def fake_resolve(query, http=None):
        return {"hash": SHA, "kind": "commit-sha"} if query == "actions/checkout@v4" else None

    yaml_text = (
        "on: push\njobs:\n  a:\n    runs-on: ubuntu-latest\n    steps:\n"
        "      - uses: actions/checkout@v4\n      - uses: org/other@v1\n"
    )
    fake_client = MagicMock()
    fake_client.parse_action_reference = main.GitHubClient().parse_action_reference
    fake_client.resolve_tag_to_sha = AsyncMock(return_value=None)
    fake_client.aclose = AsyncMock()
    with patch("main.pin_client.resolve", side_effect=fake_resolve), \
         patch("main.GitHubClient", return_value=fake_client), \
         patch("main.auditor.audit_workflow", new=AsyncMock(return_value=[
             {"type": "no_hash_pinning", "action": "actions/checkout@v4", "severity": "medium"},
             {"type": "no_hash_pinning", "action": "org/other@v1", "severity": "medium"},
         ])):
        body = TestClient(main.app).post("/api/audit/fix", json={"yaml_content": yaml_text}).json()

    by_action = {f["original"].strip(): f for f in body["fixes"]}
    pinned = by_action["- uses: actions/checkout@v4"]
    assert pinned["replacement"].strip() == f"- uses: actions/checkout@{SHA} # v4"
    assert pinned["resolved_by"] == "pin.actsense.dev"
    assert by_action["- uses: org/other@v1"]["manual"] is True
