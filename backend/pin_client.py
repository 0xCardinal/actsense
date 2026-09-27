"""Client for pin.actsense.dev, which resolves mutable references to immutable ones.

    GET {PIN_API_URL}/api/resolve?q=actions/checkout@v4
    -> {"ok": true, "result": {"hash": "11d5...", "hashKind": "commit-sha", ...},
        "pin": "actions/checkout@11d5... # v4"}

Used by the auto-fix endpoint so tag -> SHA and tag -> digest pinning works
without the user supplying a GitHub token. Any failure (network error, non-JSON
error page, ``ok: false``) returns None so callers can fall back to the GitHub
API. Set PIN_API_URL to an empty string to disable the service entirely.
"""
import os
import re
import time
from typing import Dict, Optional, Tuple

import httpx

PIN_API_URL = os.environ.get("PIN_API_URL", "https://pin.actsense.dev").rstrip("/")
_TIMEOUT = 8.0
_CACHE_TTL = 3600.0
_cache: Dict[str, Tuple[float, Optional[Dict[str, str]]]] = {}

_SHA_RE = re.compile(r"^[0-9a-f]{40}$")
_DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{64}$")


def action_query(action_ref: str) -> Optional[str]:
    """Repository-level query for an action ref.

    ``owner/repo/sub/path@v3`` and ``owner/repo@v3`` point at the same commit,
    and the service resolves the repository form, so strip the sub-path.
    """
    if "@" not in action_ref or action_ref.startswith(("./", "docker://")):
        return None
    name, ref = action_ref.rsplit("@", 1)
    parts = name.split("/")
    if len(parts) < 2 or not parts[0] or not parts[1] or not ref:
        return None
    return f"{parts[0]}/{parts[1]}@{ref}"


def image_query(image: str) -> Optional[str]:
    """Registry query for a container image reference (``docker://`` stripped)."""
    image = image[len("docker://"):] if image.startswith("docker://") else image
    if not image or "@sha256:" in image or "${{" in image:
        return None
    return image


async def resolve(query: str, http: Optional[httpx.AsyncClient] = None) -> Optional[Dict[str, str]]:
    """Resolve ``query`` to ``{"hash", "kind"}``, or None when it cannot be resolved."""
    if not PIN_API_URL or not query:
        return None
    now = time.monotonic()
    cached = _cache.get(query)
    if cached and now - cached[0] < _CACHE_TTL:
        return cached[1]

    result: Optional[Dict[str, str]] = None
    try:
        if http is None:
            async with httpx.AsyncClient() as own:
                response = await own.get(f"{PIN_API_URL}/api/resolve", params={"q": query}, timeout=_TIMEOUT)
        else:
            response = await http.get(f"{PIN_API_URL}/api/resolve", params={"q": query}, timeout=_TIMEOUT)
        if "json" in response.headers.get("content-type", ""):
            body = response.json()
            data = body.get("result") or {}
            digest = str(data.get("hash", "")).lower()
            kind = data.get("hashKind", "")
            # Only accept values that look like what they claim to be.
            if body.get("ok") and (
                (kind == "commit-sha" and _SHA_RE.match(digest))
                or (kind == "oci-digest" and _DIGEST_RE.match(digest))
            ):
                result = {"hash": digest, "kind": kind}
    except (httpx.HTTPError, ValueError):
        result = None

    # Cache failures briefly too, so one bad lookup is not retried per line.
    _cache[query] = (now if result else now - _CACHE_TTL + 60, result)
    return result
