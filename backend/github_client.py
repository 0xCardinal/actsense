"""GitHub API client for fetching repositories and actions."""
import asyncio
import base64
import re
from typing import Optional, Dict, Any
from urllib.parse import quote

import httpx
from fastapi import HTTPException

RATE_LIMIT_DETAIL = (
    "GitHub API rate limit exceeded. Please provide a GitHub token to increase "
    "your rate limit from 60/hour to 5000/hour."
)

# Responses worth memoizing for the lifetime of one client (one audit request).
# 404s are cached too: "this file/tag does not exist" is as stable as a hit.
_CACHEABLE_STATUS = (200, 404)


def _parse_version(version_str: str) -> tuple:
    """Parse 'v1.2.3' / '1.2' / 'v4' into a comparable (major, minor, patch) tuple."""
    if version_str.startswith("v"):
        version_str = version_str[1:]
    match = re.match(r'^(\d+)\.?(\d*)?\.?(\d*)?', version_str)
    if match:
        major = int(match.group(1))
        minor = int(match.group(2)) if match.group(2) else 0
        patch = int(match.group(3)) if match.group(3) else 0
        return (major, minor, patch)
    return (0, 0, 0)


class GitHubClient:
    """Thin async GitHub REST client.

    One instance is created per audit request. It keeps a single pooled HTTP
    connection and memoizes GET responses by URL, so the many checks that ask
    the same question (repository info, latest tag, commit dates, ...) for the
    same action only cost one API call per audit instead of one per check per
    workflow. Concurrent identical requests share one in-flight call.
    """

    def __init__(self, token: Optional[str] = None):
        self.token = token
        self.base_url = "https://api.github.com"
        self.headers = {
            "Accept": "application/vnd.github.v3+json",
        }
        if token:
            self.headers["Authorization"] = f"token {token}"
        self._http: Optional[httpx.AsyncClient] = None
        self._cache: Dict[str, httpx.Response] = {}
        self._inflight: Dict[str, "asyncio.Future[httpx.Response]"] = {}

    async def aclose(self) -> None:
        """Close the pooled HTTP connection."""
        if self._http is not None:
            try:
                await self._http.aclose()
            except Exception:
                pass
            self._http = None

    async def _get(self, url: str) -> httpx.Response:
        """GET with per-client memoization and in-flight de-duplication."""
        cached = self._cache.get(url)
        if cached is not None:
            return cached
        pending = self._inflight.get(url)
        if pending is not None:
            return await pending

        loop = asyncio.get_running_loop()
        future: "asyncio.Future[httpx.Response]" = loop.create_future()
        self._inflight[url] = future
        try:
            if self._http is None:
                self._http = httpx.AsyncClient(follow_redirects=True)
            response = await self._http.get(url, headers=self.headers, timeout=10.0)
            if getattr(response, "status_code", None) in _CACHEABLE_STATUS:
                self._cache[url] = response
            future.set_result(response)
            return response
        except BaseException as exc:
            future.set_exception(exc)
            # Mark the exception as retrieved so asyncio does not warn when no
            # concurrent waiter was attached to this future.
            future.exception()
            raise
        finally:
            self._inflight.pop(url, None)

    @staticmethod
    def _is_rate_limited(response: httpx.Response) -> bool:
        if response.status_code == 429:
            return True
        if response.status_code != 403:
            return False
        headers = response.headers
        if isinstance(headers.get("Retry-After"), str):
            return True  # secondary rate limit
        return headers.get("X-RateLimit-Remaining", "0") == "0"

    def _contents_url(self, owner: str, repo: str, path: str, ref: Optional[str]) -> str:
        url = f"{self.base_url}/repos/{owner}/{repo}/contents/{quote(path, safe='/')}"
        if ref:
            url += f"?ref={quote(ref, safe='')}"
        return url

    async def get_repo_contents(self, owner: str, repo: str, path: str = "", ref: Optional[str] = None) -> Dict[str, Any]:
        """Get repository contents at a specific path (optionally at a git ref)."""
        response = await self._get(self._contents_url(owner, repo, path, ref))
        if self._is_rate_limited(response):
            raise HTTPException(status_code=403, detail=RATE_LIMIT_DETAIL)
        response.raise_for_status()
        return response.json()

    async def get_file_content(self, owner: str, repo: str, path: str, ref: Optional[str] = None) -> str:
        """Get file content from repository, at ``ref`` when given (default branch otherwise)."""
        try:
            if ref:
                contents = await self.get_repo_contents(owner, repo, path, ref=ref)
            else:
                contents = await self.get_repo_contents(owner, repo, path)
        except HTTPException:
            raise
        except Exception as e:
            raise HTTPException(status_code=500, detail=f"Failed to fetch file: {str(e)}")

        if isinstance(contents, list):
            raise ValueError(f"Path {path} is a directory, not a file")

        if contents.get("encoding") == "base64":
            content = base64.b64decode(contents["content"]).decode("utf-8", errors="replace")
            return content
        return contents.get("content", "") or ""

    async def get_workflows(self, owner: str, repo: str) -> list:
        """Get all workflow files from .github/workflows."""
        try:
            workflows = await self.get_repo_contents(owner, repo, ".github/workflows")
            if isinstance(workflows, dict):
                return []
            return [w for w in workflows if w["name"].endswith((".yml", ".yaml"))]
        except HTTPException:
            raise
        except httpx.HTTPStatusError as e:
            if e.response.status_code == 404:
                return []
            if e.response.status_code == 403:
                rate_limit_remaining = e.response.headers.get("X-RateLimit-Remaining", "0")
                if rate_limit_remaining == "0":
                    raise HTTPException(status_code=403, detail=RATE_LIMIT_DETAIL)
            raise HTTPException(status_code=e.response.status_code, detail=f"GitHub API error: {str(e)}")

    async def get_action_metadata(self, owner: str, repo: str, ref: Optional[str] = "main", subdir: Optional[str] = None) -> Optional[Dict[str, Any]]:
        """Get action.yml or action.yaml at ``ref``, optionally from a subdirectory.

        The metadata must come from the ref the workflow actually pins; reading
        the default branch would audit (and follow the dependencies of) a
        different version of the action than the one that runs.
        """
        base_path = subdir.rstrip("/") if subdir else ""

        for filename in ["action.yml", "action.yaml"]:
            file_path = f"{base_path}/{filename}" if base_path else filename
            try:
                content = await self.get_file_content(owner, repo, file_path, ref=ref)
                return {"content": content, "path": file_path}
            except HTTPException as e:
                if e.status_code == 403:
                    raise
                continue
            except httpx.HTTPStatusError as e:
                if e.response.status_code == 403:
                    raise HTTPException(status_code=403, detail=f"GitHub API error: {str(e)}")
                continue
            except ValueError:
                continue
        return None

    async def get_latest_tag(self, owner: str, repo: str) -> Optional[str]:
        """Get the latest tag/release version from a repository."""
        try:
            response = await self._get(f"{self.base_url}/repos/{owner}/{repo}/releases/latest")
            if response.status_code == 200:
                tag_name = response.json().get("tag_name", "")
                if tag_name:
                    return tag_name
        except Exception:
            pass

        try:
            response = await self._get(f"{self.base_url}/repos/{owner}/{repo}/tags?per_page=100")
            if response.status_code == 200:
                tags = response.json()
                if tags:
                    version_tags = []
                    for tag in tags:
                        tag_name = tag.get("name", "")
                        if re.match(r'^v?\d+\.?\d*', tag_name):
                            version_tags.append((_parse_version(tag_name), tag_name))
                    if version_tags:
                        version_tags.sort(key=lambda x: x[0], reverse=True)
                        return version_tags[0][1]
                    return tags[0].get("name", "")
        except Exception:
            pass

        return None

    async def get_commit_date(self, owner: str, repo: str, sha: str) -> Optional[str]:
        """Get the commit date for a specific SHA."""
        try:
            response = await self._get(f"{self.base_url}/repos/{owner}/{repo}/commits/{sha}")
            if response.status_code == 200:
                commit_info = response.json().get("commit", {})
                return commit_info.get("author", {}).get("date")  # ISO 8601 format
        except Exception:
            pass
        return None

    async def get_latest_tag_commit_date(self, owner: str, repo: str) -> Optional[str]:
        """Get the commit date of the latest tag."""
        latest_tag = await self.get_latest_tag(owner, repo)
        if not latest_tag:
            return None

        try:
            response = await self._get(f"{self.base_url}/repos/{owner}/{repo}/git/refs/tags/{latest_tag}")
            if response.status_code == 200:
                ref_data = response.json()
                if isinstance(ref_data, list):
                    ref_data = next((r for r in ref_data if r.get("ref") == f"refs/tags/{latest_tag}"), ref_data[0] if ref_data else {})
                obj = ref_data.get("object", {})
                object_sha = obj.get("sha")
                if object_sha:
                    commit_sha = object_sha
                    if obj.get("type", "tag") == "tag":
                        tag_response = await self._get(f"{self.base_url}/repos/{owner}/{repo}/git/tags/{object_sha}")
                        if tag_response.status_code == 200:
                            commit_sha = tag_response.json().get("object", {}).get("sha") or object_sha
                    return await self.get_commit_date(owner, repo, commit_sha)
        except Exception:
            try:
                response = await self._get(f"{self.base_url}/repos/{owner}/{repo}/releases/latest")
                if response.status_code == 200:
                    commit_sha = response.json().get("target_commitish")
                    if commit_sha:
                        return await self.get_commit_date(owner, repo, commit_sha)
            except Exception:
                pass
        return None

    async def resolve_tag_to_sha(self, owner: str, repo: str, tag: str) -> Optional[str]:
        """Resolve a version tag (e.g. 'v4') to its full 40-char commit SHA.

        Tries the exact ref first, then falls back to matching from the refs list
        since /git/refs/tags/{prefix} returns an array of prefix matches.
        Raises HTTPException on rate limits so callers can surface it to the user.
        """
        try:
            response = await self._get(f"{self.base_url}/repos/{owner}/{repo}/git/refs/tags/{tag}")

            if response.status_code in (403, 429) and self._is_rate_limited(response):
                raise HTTPException(
                    status_code=403,
                    detail="GitHub API rate limit exceeded. Provide a GitHub token to resolve SHA hashes."
                )
            if response.status_code != 200:
                return None

            data = response.json()

            ref_obj = None
            if isinstance(data, list):
                exact = f"refs/tags/{tag}"
                for item in data:
                    if item.get("ref") == exact:
                        ref_obj = item
                        break
                # The API returns a list only when there is no exact match; any
                # element is a *different* tag (v1 -> v10, v1.2.3), so pinning
                # to it would silently pin the wrong version.
            elif isinstance(data, dict):
                ref_obj = data

            if not ref_obj:
                return None

            obj = ref_obj.get("object", {})
            object_sha = obj.get("sha")
            if not object_sha:
                return None

            if obj.get("type") == "tag":
                tag_resp = await self._get(f"{self.base_url}/repos/{owner}/{repo}/git/tags/{object_sha}")
                if tag_resp.status_code == 200:
                    return tag_resp.json().get("object", {}).get("sha", object_sha)
            return object_sha
        except HTTPException:
            raise
        except Exception:
            return None

    async def get_repository_info(self, owner: str, repo: str) -> Optional[Dict[str, Any]]:
        """Get repository information including archived status.

        Returns:
            Dict with repo info if exists and accessible, None if 404 (doesn't exist or private),
            raises HTTPException for other errors (rate limits, network issues, etc.)
        """
        url = f"{self.base_url}/repos/{owner}/{repo}"
        try:
            response = await self._get(url)
            if response.status_code == 200:
                return response.json()
            elif response.status_code == 404:
                return None  # Repository doesn't exist or is private/inaccessible
            elif response.status_code in (403, 429):
                if self._is_rate_limited(response):
                    raise HTTPException(status_code=403, detail=RATE_LIMIT_DETAIL)
                raise HTTPException(
                    status_code=403,
                    detail="Repository is inaccessible (private or insufficient permissions). Provide a token with appropriate scope."
                )
            else:
                response.raise_for_status()
        except HTTPException:
            raise
        except httpx.HTTPStatusError as e:
            if e.response.status_code == 404:
                return None
            raise HTTPException(status_code=e.response.status_code, detail=f"GitHub API error: {str(e)}")
        except httpx.TimeoutException:
            # Timeout - don't assume repo doesn't exist
            raise HTTPException(status_code=504, detail="GitHub API request timed out")
        except Exception as e:
            # Other errors - don't assume repo doesn't exist
            raise HTTPException(status_code=500, detail=f"Error checking repository: {str(e)}")
        return None

    async def _list_paged(self, url: str, max_pages: int) -> Optional[list]:
        """All items of a paginated list endpoint, or None if it 404s."""
        items: list = []
        sep = "&" if "?" in url else "?"
        for page in range(1, max_pages + 1):
            response = await self._get(f"{url}{sep}per_page=100&page={page}")
            if response.status_code == 404:
                return None
            if self._is_rate_limited(response):
                raise HTTPException(status_code=403, detail=RATE_LIMIT_DETAIL)
            if response.status_code in (401, 403):
                raise HTTPException(
                    status_code=403,
                    detail="GitHub refused to list repositories. Check that the token is valid and authorized for this organization (SSO).",
                )
            response.raise_for_status()
            batch = response.json()
            items.extend(batch)
            if len(batch) < 100:
                break
        return items

    async def list_owner_repositories(self, owner: str, max_pages: int = 10) -> Optional[Dict[str, Any]]:
        """Repositories of an organization or user, most recently pushed first.

        Returns ``{"owner_type", "private_included", "repositories"}``, or None
        when no organization or user has that name. Tries the organization
        endpoint first and falls back to the user one. A user's listing holds
        only the repositories they own; their private ones are included only
        when the token belongs to that user (``/user/repos``). An
        organization's private repositories show whenever the token can see them.
        """
        name = quote(owner, safe="")
        owner_type = "organization"
        private_included = bool(self.token)
        repos = await self._list_paged(f"{self.base_url}/orgs/{name}/repos?type=all", max_pages)
        if repos is None:
            owner_type = "user"
            private_included = False
            if self.token:
                me = await self._get(f"{self.base_url}/user")
                if me.status_code == 200 and str(me.json().get("login", "")).lower() == owner.lower():
                    repos = await self._list_paged(
                        f"{self.base_url}/user/repos?affiliation=owner&visibility=all", max_pages
                    )
                    private_included = repos is not None
        if repos is None:
            repos = await self._list_paged(f"{self.base_url}/users/{name}/repos?type=owner", max_pages)
        if repos is None:
            return None
        result = [
            {
                "name": r.get("name"),
                "full_name": r.get("full_name"),
                "description": r.get("description"),
                "private": bool(r.get("private")),
                "archived": bool(r.get("archived")),
                "fork": bool(r.get("fork")),
                "default_branch": r.get("default_branch"),
                "pushed_at": r.get("pushed_at"),
                "language": r.get("language"),
            }
            for r in repos
            if isinstance(r, dict) and r.get("full_name")
        ]
        result.sort(key=lambda r: r.get("pushed_at") or "", reverse=True)
        return {"owner_type": owner_type, "private_included": private_included, "repositories": result}

    def parse_action_reference(self, action_ref: str) -> tuple:
        """Parse action reference like 'owner/repo@v1', 'owner/repo/path@v1', or 'owner/repo@ref'."""
        if "@" in action_ref:
            repo_part, ref = action_ref.rsplit("@", 1)
        else:
            repo_part = action_ref
            ref = "main"

        if "/" in repo_part:
            parts = repo_part.split("/", 1)
            if len(parts) == 2:
                owner = parts[0]
                repo_path = parts[1]
                # Split repo and optional subdirectory path
                repo_path_parts = repo_path.split("/", 1)
                repo = repo_path_parts[0]
                subdir = repo_path_parts[1] if len(repo_path_parts) > 1 else None
                return owner, repo, ref, subdir
        return None, None, ref, None
