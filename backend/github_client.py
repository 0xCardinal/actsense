"""GitHub API client for fetching repositories and actions."""
import httpx
from typing import Optional, Dict, Any
import base64
from fastapi import HTTPException


class GitHubClient:
    def __init__(self, token: Optional[str] = None):
        self.token = token
        self.base_url = "https://api.github.com"
        self.headers = {
            "Accept": "application/vnd.github.v3+json",
        }
        if token:
            self.headers["Authorization"] = f"token {token}"

    async def get_repo_contents(self, owner: str, repo: str, path: str = "") -> Dict[str, Any]:
        """Get repository contents at a specific path."""
        url = f"{self.base_url}/repos/{owner}/{repo}/contents/{path}"
        async with httpx.AsyncClient() as client:
            response = await client.get(url, headers=self.headers)
            if response.status_code == 403:
                # Check if it's a rate limit error
                rate_limit_remaining = response.headers.get("X-RateLimit-Remaining", "0")
                if rate_limit_remaining == "0":
                    raise HTTPException(
                        status_code=403,
                        detail="GitHub API rate limit exceeded. Please provide a GitHub token to increase your rate limit from 60/hour to 5000/hour."
                    )
            response.raise_for_status()
            return response.json()

    async def get_file_content(self, owner: str, repo: str, path: str) -> str:
        """Get file content from repository."""
        try:
            contents = await self.get_repo_contents(owner, repo, path)
        except HTTPException:
            raise
        except Exception as e:
            raise HTTPException(status_code=500, detail=f"Failed to fetch file: {str(e)}")
        
        if isinstance(contents, list):
            raise ValueError(f"Path {path} is a directory, not a file")
        
        if contents.get("encoding") == "base64":
            content = base64.b64decode(contents["content"]).decode("utf-8")
            return content
        return contents.get("content", "")

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
                    raise HTTPException(
                        status_code=403,
                        detail="GitHub API rate limit exceeded. Please provide a GitHub token to increase your rate limit from 60/hour to 5000/hour."
                    )
            raise HTTPException(status_code=e.response.status_code, detail=f"GitHub API error: {str(e)}")

    async def get_action_metadata(self, owner: str, repo: str, ref: str = "main", subdir: Optional[str] = None) -> Optional[Dict[str, Any]]:
        """Get action.yml or action.yaml from a repository, optionally from a subdirectory."""
        # Construct the path to action.yml
        if subdir:
            # For subdirectory actions, look in the subdirectory
            base_path = subdir.rstrip("/")
        else:
            # For root actions, look in the root
            base_path = ""
        
        for filename in ["action.yml", "action.yaml"]:
            try:
                if base_path:
                    file_path = f"{base_path}/{filename}"
                else:
                    file_path = filename
                content = await self.get_file_content(owner, repo, file_path)
                return {"content": content, "path": file_path}
            except (httpx.HTTPStatusError, ValueError, HTTPException):
                # 404 or other errors - try next filename
                continue
        return None

    async def get_latest_tag(self, owner: str, repo: str) -> Optional[str]:
        """Get the latest tag/release version from a repository."""
        try:
            # Try releases API first (more reliable for versioned releases)
            url = f"{self.base_url}/repos/{owner}/{repo}/releases/latest"
            async with httpx.AsyncClient() as client:
                response = await client.get(url, headers=self.headers)
                if response.status_code == 200:
                    release = response.json()
                    tag_name = release.get("tag_name", "")
                    if tag_name:
                        return tag_name
        except (httpx.HTTPStatusError, Exception):
            # If releases API fails, try tags API
            pass
        
        try:
            # Fallback to tags API - get all tags and find the latest version
            url = f"{self.base_url}/repos/{owner}/{repo}/tags"
            async with httpx.AsyncClient() as client:
                response = await client.get(url, headers=self.headers)
                if response.status_code == 200:
                    tags = response.json()
                    if tags and len(tags) > 0:
                        # Find the highest version number
                        import re
                        
                        def parse_version(version_str: str) -> tuple:
                            """Parse version string into tuple for comparison (major, minor, patch)."""
                            # Remove 'v' prefix if present
                            if version_str.startswith("v"):
                                version_str = version_str[1:]
                            
                            # Match semantic version: major.minor.patch
                            match = re.match(r'^(\d+)\.?(\d*)?\.?(\d*)?', version_str)
                            if match:
                                major = int(match.group(1))
                                minor = int(match.group(2)) if match.group(2) else 0
                                patch = int(match.group(3)) if match.group(3) else 0
                                return (major, minor, patch)
                            return (0, 0, 0)
                        
                        version_tags = []
                        for tag in tags:
                            tag_name = tag.get("name", "")
                            # Check if it looks like a version number
                            if re.match(r'^v?\d+\.?\d*', tag_name):
                                ver_tuple = parse_version(tag_name)
                                version_tags.append((ver_tuple, tag_name))
                        
                        if version_tags:
                            # Sort by version tuple (highest first)
                            version_tags.sort(key=lambda x: x[0], reverse=True)
                            return version_tags[0][1]
                        
                        # If no version tags found, return the first tag
                        return tags[0].get("name", "")
        except (httpx.HTTPStatusError, Exception):
            pass
        
        return None

    async def get_commit_date(self, owner: str, repo: str, sha: str) -> Optional[str]:
        """Get the commit date for a specific SHA."""
        try:
            url = f"{self.base_url}/repos/{owner}/{repo}/commits/{sha}"
            async with httpx.AsyncClient() as client:
                response = await client.get(url, headers=self.headers)
                if response.status_code == 200:
                    commit = response.json()
                    commit_info = commit.get("commit", {})
                    author_info = commit_info.get("author", {})
                    return author_info.get("date")  # ISO 8601 format
        except (httpx.HTTPStatusError, Exception):
            pass
        return None

    async def get_latest_tag_commit_date(self, owner: str, repo: str) -> Optional[str]:
        """Get the commit date of the latest tag."""
        latest_tag = await self.get_latest_tag(owner, repo)
        if not latest_tag:
            return None
        
        # Get the commit SHA for the latest tag
        try:
            url = f"{self.base_url}/repos/{owner}/{repo}/git/refs/tags/{latest_tag}"
            async with httpx.AsyncClient() as client:
                response = await client.get(url, headers=self.headers)
                if response.status_code == 200:
                    ref_data = response.json()
                    # The ref might point to a tag object or directly to a commit
                    object_sha = ref_data.get("object", {}).get("sha")
                    if object_sha:
                        # Check if it's a tag object (needs another API call) or direct commit
                        tag_url = f"{self.base_url}/repos/{owner}/{repo}/git/tags/{object_sha}"
                        tag_response = await client.get(tag_url, headers=self.headers)
                        if tag_response.status_code == 200:
                            tag_data = tag_response.json()
                            commit_sha = tag_data.get("object", {}).get("sha")
                        else:
                            # Direct commit reference
                            commit_sha = object_sha
                        
                        if commit_sha:
                            return await self.get_commit_date(owner, repo, commit_sha)
        except (httpx.HTTPStatusError, Exception):
            # Fallback: try to get commit from releases API
            try:
                url = f"{self.base_url}/repos/{owner}/{repo}/releases/latest"
                async with httpx.AsyncClient() as client:
                    response = await client.get(url, headers=self.headers)
                    if response.status_code == 200:
                        release = response.json()
                        commit_sha = release.get("target_commitish")
                        if commit_sha:
                            return await self.get_commit_date(owner, repo, commit_sha)
            except (httpx.HTTPStatusError, Exception):
                pass
        return None

    async def get_repository_info(self, owner: str, repo: str) -> Optional[Dict[str, Any]]:
        """Get repository information including archived status."""
        try:
            url = f"{self.base_url}/repos/{owner}/{repo}"
            async with httpx.AsyncClient() as client:
                response = await client.get(url, headers=self.headers)
                if response.status_code == 200:
                    return response.json()
                elif response.status_code == 404:
                    return None  # Repository doesn't exist or is private
        except (httpx.HTTPStatusError, Exception):
            pass
        return None

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

