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

    async def get_action_metadata(self, owner: str, repo: str, ref: str = "main") -> Optional[Dict[str, Any]]:
        """Get action.yml or action.yaml from a repository."""
        for filename in ["action.yml", "action.yaml"]:
            try:
                content = await self.get_file_content(owner, repo, filename)
                return {"content": content, "path": filename}
            except httpx.HTTPStatusError:
                continue
        return None

    def parse_action_reference(self, action_ref: str) -> tuple:
        """Parse action reference like 'owner/repo@v1' or 'owner/repo@ref'."""
        if "@" in action_ref:
            repo_part, ref = action_ref.rsplit("@", 1)
        else:
            repo_part = action_ref
            ref = "main"
        
        if "/" in repo_part:
            parts = repo_part.split("/", 1)
            if len(parts) == 2:
                return parts[0], parts[1], ref
        return None, None, ref

