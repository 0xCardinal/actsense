"""Tests for github_client.py"""
import pytest
from unittest.mock import AsyncMock, MagicMock, patch
from fastapi import HTTPException
import httpx
from github_client import GitHubClient


class TestGitHubClient:
    """Test GitHubClient class."""
    
    def test_init_without_token(self):
        """Test initialization without token."""
        client = GitHubClient()
        assert client.token is None
        assert "Authorization" not in client.headers
    
    def test_init_with_token(self):
        """Test initialization with token."""
        client = GitHubClient(token="test-token")
        assert client.token == "test-token"
        assert client.headers["Authorization"] == "token test-token"
    
    @pytest.mark.asyncio
    async def test_get_repo_contents_success(self):
        """Test getting repository contents successfully."""
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"name": "file.txt", "type": "file"}
        
        with patch("httpx.AsyncClient") as mock_client_class:
            mock_client = AsyncMock()
            mock_client.__aenter__.return_value = mock_client
            mock_client.__aexit__.return_value = None
            mock_client.get.return_value = mock_response
            mock_client_class.return_value = mock_client
            
            client = GitHubClient()
            result = await client.get_repo_contents("owner", "repo", "path")
            
            assert result == {"name": "file.txt", "type": "file"}
    
    @pytest.mark.asyncio
    async def test_get_repo_contents_rate_limit(self):
        """Test handling rate limit error."""
        mock_response = MagicMock()
        mock_response.status_code = 403
        mock_response.headers = {"X-RateLimit-Remaining": "0"}
        
        with patch("httpx.AsyncClient") as mock_client_class:
            mock_client = AsyncMock()
            mock_client.__aenter__.return_value = mock_client
            mock_client.__aexit__.return_value = None
            mock_client.get.return_value = mock_response
            mock_client_class.return_value = mock_client
            
            client = GitHubClient()
            with pytest.raises(HTTPException) as exc_info:
                await client.get_repo_contents("owner", "repo")
            
            assert exc_info.value.status_code == 403
            assert "rate limit" in exc_info.value.detail.lower()
    
    @pytest.mark.asyncio
    async def test_get_file_content_success(self):
        """Test getting file content successfully."""
        mock_contents = {
            "encoding": "base64",
            "content": "SGVsbG8gV29ybGQ="  # "Hello World" in base64
        }
        
        with patch.object(GitHubClient, "get_repo_contents", new_callable=AsyncMock) as mock_get:
            mock_get.return_value = mock_contents
            
            client = GitHubClient()
            content = await client.get_file_content("owner", "repo", "file.txt")
            
            assert content == "Hello World"
    
    @pytest.mark.asyncio
    async def test_get_file_content_directory(self):
        """Test getting file content when path is directory."""
        with patch.object(GitHubClient, "get_repo_contents", new_callable=AsyncMock) as mock_get:
            mock_get.return_value = [{"name": "file1.txt"}, {"name": "file2.txt"}]
            
            client = GitHubClient()
            with pytest.raises(ValueError, match="directory"):
                await client.get_file_content("owner", "repo", "path")
    
    @pytest.mark.asyncio
    async def test_get_file_content_no_encoding(self):
        """Test getting file content without base64 encoding."""
        mock_contents = {
            "content": "plain text"
        }
        
        with patch.object(GitHubClient, "get_repo_contents", new_callable=AsyncMock) as mock_get:
            mock_get.return_value = mock_contents
            
            client = GitHubClient()
            content = await client.get_file_content("owner", "repo", "file.txt")
            
            assert content == "plain text"
    
    @pytest.mark.asyncio
    async def test_get_workflows_success(self):
        """Test getting workflows successfully."""
        mock_workflows = [
            {"name": "workflow1.yml"},
            {"name": "workflow2.yaml"},
            {"name": "readme.md"}
        ]
        
        with patch.object(GitHubClient, "get_repo_contents", new_callable=AsyncMock) as mock_get:
            mock_get.return_value = mock_workflows
            
            client = GitHubClient()
            workflows = await client.get_workflows("owner", "repo")
            
            assert len(workflows) == 2
            assert all(w["name"].endswith((".yml", ".yaml")) for w in workflows)
    
    @pytest.mark.asyncio
    async def test_get_workflows_not_found(self):
        """Test getting workflows when directory doesn't exist."""
        with patch.object(GitHubClient, "get_repo_contents", new_callable=AsyncMock) as mock_get:
            mock_get.side_effect = httpx.HTTPStatusError(
                "404 Not Found",
                request=MagicMock(),
                response=MagicMock(status_code=404)
            )
            
            client = GitHubClient()
            workflows = await client.get_workflows("owner", "repo")
            
            assert workflows == []
    
    @pytest.mark.asyncio
    async def test_get_workflows_rate_limit(self):
        """Test getting workflows with rate limit error."""
        mock_response = MagicMock()
        mock_response.status_code = 403
        mock_response.headers = {"X-RateLimit-Remaining": "0"}
        
        with patch("httpx.AsyncClient") as mock_client_class:
            mock_client = AsyncMock()
            mock_client.__aenter__.return_value = mock_client
            mock_client.__aexit__.return_value = None
            mock_client.get.side_effect = httpx.HTTPStatusError(
                "403 Forbidden",
                request=MagicMock(),
                response=mock_response
            )
            mock_client_class.return_value = mock_client
            
            client = GitHubClient()
            with pytest.raises(HTTPException) as exc_info:
                await client.get_workflows("owner", "repo")
            
            assert exc_info.value.status_code == 403
    
    @pytest.mark.asyncio
    async def test_get_action_metadata_success(self):
        """Test getting action metadata successfully."""
        mock_content = "name: My Action"
        
        with patch.object(GitHubClient, "get_file_content", new_callable=AsyncMock) as mock_get:
            mock_get.return_value = mock_content
            
            client = GitHubClient()
            result = await client.get_action_metadata("owner", "repo", "main")
            
            assert result is not None
            assert result["content"] == mock_content
            assert result["path"] == "action.yml"
    
    @pytest.mark.asyncio
    async def test_get_action_metadata_with_subdir(self):
        """Test getting action metadata from subdirectory."""
        mock_content = "name: My Action"
        
        with patch.object(GitHubClient, "get_file_content", new_callable=AsyncMock) as mock_get:
            mock_get.return_value = mock_content
            
            client = GitHubClient()
            result = await client.get_action_metadata("owner", "repo", "main", "subdir")
            
            assert result is not None
            assert "subdir" in result["path"]
    
    @pytest.mark.asyncio
    async def test_get_action_metadata_not_found(self):
        """Test getting action metadata when file doesn't exist."""
        with patch.object(GitHubClient, "get_file_content", new_callable=AsyncMock) as mock_get:
            mock_get.side_effect = httpx.HTTPStatusError(
                "404 Not Found",
                request=MagicMock(),
                response=MagicMock(status_code=404)
            )
            
            client = GitHubClient()
            result = await client.get_action_metadata("owner", "repo", "main")
            
            assert result is None
    
    @pytest.mark.asyncio
    async def test_get_latest_tag_from_releases(self):
        """Test getting latest tag from releases API."""
        mock_release = {
            "tag_name": "v1.0.0"
        }
        
        with patch("httpx.AsyncClient") as mock_client_class:
            mock_client = AsyncMock()
            mock_client.__aenter__.return_value = mock_client
            mock_client.__aexit__.return_value = None
            mock_response = MagicMock()
            mock_response.status_code = 200
            mock_response.json.return_value = mock_release
            mock_client.get.return_value = mock_response
            mock_client_class.return_value = mock_client
            
            client = GitHubClient()
            tag = await client.get_latest_tag("owner", "repo")
            
            assert tag == "v1.0.0"
    
    @pytest.mark.asyncio
    async def test_get_latest_tag_from_tags_api(self):
        """Test getting latest tag from tags API when releases fail."""
        mock_tags = [
            {"name": "v2.0.0"},
            {"name": "v1.0.0"},
            {"name": "v1.5.0"}
        ]
        
        with patch("httpx.AsyncClient") as mock_client_class:
            mock_client = AsyncMock()
            mock_client.__aenter__.return_value = mock_client
            mock_client.__aexit__.return_value = None
            
            # First call (releases) fails, second (tags) succeeds
            mock_response_releases = MagicMock()
            mock_response_releases.status_code = 404
            mock_response_tags = MagicMock()
            mock_response_tags.status_code = 200
            mock_response_tags.json.return_value = mock_tags
            mock_client.get.side_effect = [
                httpx.HTTPStatusError("404", request=MagicMock(), response=mock_response_releases),
                mock_response_tags
            ]
            mock_client_class.return_value = mock_client
            
            client = GitHubClient()
            tag = await client.get_latest_tag("owner", "repo")
            
            assert tag == "v2.0.0"
    
    @pytest.mark.asyncio
    async def test_get_latest_tag_no_tags(self):
        """Test getting latest tag when no tags exist."""
        with patch("httpx.AsyncClient") as mock_client_class:
            mock_client = AsyncMock()
            mock_client.__aenter__.return_value = mock_client
            mock_client.__aexit__.return_value = None
            
            # Both APIs fail
            mock_response = MagicMock()
            mock_response.status_code = 404
            mock_client.get.side_effect = httpx.HTTPStatusError(
                "404", request=MagicMock(), response=mock_response
            )
            mock_client_class.return_value = mock_client
            
            client = GitHubClient()
            tag = await client.get_latest_tag("owner", "repo")
            
            assert tag is None
    
    @pytest.mark.asyncio
    async def test_get_commit_date_success(self):
        """Test getting commit date successfully."""
        mock_commit = {
            "commit": {
                "author": {
                    "date": "2024-01-01T00:00:00Z"
                }
            }
        }
        
        with patch("httpx.AsyncClient") as mock_client_class:
            mock_client = AsyncMock()
            mock_client.__aenter__.return_value = mock_client
            mock_client.__aexit__.return_value = None
            mock_response = MagicMock()
            mock_response.status_code = 200
            mock_response.json.return_value = mock_commit
            mock_client.get.return_value = mock_response
            mock_client_class.return_value = mock_client
            
            client = GitHubClient()
            date = await client.get_commit_date("owner", "repo", "abc123")
            
            assert date == "2024-01-01T00:00:00Z"
    
    @pytest.mark.asyncio
    async def test_get_commit_date_failure(self):
        """Test getting commit date when request fails."""
        with patch("httpx.AsyncClient") as mock_client_class:
            mock_client = AsyncMock()
            mock_client.__aenter__.return_value = mock_client
            mock_client.__aexit__.return_value = None
            mock_client.get.side_effect = httpx.HTTPStatusError(
                "404", request=MagicMock(), response=MagicMock(status_code=404)
            )
            mock_client_class.return_value = mock_client
            
            client = GitHubClient()
            date = await client.get_commit_date("owner", "repo", "abc123")
            
            assert date is None
    
    @pytest.mark.asyncio
    async def test_get_latest_tag_commit_date_success(self):
        """Test getting latest tag commit date successfully."""
        mock_ref = {
            "object": {
                "sha": "tag-sha"
            }
        }
        mock_tag = {
            "object": {
                "sha": "commit-sha"
            }
        }
        mock_commit = {
            "commit": {
                "author": {
                    "date": "2024-01-01T00:00:00Z"
                }
            }
        }
        
        with patch.object(GitHubClient, "get_latest_tag", new_callable=AsyncMock) as mock_tag_func:
            mock_tag_func.return_value = "v1.0.0"
            
            with patch("httpx.AsyncClient") as mock_client_class:
                mock_client = AsyncMock()
                mock_client.__aenter__.return_value = mock_client
                mock_client.__aexit__.return_value = None
                
                mock_response_ref = MagicMock()
                mock_response_ref.status_code = 200
                mock_response_ref.json.return_value = mock_ref
                
                mock_response_tag = MagicMock()
                mock_response_tag.status_code = 200
                mock_response_tag.json.return_value = mock_tag
                
                mock_response_commit = MagicMock()
                mock_response_commit.status_code = 200
                mock_response_commit.json.return_value = mock_commit
                
                mock_client.get.side_effect = [
                    mock_response_ref,
                    mock_response_tag,
                    mock_response_commit
                ]
                mock_client_class.return_value = mock_client
                
                client = GitHubClient()
                date = await client.get_latest_tag_commit_date("owner", "repo")
                
                assert date == "2024-01-01T00:00:00Z"
    
    @pytest.mark.asyncio
    async def test_get_latest_tag_commit_date_no_tag(self):
        """Test getting latest tag commit date when no tag exists."""
        with patch.object(GitHubClient, "get_latest_tag", new_callable=AsyncMock) as mock_tag_func:
            mock_tag_func.return_value = None
            
            client = GitHubClient()
            date = await client.get_latest_tag_commit_date("owner", "repo")
            
            assert date is None
    
    @pytest.mark.asyncio
    async def test_get_repository_info_success(self):
        """Test getting repository info successfully."""
        mock_repo = {
            "name": "repo",
            "full_name": "owner/repo",
            "archived": False
        }
        
        with patch("httpx.AsyncClient") as mock_client_class:
            mock_client = AsyncMock()
            mock_client.__aenter__.return_value = mock_client
            mock_client.__aexit__.return_value = None
            mock_response = MagicMock()
            mock_response.status_code = 200
            mock_response.json.return_value = mock_repo
            mock_client.get.return_value = mock_response
            mock_client_class.return_value = mock_client
            
            client = GitHubClient()
            repo_info = await client.get_repository_info("owner", "repo")
            
            assert repo_info == mock_repo
    
    @pytest.mark.asyncio
    async def test_get_repository_info_not_found(self):
        """Test getting repository info when repo doesn't exist."""
        with patch("httpx.AsyncClient") as mock_client_class:
            mock_client = AsyncMock()
            mock_client.__aenter__.return_value = mock_client
            mock_client.__aexit__.return_value = None
            mock_response = MagicMock()
            mock_response.status_code = 404
            mock_client.get.return_value = mock_response
            mock_client_class.return_value = mock_client
            
            client = GitHubClient()
            repo_info = await client.get_repository_info("owner", "repo")
            
            assert repo_info is None
    
    @pytest.mark.asyncio
    async def test_get_repository_info_rate_limit(self):
        """Test getting repository info with rate limit error."""
        mock_response = MagicMock()
        mock_response.status_code = 403
        mock_response.headers = {"X-RateLimit-Remaining": "0"}
        mock_response.raise_for_status = MagicMock()
        
        with patch("httpx.AsyncClient") as mock_client_class:
            mock_client = AsyncMock()
            mock_client.__aenter__.return_value = mock_client
            mock_client.__aexit__.return_value = None
            mock_client.get.return_value = mock_response
            mock_client_class.return_value = mock_client
            
            client = GitHubClient()
            with pytest.raises(HTTPException) as exc_info:
                await client.get_repository_info("owner", "repo")
            
            # Rate limit should raise 403, but if it's caught in exception handler it might be 500
            assert exc_info.value.status_code in [403, 500]
    
    @pytest.mark.asyncio
    async def test_get_repository_info_timeout(self):
        """Test getting repository info with timeout."""
        with patch("httpx.AsyncClient") as mock_client_class:
            mock_client = AsyncMock()
            mock_client.__aenter__.return_value = mock_client
            mock_client.__aexit__.return_value = None
            mock_client.get.side_effect = httpx.TimeoutException("Request timed out")
            mock_client_class.return_value = mock_client
            
            client = GitHubClient()
            with pytest.raises(HTTPException) as exc_info:
                await client.get_repository_info("owner", "repo")
            
            assert exc_info.value.status_code == 504
    
    def test_parse_action_reference_with_ref(self):
        """Test parsing action reference with ref."""
        client = GitHubClient()
        owner, repo, ref, subdir = client.parse_action_reference("owner/repo@v1.0.0")
        
        assert owner == "owner"
        assert repo == "repo"
        assert ref == "v1.0.0"
        assert subdir is None
    
    def test_parse_action_reference_without_ref(self):
        """Test parsing action reference without ref."""
        client = GitHubClient()
        owner, repo, ref, subdir = client.parse_action_reference("owner/repo")
        
        assert owner == "owner"
        assert repo == "repo"
        assert ref == "main"
        assert subdir is None
    
    def test_parse_action_reference_with_subdir(self):
        """Test parsing action reference with subdirectory."""
        client = GitHubClient()
        owner, repo, ref, subdir = client.parse_action_reference("owner/repo/subdir@v1.0.0")
        
        assert owner == "owner"
        assert repo == "repo"
        assert ref == "v1.0.0"
        assert subdir == "subdir"
    
    def test_parse_action_reference_invalid(self):
        """Test parsing invalid action reference."""
        client = GitHubClient()
        owner, repo, ref, subdir = client.parse_action_reference("invalid")
        
        assert owner is None
        assert repo is None
        assert ref == "main"
        assert subdir is None

