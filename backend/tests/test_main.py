"""Tests for main.py"""
import pytest
from fastapi.testclient import TestClient
from unittest.mock import patch, AsyncMock, MagicMock
from main import app, resolve_action_dependencies, audit_repository
from github_client import GitHubClient
from graph_builder import GraphBuilder


@pytest.fixture
def client():
    """Create test client."""
    return TestClient(app)


class TestHealthEndpoint:
    """Test health check endpoint."""
    
    def test_health(self, client):
        """Test health check endpoint."""
        response = client.get("/api/health")
        assert response.status_code == 200
        assert response.json() == {"status": "ok"}


class TestAuditEndpoint:
    """Test audit endpoint."""
    
    @pytest.mark.asyncio
    async def test_audit_repository(self, client):
        """Test auditing a repository."""
        mock_workflows = [
            {"name": "test.yml", "path": ".github/workflows/test.yml"}
        ]
        mock_workflow_content = """
name: Test Workflow
on: [push]
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
"""
        mock_workflow_parsed = {
            "name": "Test Workflow",
            "on": ["push"],
            "jobs": {
                "test": {
                    "runs-on": "ubuntu-latest",
                    "steps": [
                        {"uses": "actions/checkout@v4"}
                    ]
                }
            }
        }
        
        with patch("main.GitHubClient") as mock_client_class:
            mock_client = MagicMock()
            mock_client.get_workflows = AsyncMock(return_value=mock_workflows)
            mock_client.get_file_content = AsyncMock(return_value=mock_workflow_content)
            mock_client.get_repository_info = AsyncMock(return_value={"name": "repo"})
            mock_client.parse_action_reference = MagicMock(return_value=("actions", "checkout", "v4", None))
            mock_client.get_action_metadata = AsyncMock(return_value=None)
            mock_client_class.return_value = mock_client
            
            with patch("main.WorkflowParser") as mock_parser:
                mock_parser_instance = MagicMock()
                mock_parser_instance.parse_workflow.return_value = mock_workflow_parsed
                mock_parser_instance.extract_actions.return_value = ["actions/checkout@v4"]
                mock_parser.return_value = mock_parser_instance
                
                with patch("main.SecurityAuditor") as mock_auditor:
                    mock_auditor_instance = MagicMock()
                    mock_auditor_instance.audit_workflow = AsyncMock(return_value=[])
                    mock_auditor_instance.audit_action = MagicMock(return_value=[])
                    mock_auditor_instance.check_inconsistent_action_versions = MagicMock(return_value=[])
                    mock_auditor.return_value = mock_auditor_instance
                    
                    response = client.post(
                        "/api/audit",
                        json={"repository": "owner/repo"}
                    )
                    
                    assert response.status_code == 200
                    data = response.json()
                    assert "id" in data
                    assert "graph" in data
                    assert "statistics" in data
    
    @pytest.mark.asyncio
    async def test_audit_repository_with_url(self, client):
        """Test auditing a repository with full URL."""
        with patch("main.audit_repository", new_callable=AsyncMock) as mock_audit:
            mock_audit.return_value = None
            
            with patch("main.GraphBuilder") as mock_graph:
                mock_graph_instance = MagicMock()
                mock_graph_instance.get_graph_data.return_value = {"nodes": [], "edges": []}
                mock_graph_instance.get_statistics.return_value = {"total_nodes": 0}
                mock_graph.return_value = mock_graph_instance
                
                response = client.post(
                    "/api/audit",
                    json={"repository": "https://github.com/owner/repo"}
                )
                
                assert response.status_code == 200
    
    @pytest.mark.asyncio
    async def test_audit_repository_invalid_format(self, client):
        """Test auditing repository with invalid format."""
        response = client.post(
            "/api/audit",
            json={"repository": "invalid"}
        )
        
        assert response.status_code == 400
    
    @pytest.mark.asyncio
    async def test_audit_action(self, client):
        """Test auditing a single action."""
        with patch("main.resolve_action_dependencies", new_callable=AsyncMock) as mock_resolve:
            mock_resolve.return_value = None
            
            with patch("main.GitHubClient") as mock_client_class:
                mock_client = MagicMock()
                mock_client.parse_action_reference = MagicMock(return_value=("actions", "checkout", "v4", None))
                mock_client.get_repository_info = AsyncMock(return_value={"name": "checkout"})
                mock_client.get_action_metadata = AsyncMock(return_value=None)
                mock_client_class.return_value = mock_client
                
                with patch("main.GraphBuilder") as mock_graph:
                    mock_graph_instance = MagicMock()
                    mock_graph_instance.get_graph_data.return_value = {"nodes": [], "edges": []}
                    mock_graph_instance.get_statistics.return_value = {"total_nodes": 0}
                    mock_graph.return_value = mock_graph_instance
                    
                    response = client.post(
                        "/api/audit",
                        json={"action": "actions/checkout@v4"}
                    )
                    
                    assert response.status_code == 200
    
    @pytest.mark.asyncio
    async def test_audit_no_repository_or_action(self, client):
        """Test audit endpoint without repository or action."""
        response = client.post(
            "/api/audit",
            json={}
        )
        
        assert response.status_code == 400
    
    @pytest.mark.asyncio
    async def test_audit_with_token(self, client):
        """Test audit endpoint with GitHub token."""
        with patch("main.audit_repository", new_callable=AsyncMock) as mock_audit:
            mock_audit.return_value = None
            
            with patch("main.GraphBuilder") as mock_graph:
                mock_graph_instance = MagicMock()
                mock_graph_instance.get_graph_data.return_value = {"nodes": [], "edges": []}
                mock_graph_instance.get_statistics.return_value = {"total_nodes": 0}
                mock_graph.return_value = mock_graph_instance
                
                response = client.post(
                    "/api/audit",
                    json={
                        "repository": "owner/repo",
                        "github_token": "test-token"
                    }
                )
                
                assert response.status_code == 200
    
    @pytest.mark.asyncio
    async def test_audit_with_use_clone(self, client):
        """Test audit endpoint with use_clone option."""
        with patch("main.audit_repository", new_callable=AsyncMock) as mock_audit:
            mock_audit.return_value = None
            
            with patch("main.GraphBuilder") as mock_graph:
                mock_graph_instance = MagicMock()
                mock_graph_instance.get_graph_data.return_value = {"nodes": [], "edges": []}
                mock_graph_instance.get_statistics.return_value = {"total_nodes": 0}
                mock_graph.return_value = mock_graph_instance
                
                response = client.post(
                    "/api/audit",
                    json={
                        "repository": "owner/repo",
                        "use_clone": True
                    }
                )
                
                assert response.status_code == 200


class TestAnalysesEndpoints:
    """Test analysis endpoints."""
    
    def test_list_analyses(self, client):
        """Test listing analyses."""
        response = client.get("/api/analyses")
        assert response.status_code == 200
        assert isinstance(response.json(), list)
    
    def test_list_analyses_with_limit(self, client):
        """Test listing analyses with limit."""
        response = client.get("/api/analyses?limit=10")
        assert response.status_code == 200
    
    def test_list_analyses_with_repository(self, client):
        """Test listing analyses filtered by repository."""
        response = client.get("/api/analyses?repository=test/repo")
        assert response.status_code == 200
    
    def test_get_analysis_nonexistent(self, client):
        """Test getting non-existent analysis."""
        response = client.get("/api/analyses/nonexistent-id")
        assert response.status_code == 404
    
    def test_delete_analysis_nonexistent(self, client):
        """Test deleting non-existent analysis."""
        response = client.delete("/api/analyses/nonexistent-id")
        assert response.status_code == 404


class TestResolveActionDependencies:
    """Test resolve_action_dependencies function."""
    
    @pytest.mark.asyncio
    async def test_resolve_action_dependencies_max_depth(self):
        """Test resolve_action_dependencies respects max depth."""
        mock_client = MagicMock()
        mock_client.parse_action_reference = MagicMock(return_value=("owner", "repo", "v1", None))
        mock_client.get_repository_info = AsyncMock(return_value={"name": "repo"})
        mock_client.get_action_metadata = AsyncMock(return_value=None)
        
        graph = GraphBuilder()
        visited = set()
        
        await resolve_action_dependencies(mock_client, "owner/repo@v1", graph, visited, depth=6, max_depth=5)
        
        # Should not add node because depth exceeds max_depth
        assert len(graph.nodes) == 0
    
    @pytest.mark.asyncio
    async def test_resolve_action_dependencies_visited(self):
        """Test resolve_action_dependencies skips visited actions."""
        mock_client = MagicMock()
        mock_client.parse_action_reference = MagicMock(return_value=("owner", "repo", "v1", None))
        
        graph = GraphBuilder()
        visited = {"owner/repo@v1"}
        
        await resolve_action_dependencies(mock_client, "owner/repo@v1", graph, visited)
        
        # Should not add node because already visited
        assert len(graph.nodes) == 0
    
    @pytest.mark.asyncio
    async def test_resolve_action_dependencies_invalid_reference(self):
        """Test resolve_action_dependencies with invalid reference."""
        mock_client = MagicMock()
        mock_client.parse_action_reference = MagicMock(return_value=(None, None, "v1", None))
        
        graph = GraphBuilder()
        visited = set()
        
        await resolve_action_dependencies(mock_client, "invalid", graph, visited)
        
        # Should not add node because reference is invalid
        assert len(graph.nodes) == 0
    
    @pytest.mark.asyncio
    async def test_resolve_action_dependencies_workflow_file(self):
        """Test resolve_action_dependencies skips workflow files."""
        mock_client = MagicMock()
        mock_client.parse_action_reference = MagicMock(return_value=("owner", "repo", "v1", ".github/workflows/test.yml"))
        
        graph = GraphBuilder()
        visited = set()
        
        await resolve_action_dependencies(mock_client, "owner/repo/.github/workflows/test.yml@v1", graph, visited)
        
        # Should not add node because it's a workflow file
        assert len(graph.nodes) == 0
    
    @pytest.mark.asyncio
    async def test_resolve_action_dependencies_missing_repo(self):
        """Test resolve_action_dependencies with missing repository."""
        mock_client = MagicMock()
        mock_client.parse_action_reference = MagicMock(return_value=("owner", "repo", "v1", None))
        mock_client.get_repository_info = AsyncMock(return_value=None)
        
        graph = GraphBuilder()
        visited = set()
        
        await resolve_action_dependencies(mock_client, "owner/repo@v1", graph, visited)
        
        # Should add node with missing repo issue
        assert len(graph.nodes) > 0
        node = graph.nodes.get("owner/repo@v1")
        if node:
            assert len(node["issues"]) > 0


class TestAuditRepository:
    """Test audit_repository function."""
    
    @pytest.mark.asyncio
    async def test_audit_repository_api_method(self):
        """Test audit_repository using API method."""
        mock_client = MagicMock()
        mock_client.get_workflows = AsyncMock(return_value=[])
        mock_client.get_repository_info = AsyncMock(return_value={"name": "repo"})
        
        graph = GraphBuilder()
        
        await audit_repository(mock_client, "owner", "repo", graph, use_clone=False)
        
        # Should add repository node
        assert "owner/repo" in graph.nodes
    
    @pytest.mark.asyncio
    async def test_audit_repository_clone_method(self):
        """Test audit_repository using clone method."""
        mock_client = MagicMock()
        mock_client.get_repository_info = AsyncMock(return_value={"name": "repo"})
        
        with patch("main.cloner") as mock_cloner:
            mock_cloner.clone_repository = MagicMock(return_value=("/tmp/clone", "/tmp/clone"))
            mock_cloner.get_workflow_files = MagicMock(return_value=[])
            mock_cloner.cleanup = MagicMock()
            
            graph = GraphBuilder()
            
            await audit_repository(mock_client, "owner", "repo", graph, use_clone=True)
            
            # Should add repository node
            assert "owner/repo" in graph.nodes
            # Should cleanup
            mock_cloner.cleanup.assert_called_once()

