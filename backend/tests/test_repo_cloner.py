"""Tests for repo_cloner.py"""
import pytest
import tempfile
import shutil
from pathlib import Path
from unittest.mock import patch, MagicMock
from repo_cloner import RepoCloner


class TestRepoCloner:
    """Test RepoCloner class."""
    
    def test_init_with_custom_dir(self):
        """Test initialization with custom base directory."""
        with tempfile.TemporaryDirectory() as tmpdir:
            cloner = RepoCloner(base_dir=tmpdir)
            assert cloner.base_dir == Path(tmpdir)
            assert cloner.base_dir.exists()
    
    def test_init_with_default_dir(self):
        """Test initialization with default base directory."""
        cloner = RepoCloner()
        assert cloner.base_dir.exists()
        assert "actsense-clones" in str(cloner.base_dir)
    
    @patch('repo_cloner.subprocess.run')
    def test_clone_repository_basic(self, mock_run):
        """Test cloning a repository without token or branch."""
        mock_run.return_value = MagicMock(returncode=0, stderr="")
        
        with tempfile.TemporaryDirectory() as tmpdir:
            cloner = RepoCloner(base_dir=tmpdir)
            
            clone_path, cleanup_path = cloner.clone_repository("owner", "repo")
            
            assert clone_path is not None
            assert cleanup_path == clone_path
            assert "owner" in clone_path
            assert "repo" in clone_path
            
            # Verify git clone was called
            mock_run.assert_called_once()
            call_args = mock_run.call_args
            assert "git" in call_args[0][0]
            assert "clone" in call_args[0][0]
            assert "--depth" in call_args[0][0]
            assert "1" in call_args[0][0]
    
    @patch('repo_cloner.subprocess.run')
    def test_clone_repository_with_token(self, mock_run):
        """Test cloning a repository with token."""
        mock_run.return_value = MagicMock(returncode=0, stderr="")
        
        with tempfile.TemporaryDirectory() as tmpdir:
            cloner = RepoCloner(base_dir=tmpdir)
            
            clone_path, _ = cloner.clone_repository("owner", "repo", token="test-token")
            
            # Verify token was used in URL
            call_args = mock_run.call_args
            assert "test-token" in str(call_args[0][0])
    
    @patch('repo_cloner.subprocess.run')
    def test_clone_repository_with_branch(self, mock_run):
        """Test cloning a repository with specific branch."""
        mock_run.return_value = MagicMock(returncode=0, stderr="")
        
        with tempfile.TemporaryDirectory() as tmpdir:
            cloner = RepoCloner(base_dir=tmpdir)
            
            clone_path, _ = cloner.clone_repository("owner", "repo", branch="develop")
            
            # Verify branch was specified
            call_args = mock_run.call_args
            assert "-b" in call_args[0][0]
            assert "develop" in call_args[0][0]
    
    @patch('repo_cloner.subprocess.run')
    def test_clone_repository_failure(self, mock_run):
        """Test cloning failure handling."""
        mock_run.return_value = MagicMock(returncode=1, stderr="Git clone failed")
        
        with tempfile.TemporaryDirectory() as tmpdir:
            cloner = RepoCloner(base_dir=tmpdir)
            
            with pytest.raises(Exception, match="Git clone failed"):
                cloner.clone_repository("owner", "repo")
    
    @patch('repo_cloner.subprocess.run')
    def test_clone_repository_timeout(self, mock_run):
        """Test cloning timeout handling."""
        import subprocess
        mock_run.side_effect = subprocess.TimeoutExpired("git", 300)
        
        with tempfile.TemporaryDirectory() as tmpdir:
            cloner = RepoCloner(base_dir=tmpdir)
            
            with pytest.raises(Exception, match="timed out"):
                cloner.clone_repository("owner", "repo")
    
    @patch('repo_cloner.subprocess.run')
    def test_clone_repository_cleanup_on_error(self, mock_run):
        """Test cleanup on clone error."""
        import subprocess
        mock_run.side_effect = Exception("Unexpected error")
        
        with tempfile.TemporaryDirectory() as tmpdir:
            cloner = RepoCloner(base_dir=tmpdir)
            
            with pytest.raises(Exception):
                cloner.clone_repository("owner", "repo")
    
    def test_get_file_content(self):
        """Test reading file content from cloned repository."""
        with tempfile.TemporaryDirectory() as tmpdir:
            cloner = RepoCloner(base_dir=tmpdir)
            
            # Create a test file
            test_file = Path(tmpdir) / "test_file.txt"
            test_file.write_text("test content")
            
            content = cloner.get_file_content(str(tmpdir), "test_file.txt")
            assert content == "test content"
    
    def test_get_file_content_nonexistent(self):
        """Test reading non-existent file."""
        with tempfile.TemporaryDirectory() as tmpdir:
            cloner = RepoCloner(base_dir=tmpdir)
            
            with pytest.raises(FileNotFoundError):
                cloner.get_file_content(str(tmpdir), "nonexistent.txt")
    
    def test_get_workflow_files_empty(self):
        """Test getting workflow files when none exist."""
        with tempfile.TemporaryDirectory() as tmpdir:
            cloner = RepoCloner(base_dir=tmpdir)
            
            workflows = cloner.get_workflow_files(str(tmpdir))
            assert workflows == []
    
    def test_get_workflow_files_yml(self):
        """Test getting .yml workflow files."""
        with tempfile.TemporaryDirectory() as tmpdir:
            cloner = RepoCloner(base_dir=tmpdir)
            
            # Create workflows directory
            workflows_dir = Path(tmpdir) / ".github" / "workflows"
            workflows_dir.mkdir(parents=True)
            
            # Create a workflow file
            workflow_file = workflows_dir / "test.yml"
            workflow_file.write_text("name: test")
            
            workflows = cloner.get_workflow_files(str(tmpdir))
            assert len(workflows) == 1
            assert workflows[0]["name"] == "test.yml"
            assert workflows[0]["path"] == ".github/workflows/test.yml"
    
    def test_get_workflow_files_yaml(self):
        """Test getting .yaml workflow files."""
        with tempfile.TemporaryDirectory() as tmpdir:
            cloner = RepoCloner(base_dir=tmpdir)
            
            # Create workflows directory
            workflows_dir = Path(tmpdir) / ".github" / "workflows"
            workflows_dir.mkdir(parents=True)
            
            # Create a workflow file
            workflow_file = workflows_dir / "test.yaml"
            workflow_file.write_text("name: test")
            
            workflows = cloner.get_workflow_files(str(tmpdir))
            assert len(workflows) == 1
            assert workflows[0]["name"] == "test.yaml"
    
    def test_get_workflow_files_multiple(self):
        """Test getting multiple workflow files."""
        with tempfile.TemporaryDirectory() as tmpdir:
            cloner = RepoCloner(base_dir=tmpdir)
            
            # Create workflows directory
            workflows_dir = Path(tmpdir) / ".github" / "workflows"
            workflows_dir.mkdir(parents=True)
            
            # Create multiple workflow files
            (workflows_dir / "workflow1.yml").write_text("name: test1")
            (workflows_dir / "workflow2.yaml").write_text("name: test2")
            (workflows_dir / "workflow3.yml").write_text("name: test3")
            
            workflows = cloner.get_workflow_files(str(tmpdir))
            assert len(workflows) == 3
    
    def test_cleanup(self):
        """Test cleaning up cloned repository."""
        with tempfile.TemporaryDirectory() as tmpdir:
            cloner = RepoCloner(base_dir=tmpdir)
            
            # Create a directory to simulate cloned repo
            clone_path = Path(tmpdir) / "test_clone"
            clone_path.mkdir()
            (clone_path / "test_file.txt").write_text("test")
            
            assert clone_path.exists()
            cloner.cleanup(str(clone_path))
            assert not clone_path.exists()
    
    def test_cleanup_nonexistent(self):
        """Test cleaning up non-existent path."""
        with tempfile.TemporaryDirectory() as tmpdir:
            cloner = RepoCloner(base_dir=tmpdir)
            
            # Should not raise error
            cloner.cleanup(str(Path(tmpdir) / "nonexistent"))

