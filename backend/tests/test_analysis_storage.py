"""Tests for analysis_storage.py"""
import pytest
import json
import tempfile
import shutil
from pathlib import Path
from analysis_storage import AnalysisStorage


class TestAnalysisStorage:
    """Test AnalysisStorage class."""
    
    def test_init_with_custom_dir(self):
        """Test initialization with custom storage directory."""
        with tempfile.TemporaryDirectory() as tmpdir:
            storage = AnalysisStorage(storage_dir=tmpdir)
            assert storage.storage_dir == Path(tmpdir)
            assert storage.storage_dir.exists()
    
    def test_init_with_default_dir(self):
        """Test initialization with default storage directory."""
        storage = AnalysisStorage()
        expected = Path(__file__).parent.parent.parent / "data" / "analyses"
        assert storage.storage_dir == expected
        assert storage.storage_dir.exists()
    
    def test_save_analysis(self):
        """Test saving an analysis."""
        with tempfile.TemporaryDirectory() as tmpdir:
            storage = AnalysisStorage(storage_dir=tmpdir)
            graph_data = {"nodes": [], "edges": []}
            statistics = {"total_nodes": 0}
            
            analysis_id = storage.save_analysis(
                repository="test/repo",
                action=None,
                graph_data=graph_data,
                statistics=statistics,
                method="api"
            )
            
            assert analysis_id is not None
            assert len(analysis_id) == 36  # UUID length
            
            # Check file was created
            file_path = storage.storage_dir / f"{analysis_id}.json"
            assert file_path.exists()
            
            # Check file contents
            with open(file_path, 'r') as f:
                data = json.load(f)
            
            assert data["id"] == analysis_id
            assert data["repository"] == "test/repo"
            assert data["action"] is None
            assert data["method"] == "api"
            assert data["graph"] == graph_data
            assert data["statistics"] == statistics
            assert "timestamp" in data
    
    def test_save_analysis_with_action(self):
        """Test saving an analysis with action."""
        with tempfile.TemporaryDirectory() as tmpdir:
            storage = AnalysisStorage(storage_dir=tmpdir)
            graph_data = {"nodes": [{"id": "node1"}], "edges": []}
            statistics = {"total_nodes": 1}
            
            analysis_id = storage.save_analysis(
                repository=None,
                action="actions/checkout@v4",
                graph_data=graph_data,
                statistics=statistics,
                method="clone"
            )
            
            file_path = storage.storage_dir / f"{analysis_id}.json"
            with open(file_path, 'r') as f:
                data = json.load(f)
            
            assert data["repository"] is None
            assert data["action"] == "actions/checkout@v4"
            assert data["method"] == "clone"
    
    def test_get_analysis_existing(self):
        """Test retrieving an existing analysis."""
        with tempfile.TemporaryDirectory() as tmpdir:
            storage = AnalysisStorage(storage_dir=tmpdir)
            graph_data = {"nodes": [], "edges": []}
            statistics = {"total_nodes": 0}
            
            analysis_id = storage.save_analysis(
                repository="test/repo",
                action=None,
                graph_data=graph_data,
                statistics=statistics
            )
            
            retrieved = storage.get_analysis(analysis_id)
            assert retrieved is not None
            assert retrieved["id"] == analysis_id
            assert retrieved["repository"] == "test/repo"
            assert retrieved["graph"] == graph_data
    
    def test_get_analysis_nonexistent(self):
        """Test retrieving a non-existent analysis."""
        with tempfile.TemporaryDirectory() as tmpdir:
            storage = AnalysisStorage(storage_dir=tmpdir)
            result = storage.get_analysis("nonexistent-id")
            assert result is None
    
    def test_list_analyses_empty(self):
        """Test listing analyses when none exist."""
        with tempfile.TemporaryDirectory() as tmpdir:
            storage = AnalysisStorage(storage_dir=tmpdir)
            analyses = storage.list_analyses()
            assert analyses == []
    
    def test_list_analyses_multiple(self):
        """Test listing multiple analyses."""
        with tempfile.TemporaryDirectory() as tmpdir:
            storage = AnalysisStorage(storage_dir=tmpdir)
            
            # Save multiple analyses
            ids = []
            for i in range(3):
                analysis_id = storage.save_analysis(
                    repository=f"test/repo{i}",
                    action=None,
                    graph_data={"nodes": []},
                    statistics={"total_nodes": 0}
                )
                ids.append(analysis_id)
            
            analyses = storage.list_analyses()
            assert len(analyses) == 3
            
            # Check metadata is included
            for analysis in analyses:
                assert "id" in analysis
                assert "timestamp" in analysis
                assert "repository" in analysis
                assert "statistics" in analysis
                assert "graph" not in analysis  # Should not include full graph
    
    def test_list_analyses_with_limit(self):
        """Test listing analyses with limit."""
        with tempfile.TemporaryDirectory() as tmpdir:
            storage = AnalysisStorage(storage_dir=tmpdir)
            
            # Save 5 analyses
            for i in range(5):
                storage.save_analysis(
                    repository=f"test/repo{i}",
                    action=None,
                    graph_data={"nodes": []},
                    statistics={"total_nodes": 0}
                )
            
            # Limit to 2
            analyses = storage.list_analyses(limit=2)
            assert len(analyses) == 2
    
    def test_list_analyses_filtered_by_repository(self):
        """Test listing analyses filtered by repository."""
        with tempfile.TemporaryDirectory() as tmpdir:
            storage = AnalysisStorage(storage_dir=tmpdir)
            
            # Save analyses for different repositories
            storage.save_analysis(
                repository="test/repo1",
                action=None,
                graph_data={"nodes": []},
                statistics={"total_nodes": 0}
            )
            storage.save_analysis(
                repository="test/repo2",
                action=None,
                graph_data={"nodes": []},
                statistics={"total_nodes": 0}
            )
            storage.save_analysis(
                repository="test/repo1",
                action=None,
                graph_data={"nodes": []},
                statistics={"total_nodes": 0}
            )
            
            # Filter by repo1
            analyses = storage.list_analyses(repository="test/repo1")
            assert len(analyses) == 2
            for analysis in analyses:
                assert analysis["repository"] == "test/repo1"
    
    def test_list_analyses_with_invalid_json(self, tmp_path, monkeypatch, capsys):
        """Test listing analyses handles invalid JSON gracefully."""
        storage = AnalysisStorage(storage_dir=str(tmp_path))
        
        # Create a valid analysis
        storage.save_analysis(
            repository="test/repo",
            action=None,
            graph_data={"nodes": []},
            statistics={"total_nodes": 0}
        )
        
        # Create an invalid JSON file
        invalid_file = tmp_path / "invalid.json"
        invalid_file.write_text("not valid json")
        
        analyses = storage.list_analyses()
        # Should return the valid analysis and skip the invalid one
        assert len(analyses) == 1
        assert analyses[0]["repository"] == "test/repo"
    
    def test_delete_analysis_existing(self):
        """Test deleting an existing analysis."""
        with tempfile.TemporaryDirectory() as tmpdir:
            storage = AnalysisStorage(storage_dir=tmpdir)
            
            analysis_id = storage.save_analysis(
                repository="test/repo",
                action=None,
                graph_data={"nodes": []},
                statistics={"total_nodes": 0}
            )
            
            file_path = storage.storage_dir / f"{analysis_id}.json"
            assert file_path.exists()
            
            result = storage.delete_analysis(analysis_id)
            assert result is True
            assert not file_path.exists()
    
    def test_delete_analysis_nonexistent(self):
        """Test deleting a non-existent analysis."""
        with tempfile.TemporaryDirectory() as tmpdir:
            storage = AnalysisStorage(storage_dir=tmpdir)
            result = storage.delete_analysis("nonexistent-id")
            assert result is False

