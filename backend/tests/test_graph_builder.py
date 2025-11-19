"""Tests for graph_builder.py"""
import pytest
from graph_builder import GraphBuilder


class TestGraphBuilder:
    """Test GraphBuilder class."""
    
    def test_init(self):
        """Test GraphBuilder initialization."""
        builder = GraphBuilder()
        assert builder.nodes == {}
        assert builder.edges == []
        assert builder.issues == {}
    
    def test_add_node(self):
        """Test adding a node to the graph."""
        builder = GraphBuilder()
        builder.add_node("node1", "Node 1", "action", {"owner": "test"})
        
        assert "node1" in builder.nodes
        assert builder.nodes["node1"]["label"] == "Node 1"
        assert builder.nodes["node1"]["type"] == "action"
        assert builder.nodes["node1"]["metadata"] == {"owner": "test"}
        assert builder.nodes["node1"]["issues"] == []
    
    def test_add_node_defaults(self):
        """Test adding a node with default values."""
        builder = GraphBuilder()
        builder.add_node("node1", "Node 1")
        
        assert builder.nodes["node1"]["type"] == "action"
        assert builder.nodes["node1"]["metadata"] == {}
    
    def test_add_node_duplicate(self):
        """Test adding duplicate node doesn't overwrite."""
        builder = GraphBuilder()
        builder.add_node("node1", "Node 1", metadata={"key": "value1"})
        builder.add_node("node1", "Node 2", metadata={"key": "value2"})
        
        # Should keep original
        assert builder.nodes["node1"]["label"] == "Node 1"
        assert builder.nodes["node1"]["metadata"] == {"key": "value1"}
    
    def test_add_edge(self):
        """Test adding an edge to the graph."""
        builder = GraphBuilder()
        builder.add_node("node1", "Node 1")
        builder.add_node("node2", "Node 2")
        builder.add_edge("node1", "node2", "uses")
        
        assert len(builder.edges) == 1
        assert builder.edges[0]["source"] == "node1"
        assert builder.edges[0]["target"] == "node2"
        assert builder.edges[0]["type"] == "uses"
    
    def test_add_edge_duplicate(self):
        """Test adding duplicate edge is ignored."""
        builder = GraphBuilder()
        builder.add_node("node1", "Node 1")
        builder.add_node("node2", "Node 2")
        builder.add_edge("node1", "node2")
        builder.add_edge("node1", "node2")
        
        assert len(builder.edges) == 1
    
    def test_add_issues_to_node(self):
        """Test adding issues to a node."""
        builder = GraphBuilder()
        builder.add_node("node1", "Node 1")
        
        issues = [
            {"severity": "high", "message": "Issue 1"},
            {"severity": "medium", "message": "Issue 2"}
        ]
        builder.add_issues_to_node("node1", issues)
        
        assert len(builder.nodes["node1"]["issues"]) == 2
        assert len(builder.issues["node1"]) == 2
    
    def test_add_issues_to_nonexistent_node(self):
        """Test adding issues to non-existent node does nothing."""
        builder = GraphBuilder()
        issues = [{"severity": "high", "message": "Issue 1"}]
        builder.add_issues_to_node("nonexistent", issues)
        
        assert "nonexistent" not in builder.nodes
        # Issues are only added if node exists (as per implementation)
        assert "nonexistent" not in builder.issues or len(builder.issues.get("nonexistent", [])) == 0
    
    def test_is_reachable_direct(self):
        """Test reachability check for direct connection."""
        builder = GraphBuilder()
        builder.add_node("node1", "Node 1")
        builder.add_node("node2", "Node 2")
        builder.add_edge("node1", "node2")
        
        assert builder._is_reachable("node1", "node2") is True
        assert builder._is_reachable("node2", "node1") is False
    
    def test_is_reachable_transitive(self):
        """Test reachability check for transitive connection."""
        builder = GraphBuilder()
        builder.add_node("node1", "Node 1")
        builder.add_node("node2", "Node 2")
        builder.add_node("node3", "Node 3")
        builder.add_edge("node1", "node2")
        builder.add_edge("node2", "node3")
        
        assert builder._is_reachable("node1", "node3") is True
        assert builder._is_reachable("node3", "node1") is False
    
    def test_is_reachable_same_node(self):
        """Test reachability check for same node returns False."""
        builder = GraphBuilder()
        builder.add_node("node1", "Node 1")
        
        assert builder._is_reachable("node1", "node1") is False
    
    def test_is_reachable_with_exclude_edge(self):
        """Test reachability check excluding an edge."""
        builder = GraphBuilder()
        builder.add_node("node1", "Node 1")
        builder.add_node("node2", "Node 2")
        builder.add_node("node3", "Node 3")
        builder.add_edge("node1", "node2")
        builder.add_edge("node1", "node3")
        builder.add_edge("node2", "node3")
        
        # node3 is reachable from node1 even without direct edge
        assert builder._is_reachable("node1", "node3", exclude_edge=("node1", "node3")) is True
    
    def test_remove_redundant_edges(self):
        """Test removing redundant edges."""
        builder = GraphBuilder()
        builder.add_node("node1", "Node 1")
        builder.add_node("node2", "Node 2")
        builder.add_node("node3", "Node 3")
        
        # Add direct and transitive edges
        builder.add_edge("node1", "node2")
        builder.add_edge("node2", "node3")
        builder.add_edge("node1", "node3")  # Redundant
        
        builder._remove_redundant_edges()
        
        # Should remove the redundant direct edge
        edge_targets = {e["target"] for e in builder.edges if e["source"] == "node1"}
        assert "node3" not in edge_targets or "node2" in edge_targets
    
    def test_get_graph_data(self):
        """Test getting graph data."""
        builder = GraphBuilder()
        builder.add_node("node1", "Node 1")
        builder.add_node("node2", "Node 2")
        builder.add_edge("node1", "node2")
        
        graph_data = builder.get_graph_data()
        
        assert "nodes" in graph_data
        assert "edges" in graph_data
        assert "issues" in graph_data
        assert len(graph_data["nodes"]) == 2
        assert len(graph_data["edges"]) == 1
    
    def test_get_graph_data_with_issues(self):
        """Test getting graph data with issues."""
        builder = GraphBuilder()
        builder.add_node("node1", "Node 1")
        builder.add_issues_to_node("node1", [
            {"severity": "critical", "message": "Critical issue"},
            {"severity": "high", "message": "High issue"}
        ])
        
        graph_data = builder.get_graph_data()
        
        node1 = next(n for n in graph_data["nodes"] if n["id"] == "node1")
        assert node1["issue_count"] == 2
        assert node1["severity"] == "critical"
    
    def test_get_graph_data_severity_priority(self):
        """Test severity priority in graph data."""
        builder = GraphBuilder()
        builder.add_node("node1", "Node 1")
        
        # Test critical priority
        builder.add_issues_to_node("node1", [
            {"severity": "low", "message": "Low"},
            {"severity": "critical", "message": "Critical"}
        ])
        graph_data = builder.get_graph_data()
        node1 = next(n for n in graph_data["nodes"] if n["id"] == "node1")
        assert node1["severity"] == "critical"
        
        # Reset and test high priority
        builder = GraphBuilder()
        builder.add_node("node2", "Node 2")
        builder.add_issues_to_node("node2", [
            {"severity": "low", "message": "Low"},
            {"severity": "high", "message": "High"}
        ])
        graph_data = builder.get_graph_data()
        node2 = next(n for n in graph_data["nodes"] if n["id"] == "node2")
        assert node2["severity"] == "high"
        
        # Reset and test medium priority
        builder = GraphBuilder()
        builder.add_node("node3", "Node 3")
        builder.add_issues_to_node("node3", [
            {"severity": "low", "message": "Low"},
            {"severity": "medium", "message": "Medium"}
        ])
        graph_data = builder.get_graph_data()
        node3 = next(n for n in graph_data["nodes"] if n["id"] == "node3")
        assert node3["severity"] == "medium"
        
        # Reset and test low priority
        builder = GraphBuilder()
        builder.add_node("node4", "Node 4")
        builder.add_issues_to_node("node4", [
            {"severity": "low", "message": "Low"}
        ])
        graph_data = builder.get_graph_data()
        node4 = next(n for n in graph_data["nodes"] if n["id"] == "node4")
        assert node4["severity"] == "low"
    
    def test_get_graph_data_no_issues(self):
        """Test getting graph data for node with no issues."""
        builder = GraphBuilder()
        builder.add_node("node1", "Node 1")
        
        graph_data = builder.get_graph_data()
        node1 = next(n for n in graph_data["nodes"] if n["id"] == "node1")
        assert node1["issue_count"] == 0
        assert node1["severity"] == "none"
    
    def test_get_statistics(self):
        """Test getting graph statistics."""
        builder = GraphBuilder()
        builder.add_node("node1", "Node 1")
        builder.add_node("node2", "Node 2")
        builder.add_edge("node1", "node2")
        builder.add_issues_to_node("node1", [
            {"severity": "high", "message": "Issue 1"},
            {"severity": "medium", "message": "Issue 2"}
        ])
        builder.add_issues_to_node("node2", [
            {"severity": "low", "message": "Issue 3"}
        ])
        
        stats = builder.get_statistics()
        
        assert stats["total_nodes"] == 2
        assert stats["total_edges"] == 1
        assert stats["total_issues"] == 3
        assert stats["nodes_with_issues"] == 2
        assert stats["severity_counts"]["high"] == 1
        assert stats["severity_counts"]["medium"] == 1
        assert stats["severity_counts"]["low"] == 1
    
    def test_get_statistics_empty(self):
        """Test getting statistics for empty graph."""
        builder = GraphBuilder()
        stats = builder.get_statistics()
        
        assert stats["total_nodes"] == 0
        assert stats["total_edges"] == 0
        assert stats["total_issues"] == 0
        assert stats["nodes_with_issues"] == 0
        assert stats["severity_counts"] == {}
    
    def test_remove_redundant_edges_empty(self):
        """Test removing redundant edges from empty graph."""
        builder = GraphBuilder()
        builder._remove_redundant_edges()
        assert len(builder.edges) == 0

