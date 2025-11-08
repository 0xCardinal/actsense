"""Build dependency graph for GitHub Actions."""
from typing import Dict, List, Set, Optional, Any
from collections import defaultdict


class GraphBuilder:
    def __init__(self):
        self.nodes: Dict[str, Dict[str, Any]] = {}
        self.edges: List[Dict[str, str]] = []
        self.issues: Dict[str, List[Dict[str, Any]]] = defaultdict(list)

    def add_node(self, node_id: str, label: str, node_type: str = "action", metadata: Optional[Dict] = None):
        """Add a node to the graph."""
        if node_id not in self.nodes:
            self.nodes[node_id] = {
                "id": node_id,
                "label": label,
                "type": node_type,
                "metadata": metadata or {},
                "issues": []
            }

    def add_edge(self, source: str, target: str, edge_type: str = "uses"):
        """Add an edge to the graph."""
        edge = {
            "source": source,
            "target": target,
            "type": edge_type
        }
        if edge not in self.edges:
            self.edges.append(edge)

    def add_issues_to_node(self, node_id: str, issues: List[Dict[str, Any]]):
        """Add security issues to a node."""
        if node_id in self.nodes:
            self.nodes[node_id]["issues"].extend(issues)
            self.issues[node_id].extend(issues)

    def get_graph_data(self) -> Dict[str, Any]:
        """Get graph data in format suitable for visualization."""
        # Calculate issue counts and severity for nodes
        for node_id, node in self.nodes.items():
            issues = node.get("issues", [])
            node["issue_count"] = len(issues)
            if issues:
                severities = [issue.get("severity", "low") for issue in issues]
                if "critical" in severities:
                    node["severity"] = "critical"
                elif "high" in severities:
                    node["severity"] = "high"
                elif "medium" in severities:
                    node["severity"] = "medium"
                else:
                    node["severity"] = "low"
            else:
                node["severity"] = "none"

        return {
            "nodes": list(self.nodes.values()),
            "edges": self.edges,
            "issues": dict(self.issues)
        }

    def get_statistics(self) -> Dict[str, Any]:
        """Get statistics about the graph."""
        total_nodes = len(self.nodes)
        total_edges = len(self.edges)
        total_issues = sum(len(issues) for issues in self.issues.values())
        
        severity_counts = defaultdict(int)
        for issues in self.issues.values():
            for issue in issues:
                severity_counts[issue.get("severity", "low")] += 1
        
        return {
            "total_nodes": total_nodes,
            "total_edges": total_edges,
            "total_issues": total_issues,
            "severity_counts": dict(severity_counts),
            "nodes_with_issues": len(self.issues)
        }

