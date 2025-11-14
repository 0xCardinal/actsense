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

    def _is_reachable(self, source: str, target: str, exclude_edge: Optional[tuple] = None) -> bool:
        """Check if target is reachable from source through existing edges."""
        if source == target:
            return False
        
        # Build adjacency list for DFS
        children = defaultdict(list)
        for edge in self.edges:
            if exclude_edge and edge["source"] == exclude_edge[0] and edge["target"] == exclude_edge[1]:
                continue
            children[edge["source"]].append(edge["target"])
        
        # DFS to check reachability
        visited = set()
        stack = [source]
        
        while stack:
            node = stack.pop()
            if node == target:
                return True
            if node in visited:
                continue
            visited.add(node)
            for child in children.get(node, []):
                if child not in visited:
                    stack.append(child)
        
        return False
    
    def add_edge(self, source: str, target: str, edge_type: str = "uses"):
        """Add an edge to the graph, avoiding redundant transitive edges."""
        # Check if edge already exists
        edge_key = (source, target)
        existing_edge_keys = {(e["source"], e["target"]) for e in self.edges}
        
        if edge_key in existing_edge_keys:
            return
        
        # Note: We don't check for redundancy here during edge addition
        # because the graph is built incrementally and we don't know all paths yet.
        # Redundancy removal happens in get_graph_data() after the graph is complete.
        
        self.edges.append({
            "source": source,
            "target": target,
            "type": edge_type
        })

    def add_issues_to_node(self, node_id: str, issues: List[Dict[str, Any]]):
        """Add security issues to a node."""
        if node_id in self.nodes:
            self.nodes[node_id]["issues"].extend(issues)
            self.issues[node_id].extend(issues)

    def _remove_redundant_edges(self):
        """Remove edges that are redundant (target is reachable through other paths)."""
        if not self.edges:
            return
        
        # Find redundant edges
        redundant_edges = set()
        for edge in self.edges:
            source = edge["source"]
            target = edge["target"]
            
            # Check if target is still reachable from source without this edge
            if self._is_reachable(source, target, exclude_edge=(source, target)):
                redundant_edges.add((source, target))
        
        # Remove redundant edges
        self.edges = [
            edge for edge in self.edges
            if (edge["source"], edge["target"]) not in redundant_edges
        ]
    
    def get_graph_data(self) -> Dict[str, Any]:
        """Get graph data in format suitable for visualization."""
        # Remove redundant edges before returning graph data
        self._remove_redundant_edges()
        
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

