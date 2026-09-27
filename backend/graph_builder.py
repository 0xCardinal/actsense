"""Build dependency graph for GitHub Actions."""
from typing import Dict, List, Set, Optional, Any, Tuple
from collections import defaultdict, deque

_SEVERITY_ORDER = ("critical", "high", "medium", "low")


class GraphBuilder:
    def __init__(self):
        self.nodes: Dict[str, Dict[str, Any]] = {}
        self.edges: List[Dict[str, str]] = []
        self.issues: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
        self._edge_keys: Set[Tuple[str, str]] = set()

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

        children = defaultdict(list)
        for edge in self.edges:
            if exclude_edge and edge["source"] == exclude_edge[0] and edge["target"] == exclude_edge[1]:
                continue
            children[edge["source"]].append(edge["target"])

        visited = set()
        stack = [source]
        while stack:
            node = stack.pop()
            if node == target:
                return True
            if node in visited:
                continue
            visited.add(node)
            stack.extend(child for child in children.get(node, []) if child not in visited)
        return False

    def add_edge(self, source: str, target: str, edge_type: str = "uses"):
        """Add an edge to the graph (duplicates are ignored)."""
        edge_key = (source, target)
        if edge_key in self._edge_keys:
            return
        self._edge_keys.add(edge_key)
        self.edges.append({
            "source": source,
            "target": target,
            "type": edge_type
        })

    def add_issues_to_node(self, node_id: str, issues: List[Dict[str, Any]]):
        """Add security issues to a node."""
        if not issues or node_id not in self.nodes:
            return
        self.nodes[node_id]["issues"].extend(issues)
        self.issues[node_id].extend(issues)

    def _remove_redundant_edges(self):
        """Transitive reduction: drop edges whose target is reachable another way.

        Not applied by get_graph_data(): an edge in this graph means "A directly
        references B". If a workflow uses actions/checkout directly *and* through
        a composite action, removing the direct edge would misreport that the
        workflow only depends on checkout transitively. Kept for callers that
        explicitly want a reduced view.
        """
        if not self.edges:
            return
        redundant_edges = {
            (edge["source"], edge["target"])
            for edge in self.edges
            if self._is_reachable(edge["source"], edge["target"], exclude_edge=(edge["source"], edge["target"]))
        }
        self.edges = [
            edge for edge in self.edges
            if (edge["source"], edge["target"]) not in redundant_edges
        ]
        self._edge_keys = {(e["source"], e["target"]) for e in self.edges}

    def _compute_depths(self) -> Dict[str, int]:
        """Shortest distance (in edges) from any root node. Roots have depth 0."""
        children = defaultdict(list)
        has_parent = set()
        for edge in self.edges:
            children[edge["source"]].append(edge["target"])
            has_parent.add(edge["target"])

        roots = [nid for nid in self.nodes if nid not in has_parent]
        depths: Dict[str, int] = {}
        queue = deque()
        for root in roots:
            depths[root] = 0
            queue.append(root)
        while queue:
            current = queue.popleft()
            for child in children.get(current, []):
                if child not in depths:
                    depths[child] = depths[current] + 1
                    queue.append(child)
        # Nodes only reachable through a cycle have no root; place them at 0.
        for nid in self.nodes:
            depths.setdefault(nid, 0)
        return depths

    def get_graph_data(self) -> Dict[str, Any]:
        """Get graph data in format suitable for visualization."""
        depths = self._compute_depths()
        for node_id, node in self.nodes.items():
            issues = node.get("issues", [])
            node["issue_count"] = len(issues)
            node["depth"] = depths.get(node_id, 0)
            severities = {issue.get("severity", "low") for issue in issues}
            node["severity"] = next((s for s in _SEVERITY_ORDER if s in severities), "low" if issues else "none")

        return {
            "nodes": list(self.nodes.values()),
            "edges": self.edges,
            "issues": dict(self.issues)
        }

    def _unique_issues(self) -> List[Dict[str, Any]]:
        """All issues, counting an issue object once even if attached to several nodes.

        Findings are deliberately mirrored onto related nodes (a package-install
        finding onto the package node, an unpinned-image finding onto the image
        node) so the graph is navigable; they are still one finding.
        """
        seen: Set[int] = set()
        unique = []
        for issues in self.issues.values():
            for issue in issues:
                if id(issue) not in seen:
                    seen.add(id(issue))
                    unique.append(issue)
        return unique

    def get_statistics(self) -> Dict[str, Any]:
        """Get statistics about the graph."""
        unique_issues = self._unique_issues()
        severity_counts = defaultdict(int)
        for issue in unique_issues:
            severity_counts[issue.get("severity", "low")] += 1

        depths = self._compute_depths()
        return {
            "total_nodes": len(self.nodes),
            "total_edges": len(self.edges),
            "total_issues": len(unique_issues),
            "severity_counts": dict(severity_counts),
            "nodes_with_issues": sum(1 for issues in self.issues.values() if issues),
            "max_depth": max(depths.values(), default=0),
        }
