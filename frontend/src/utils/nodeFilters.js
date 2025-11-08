/**
 * Shared filtering logic for nodes across graph and table views
 * Ensures both views show the same nodes
 */
export function filterNodes(graphData, filter) {
  if (!graphData?.nodes || !Array.isArray(graphData.nodes)) {
    return []
  }
  
  if (!filter) {
    return graphData.nodes
  }
  
  if (filter.type === 'has_issues') {
    return graphData.nodes.filter(node => (node.issue_count || 0) > 0)
  }
  
  if (filter.type === 'has_dependencies') {
    // Show nodes that have outgoing edges (nodes that use other actions)
    // AND their dependencies (nodes that are targets of edges)
    const nodesWithEdges = new Set()
    const dependencyNodes = new Set()
    
    if (graphData?.edges) {
      graphData.edges.forEach(edge => {
        nodesWithEdges.add(edge.source) // Parents
        dependencyNodes.add(edge.target) // Dependencies
      })
    }
    
    // Include both parents and their dependencies
    const allRelevantNodes = new Set([...nodesWithEdges, ...dependencyNodes])
    return graphData.nodes.filter(node => allRelevantNodes.has(node.id))
  }
  
  if (filter.type === 'severity' && filter.severity) {
    return graphData.nodes.filter(node => {
      const issues = node.issues || []
      return issues.some(issue => issue.severity === filter.severity)
    })
  }
  
  return graphData.nodes
}

