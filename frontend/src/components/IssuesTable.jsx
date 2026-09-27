import React, { useMemo } from 'react'
import './IssuesTable.css'

function IssuesTable({ graphData, filter, onNodeSelect, onIssueSelect }) {
  const getSeverityColor = (severity) => {
    switch (severity) {
      case 'critical':
        return '#dc2626'
      case 'high':
        return '#ea580c'
      case 'medium':
        return '#ca8a04'
      case 'low':
        return '#6b7280'
      default:
        return '#16a34a'
    }
  }

  // Collect all issues from all nodes
  const allIssues = useMemo(() => {
    if (!graphData?.nodes) return []
    
    const issues = []
    
    graphData.nodes.forEach(node => {
      const nodeIssues = node.issues || []
      nodeIssues.forEach(issue => {
        issues.push({
          ...issue,
          nodeId: node.id,
          nodeLabel: node.label,
          nodeType: node.type,
        })
      })
    })
    
    // The backend mirrors a finding onto the package / image node it is
    // about, so the graph is navigable. List those once: drop a finding on a
    // package or image node when the identical finding exists on its source
    // node. Identical findings on two workflows are distinct and both kept.
    const MIRROR_TYPES = new Set(['package', 'container_image'])
    const keyOf = ({ nodeId, nodeLabel, nodeType, ...finding }) => JSON.stringify(finding)
    const sourceKeys = new Set(issues.filter(i => !MIRROR_TYPES.has(i.nodeType)).map(keyOf))
    const unique = issues.filter(i => !MIRROR_TYPES.has(i.nodeType) || !sourceKeys.has(keyOf(i)))
    const rank = { critical: 0, high: 1, medium: 2, low: 3 }
    unique.sort((a, b) => (rank[a.severity] ?? 9) - (rank[b.severity] ?? 9) || String(a.type).localeCompare(String(b.type)))
    issues.length = 0
    issues.push(...unique)

    // Apply filter if present
    if (filter) {
      if (filter.type === 'severity' && filter.severity) {
        return issues.filter(issue => issue.severity === filter.severity)
      }
      if (filter.type === 'has_issues') {
        // Show all issues when filtering by has_issues
        return issues
      }
      // For other filter types, show all issues
      return issues
    }
    
    return issues
  }, [graphData, filter])

  const handleRowClick = (issue) => {
    if (onIssueSelect) {
      onIssueSelect(issue)
      return
    }

    // Find the node for this issue
    const node = graphData.nodes.find(n => n.id === issue.nodeId)
    if (node && onNodeSelect) {
      onNodeSelect({
        id: node.id,
        data: {
          nodeLabel: node.label,
          type: node.type,
          issues: node.issues || [],
          nodeType: node.type,
          originalId: node.id,
        }
      })
    }
  }

  return (
    <div className="issues-table-container">
      <div className="issues-table-header">
        <h2>Security Issues</h2>
        <div className="issues-count">{allIssues.length} issue{allIssues.length !== 1 ? 's' : ''}</div>
      </div>
      
      {allIssues.length === 0 ? (
        <div className="issues-empty">
          <p>No issues found{filter ? ' matching the current filter' : ''}</p>
        </div>
      ) : (
        <div className="issues-table-wrapper">
          <table className="issues-table">
            <thead>
              <tr>
                <th>Severity</th>
                <th>Type</th>
                <th>Node</th>
                <th>Message</th>
                <th>Action</th>
              </tr>
            </thead>
            <tbody>
              {allIssues.map((issue, index) => (
                <tr 
                  key={`${issue.nodeId}-${index}`}
                  onClick={() => handleRowClick(issue)}
                  className="issues-table-row"
                >
                  <td>
                    <span 
                      className="severity-badge"
                      style={{ backgroundColor: getSeverityColor(issue.severity) }}
                    >
                      {issue.severity?.toUpperCase() || 'UNKNOWN'}
                    </span>
                  </td>
                  <td>
                    <span className="issue-type-cell">{issue.type || 'Unknown'}</span>
                  </td>
                  <td>
                    <div className="node-cell">
                      <span className="node-label">{issue.nodeLabel || issue.nodeId}</span>
                      <span className="node-type">{issue.nodeType}</span>
                    </div>
                  </td>
                  <td>
                    <div className="message-cell">{issue.message || 'No message'}</div>
                  </td>
                  <td>
                    {issue.action && (
                      <code className="action-cell">{issue.action}</code>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  )
}

export default IssuesTable

