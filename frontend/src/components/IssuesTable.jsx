import React, { useMemo } from 'react'
import './IssuesTable.css'

function IssuesTable({ graphData, filter, onNodeSelect }) {
  const getSeverityColor = (severity) => {
    switch (severity) {
      case 'critical':
        return '#f85149'
      case 'high':
        return '#f0883e'
      case 'medium':
        return '#d29922'
      case 'low':
        return '#8b949e'
      default:
        return '#238636'
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

