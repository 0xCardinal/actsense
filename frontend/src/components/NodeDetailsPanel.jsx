import React from 'react'
import './NodeDetailsPanel.css'

function NodeDetailsPanel({ node, onClose }) {
  console.log('NodeDetailsPanel called with node:', node)
  
  if (!node) {
    console.log('NodeDetailsPanel: node is null/undefined, returning null')
    return null
  }

  console.log('NodeDetailsPanel: rendering panel for node:', node)

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

  const getNodeTypeLabel = (type) => {
    switch (type) {
      case 'repository':
        return 'Repository'
      case 'workflow':
        return 'Workflow'
      case 'action':
        return 'Action'
      default:
        return 'Node'
    }
  }

  const issues = node.data?.issues || []
  const hasIssues = issues.length > 0

  return (
    <div className="node-details-panel">
      <div className="panel-header">
        <h2>Node Details</h2>
        <button className="close-button" onClick={onClose} aria-label="Close">
          ×
        </button>
      </div>

      <div className="panel-content">
        <div className="detail-section">
          <div className="detail-label">Name</div>
          <div className="detail-value">{node.data?.nodeLabel || node.id}</div>
        </div>

        <div className="detail-section">
          <div className="detail-label">Type</div>
          <div className="detail-value">{getNodeTypeLabel(node.data?.type)}</div>
        </div>

        <div className="detail-section">
          <div className="detail-label">Node ID</div>
          <div className="detail-value detail-value-small">{node.id}</div>
        </div>

        <div className="detail-section">
          <div className="detail-label">Security Status</div>
          <div className="detail-value">
            {hasIssues ? (
              <span className="status-badge status-issues">
                {issues.length} Issue{issues.length !== 1 ? 's' : ''} Found
              </span>
            ) : (
              <span className="status-badge status-safe">No Issues</span>
            )}
          </div>
        </div>

        {hasIssues && (
          <div className="detail-section issues-section">
            <div className="detail-label">Security Issues</div>
            <div className="issues-list">
              {issues.map((issue, index) => {
                const severity = issue.severity || 'low'
                const color = getSeverityColor(severity)
                return (
                  <div key={index} className="issue-item" style={{ borderLeftColor: color }}>
                    <div className="issue-header">
                      <span className="issue-severity" style={{ backgroundColor: color }}>
                        {severity.toUpperCase()}
                      </span>
                      <span className="issue-type">{issue.type || 'Unknown Issue'}</span>
                    </div>
                    {issue.message && (
                      <div className="issue-message">{issue.message}</div>
                    )}
                    {issue.action && (
                      <div className="issue-action">Action: {issue.action}</div>
                    )}
                    {issue.path && (
                      <div className="issue-path">Path: {issue.path}</div>
                    )}
                  </div>
                )
              })}
            </div>
          </div>
        )}

        {!hasIssues && (
          <div className="detail-section">
            <div className="no-issues-message">
              ✓ This node has no security issues detected.
            </div>
          </div>
        )}
      </div>
    </div>
  )
}

export default NodeDetailsPanel

