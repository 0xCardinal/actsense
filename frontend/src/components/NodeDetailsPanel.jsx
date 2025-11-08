import React, { useMemo } from 'react'
import './NodeDetailsPanel.css'

function NodeDetailsPanel({ node, graphData, onClose }) {
  if (!node) {
    return null
  }

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

  const getNodeTypeIcon = (type) => {
    switch (type) {
      case 'repository':
        return '📦'
      case 'workflow':
        return '⚙️'
      case 'action':
        return '🔧'
      default:
        return '•'
    }
  }

  // Find dependencies (nodes this node depends on) and dependents (nodes that depend on this node)
  const { dependencies, dependents } = useMemo(() => {
    if (!graphData?.edges) {
      return { dependencies: [], dependents: [] }
    }

    // Get the actual node ID - handle both original and duplicated nodes
    const nodeId = node.data?.originalId || node.id
    if (!nodeId) {
      return { dependencies: [], dependents: [] }
    }

    const nodeMap = new Map()
    if (graphData.nodes) {
      graphData.nodes.forEach(n => {
        nodeMap.set(n.id, n)
      })
    }

    const deps = []
    const dependentsList = []

    graphData.edges.forEach(edge => {
      if (edge.source === nodeId) {
        // This node depends on edge.target
        const depNode = nodeMap.get(edge.target)
        if (depNode) {
          deps.push(depNode)
        }
      }
      if (edge.target === nodeId) {
        // edge.source depends on this node
        const dependentNode = nodeMap.get(edge.source)
        if (dependentNode) {
          dependentsList.push(dependentNode)
        }
      }
    })

    return {
      dependencies: deps,
      dependents: dependentsList
    }
  }, [graphData, node.id, node.data?.originalId])

  const issues = node.data?.issues || []
  const hasIssues = issues.length > 0

  return (
    <>
      <div className="node-details-backdrop" onClick={onClose} />
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

        {/* Dependency Chain Section - Moved before Security Status */}
        {(dependencies.length > 0 || dependents.length > 0) && (
          <div className="detail-section dependency-section">
            <div className="detail-label">Dependency Chain</div>
            
            {dependents.length > 0 && (
              <div className="dependency-group">
                <div className="dependency-group-label">Depends On This Node</div>
                <div className="dependency-chain">
                  {dependents.map((depNode, index) => (
                    <React.Fragment key={depNode.id}>
                      {index > 0 && <span className="chain-arrow">→</span>}
                      <div className="chain-node">
                        <span className="node-icon">{getNodeTypeIcon(depNode.type)}</span>
                        <span className="node-label">{depNode.label || depNode.id}</span>
                        {depNode.issue_count > 0 && (
                          <span 
                            className="node-issue-badge"
                            style={{ backgroundColor: getSeverityColor(depNode.severity || 'none') }}
                          >
                            {depNode.issue_count}
                          </span>
                        )}
                      </div>
                    </React.Fragment>
                  ))}
                  <span className="chain-arrow">→</span>
                  <div className="chain-node chain-node-current">
                    <span className="node-icon">{getNodeTypeIcon(node.data?.type)}</span>
                    <span className="node-label">{node.data?.nodeLabel || node.id}</span>
                    {hasIssues && (
                      <span 
                        className="node-issue-badge"
                        style={{ backgroundColor: getSeverityColor(issues[0]?.severity || 'none') }}
                      >
                        {issues.length}
                      </span>
                    )}
                  </div>
                </div>
              </div>
            )}

            {dependencies.length > 0 && (
              <div className="dependency-group">
                <div className="dependency-group-label">This Node Depends On</div>
                <div className="dependency-chain">
                  <div className="chain-node chain-node-current">
                    <span className="node-icon">{getNodeTypeIcon(node.data?.type)}</span>
                    <span className="node-label">{node.data?.nodeLabel || node.id}</span>
                    {hasIssues && (
                      <span 
                        className="node-issue-badge"
                        style={{ backgroundColor: getSeverityColor(issues[0]?.severity || 'none') }}
                      >
                        {issues.length}
                      </span>
                    )}
                  </div>
                  {dependencies.map((depNode, index) => (
                    <React.Fragment key={depNode.id}>
                      <span className="chain-arrow">→</span>
                      <div className="chain-node">
                        <span className="node-icon">{getNodeTypeIcon(depNode.type)}</span>
                        <span className="node-label">{depNode.label || depNode.id}</span>
                        {depNode.issue_count > 0 && (
                          <span 
                            className="node-issue-badge"
                            style={{ backgroundColor: getSeverityColor(depNode.severity || 'none') }}
                          >
                            {depNode.issue_count}
                          </span>
                        )}
                      </div>
                    </React.Fragment>
                  ))}
                </div>
              </div>
            )}
          </div>
        )}

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
    </>
  )
}

export default NodeDetailsPanel

