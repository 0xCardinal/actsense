import React from 'react'
import { filterNodes } from '../utils/nodeFilters'
import './NodesTable.css'

function NodesTable({ graphData, filter, onNodeSelect }) {
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

  // Filter nodes based on filter criteria - use shared filtering logic
  const filteredNodes = React.useMemo(() => {
    return filterNodes(graphData, filter)
  }, [graphData, filter])

  const handleRowClick = (node) => {
    if (onNodeSelect) {
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
    <div className="nodes-table-container">
      <div className="nodes-table-header">
        <h2>Nodes</h2>
        <div className="nodes-count">{filteredNodes.length} node{filteredNodes.length !== 1 ? 's' : ''}</div>
      </div>
      
      {filteredNodes.length === 0 ? (
        <div className="nodes-empty">
          <p>No nodes found{filter ? ' matching the current filter' : ''}</p>
        </div>
      ) : (
        <div className="nodes-table-wrapper">
          <div className="nodes-table-header-row">
            <table className="nodes-table">
              <thead>
                <tr>
                  <th>Type</th>
                  <th>Node</th>
                  <th>Issues</th>
                  <th>Severity</th>
                </tr>
              </thead>
            </table>
          </div>
          <div className="nodes-table-body-wrapper">
            <table className="nodes-table">
              <tbody>
                {filteredNodes.map((node) => (
                  <tr 
                    key={node.id}
                    onClick={() => handleRowClick(node)}
                    className="nodes-table-row"
                  >
                    <td>
                      <span className="node-type-badge">
                        <span className="node-icon">{getNodeTypeIcon(node.type)}</span>
                        <span>{node.type}</span>
                      </span>
                    </td>
                    <td>
                      <span className="node-label-cell">{node.label || node.id}</span>
                    </td>
                    <td>
                      {node.issue_count > 0 ? (
                        <span className="issue-count-badge">{node.issue_count}</span>
                      ) : (
                        <span className="no-issues">—</span>
                      )}
                    </td>
                    <td>
                      {node.severity && node.severity !== 'none' ? (
                        <span 
                          className="severity-badge"
                          style={{ backgroundColor: getSeverityColor(node.severity) }}
                        >
                          {node.severity.toUpperCase()}
                        </span>
                      ) : (
                        <span className="no-issues">—</span>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}
    </div>
  )
}

export default NodesTable

