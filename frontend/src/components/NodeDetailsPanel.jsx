import React, { useMemo, useState } from 'react'
import './NodeDetailsPanel.css'
import IssueDetailsModal from './IssueDetailsModal'
import ShareModal from './ShareModal'

function NodeDetailsPanel({ node, graphData, onClose, onNodeSelect, shareMode, onScanRepository, onViewAnalysis, repositoryAuditStatus, onStartAnalysis, setRepositoryInput }) {
  const [selectedIssue, setSelectedIssue] = useState(null)
  const [showShareModal, setShowShareModal] = useState(false)
  
  if (!node) {
    return null
  }

  // Generate share link
  const generateShareLink = () => {
    // Get the original node from graphData if available
    const originalNodeId = node.data?.originalId || node.id
    let originalNode = null
    if (graphData?.nodes && originalNodeId) {
      originalNode = graphData.nodes.find(n => n.id === originalNodeId)
    }
    
    // Extract node data
    const nodeType = node.data?.nodeType || node.data?.type || originalNode?.type
    const nodeLabel = node.data?.nodeLabel || node.id
    const metadata = originalNode?.metadata || node.data?.metadata || node.data?.metadata || {}
    const issues = originalNode?.issues || node.data?.issues || []
    
    // Extract repository info
    let repository = null
    if (nodeType === 'repository') {
      const owner = metadata.owner || node.id.split('/')[0]
      const repo = metadata.repo || node.id.split('/')[1]
      if (owner && repo && owner !== 'undefined' && repo !== 'undefined') {
        repository = `${owner}/${repo}`
      }
    } else if (nodeType === 'workflow' && node.id.includes(':')) {
      const repoPart = node.id.split(':')[0]
      repository = repoPart
    } else if (nodeType === 'action') {
      const owner = metadata.owner
      const repo = metadata.repo
      if (owner && repo && owner !== 'undefined' && repo !== 'undefined') {
        repository = `${owner}/${repo}`
      } else if (node.id.includes('@')) {
        const repoPart = node.id.split('@')[0]
        repository = repoPart
      }
    }
    
    // Find the scanned repository (root repository from the analysis)
    // This is the repository node with type 'repository' that has no incoming edges
    let scannedRepository = null
    if (graphData?.nodes && graphData?.edges) {
      const rootRepoNode = graphData.nodes.find(n => {
        if (n.type === 'repository') {
          // Check if it has no incoming edges (it's the root)
          const hasIncomingEdges = graphData.edges.some(edge => edge.target === n.id)
          return !hasIncomingEdges
        }
        return false
      })
      
      if (rootRepoNode) {
        const owner = rootRepoNode.metadata?.owner || rootRepoNode.id.split('/')[0]
        const repo = rootRepoNode.metadata?.repo || rootRepoNode.id.split('/')[1]
        if (owner && repo && owner !== 'undefined' && repo !== 'undefined') {
          scannedRepository = `${owner}/${repo}`
        }
      }
    }
    
    // Create payload
    const payload = {
      repository: repository,
      scannedRepository: scannedRepository, // The repository that was scanned (from analysis JSON)
      node: {
        id: node.id,
        label: nodeLabel,
        type: nodeType,
        metadata: metadata,
        issues: issues.map(issue => ({
          type: issue.type,
          severity: issue.severity,
          message: issue.message,
          description: issue.description,
          mitigation: issue.mitigation,
          line_number: issue.line_number,
          path: issue.path
        }))
      }
    }
    
    // Encode as base64
    const encoded = btoa(JSON.stringify(payload))
    const shareUrl = `${window.location.origin}${window.location.pathname}?share=${encoded}`
    
    return shareUrl
  }

  const handleShareClick = () => {
    setShowShareModal(true)
  }

  // Get the scanned repository (root repository from the analysis)
  const getScannedRepository = () => {
    // In share mode, use scannedRepository from node data (from share link payload)
    if (shareMode && node.data?.scannedRepository) {
      return node.data.scannedRepository
    }
    
    // Otherwise, find it from graphData
    if (graphData?.nodes && graphData?.edges) {
      const rootRepoNode = graphData.nodes.find(n => {
        if (n.type === 'repository') {
          // Check if it has no incoming edges (it's the root)
          const hasIncomingEdges = graphData.edges.some(edge => edge.target === n.id)
          return !hasIncomingEdges
        }
        return false
      })
      
      if (rootRepoNode) {
        const owner = rootRepoNode.metadata?.owner || rootRepoNode.id.split('/')[0]
        const repo = rootRepoNode.metadata?.repo || rootRepoNode.id.split('/')[1]
        if (owner && repo && owner !== 'undefined' && repo !== 'undefined') {
          return `${owner}/${repo}`
        }
      }
    }
    return null
  }

  // Extract repository for the share modal
  const getRepository = () => {
    const originalNodeId = node.data?.originalId || node.id
    let originalNode = null
    if (graphData?.nodes && originalNodeId) {
      originalNode = graphData.nodes.find(n => n.id === originalNodeId)
    }
    
    const nodeType = node.data?.nodeType || node.data?.type || originalNode?.type
    const metadata = originalNode?.metadata || node.data?.metadata || node.data?.metadata || {}
    
    let repository = null
    if (nodeType === 'repository') {
      const owner = metadata.owner || node.id.split('/')[0]
      const repo = metadata.repo || node.id.split('/')[1]
      if (owner && repo && owner !== 'undefined' && repo !== 'undefined') {
        repository = `${owner}/${repo}`
      }
    } else if (nodeType === 'workflow' && node.id.includes(':')) {
      const repoPart = node.id.split(':')[0]
      repository = repoPart
    } else if (nodeType === 'action') {
      const owner = metadata.owner
      const repo = metadata.repo
      if (owner && repo && owner !== 'undefined' && repo !== 'undefined') {
        repository = `${owner}/${repo}`
      } else if (node.id.includes('@')) {
        const repoPart = node.id.split('@')[0]
        repository = repoPart
      }
    }
    
    return repository
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

  // Helper function to get GitHub URL for any node
  const getNodeGitHubUrl = (nodeData) => {
    if (!nodeData) return null
    
    // Get the original node from graphData if available (to get metadata)
    const originalNodeId = nodeData.data?.originalId || nodeData.id || nodeData.data?.id
    let originalNode = null
    if (graphData?.nodes && originalNodeId) {
      originalNode = graphData.nodes.find(n => n.id === originalNodeId)
    }
    
    // Handle different node structures - check ReactFlow node structure first, then original node
    const nodeType = nodeData.data?.nodeType || nodeData.type || originalNode?.type
    const metadata = originalNode?.metadata || nodeData.metadata || nodeData.data?.metadata || {}
    const nodeId = originalNodeId || nodeData.id || nodeData.data?.id || nodeData.label || ''
    
    if (nodeType === 'repository') {
      const owner = metadata.owner || nodeId.split('/')[0]
      const repo = metadata.repo || nodeId.split('/')[1]
      if (owner && repo && owner !== 'undefined' && repo !== 'undefined') {
        return `https://github.com/${owner}/${repo}`
      }
    } else if (nodeType === 'workflow') {
      // Workflow node ID format: owner/repo:workflow_name
      const path = metadata.path
      
      if (path && nodeId.includes(':')) {
        const repoPart = nodeId.split(':')[0]
        const parts = repoPart.split('/')
        if (parts.length >= 2) {
          const owner = parts[0]
          const repo = parts[1]
          if (owner && repo && owner !== 'undefined' && repo !== 'undefined') {
            return `https://github.com/${owner}/${repo}/blob/HEAD/${path}`
          }
        }
      }
    } else if (nodeType === 'action') {
      const owner = metadata.owner
      const repo = metadata.repo
      const ref = metadata.ref || 'main'
      const subdir = metadata.subdir
      
      if (owner && repo && owner !== 'undefined' && repo !== 'undefined') {
        let filePath = 'action.yml'
        if (subdir) {
          filePath = `${subdir}/action.yml`
        }
        return `https://github.com/${owner}/${repo}/blob/${ref}/${filePath}`
      } else {
        // Fallback: try to parse from node ID (format: owner/repo@ref or owner/repo/path@ref)
        if (nodeId.includes('@')) {
          const [repoPart, refPart] = nodeId.split('@')
          const parts = repoPart.split('/')
          if (parts.length >= 2) {
            const owner = parts[0]
            const repo = parts[1]
            if (owner && repo && owner !== 'undefined' && repo !== 'undefined') {
              const subdir = parts.length > 2 ? parts.slice(2).join('/') : null
              const ref = refPart || 'main'
              
              let filePath = 'action.yml'
              if (subdir) {
                filePath = `${subdir}/action.yml`
              }
              return `https://github.com/${owner}/${repo}/blob/${ref}/${filePath}`
            }
          }
        }
      }
    }
    
    return null
  }

  const getGitHubUrl = () => {
    return getNodeGitHubUrl(node)
  }

  const githubUrl = getGitHubUrl()

  // Find other instances of the same issue type
  const findOtherInstances = (issueType) => {
    if (!graphData?.nodes || !graphData?.issues) {
      return []
    }
    
    const otherInstances = []
    Object.entries(graphData.issues).forEach(([nodeId, nodeIssues]) => {
      // Skip the current node
      const currentNodeId = node.data?.originalId || node.id
      if (nodeId === currentNodeId) {
        return
      }
      
      nodeIssues.forEach(issue => {
        if (issue.type === issueType) {
          const nodeData = graphData.nodes.find(n => n.id === nodeId)
          if (nodeData) {
            otherInstances.push({
              ...issue,
              nodeLabel: nodeData.label,
              id: nodeId
            })
          }
        }
      })
    })
    
    return otherInstances
  }

  const getIssueGitHubUrl = (issue) => {
    // Get the original node from graphData to access metadata
    const originalNodeId = node.data?.originalId || node.id
    let originalNode = null
    if (graphData?.nodes && originalNodeId) {
      originalNode = graphData.nodes.find(n => n.id === originalNodeId)
    }
    
    const nodeType = node.data?.nodeType || node.data?.type || originalNode?.type
    const metadata = originalNode?.metadata || node.data?.metadata || {}
    const nodeId = originalNodeId || node.id
    
    // For workflow issues, link to the workflow file
    if (nodeType === 'workflow') {
      const path = metadata.path
      
      if (path && nodeId.includes(':')) {
        const repoPart = nodeId.split(':')[0]
        const parts = repoPart.split('/')
        if (parts.length >= 2) {
          const owner = parts[0]
          const repo = parts[1]
          if (owner && repo && owner !== 'undefined' && repo !== 'undefined') {
            // Use line_number if available (most accurate) - GitHub will highlight this line
            if (issue.line_number) {
              const lineNum = parseInt(issue.line_number, 10)
              if (!isNaN(lineNum) && lineNum > 0) {
                return `https://github.com/${owner}/${repo}/blob/HEAD/${path}#L${lineNum}`
              }
            }
            // Fallback to path if it's a number
            if (issue.path && !isNaN(parseInt(issue.path, 10))) {
              const lineNum = parseInt(issue.path, 10)
              if (lineNum > 0) {
                return `https://github.com/${owner}/${repo}/blob/HEAD/${path}#L${lineNum}`
              }
            }
            // Fallback to job/step context
            if (issue.job && issue.step) {
              return `https://github.com/${owner}/${repo}/blob/HEAD/${path}`
            }
            return `https://github.com/${owner}/${repo}/blob/HEAD/${path}`
          }
        }
      }
    } else if (nodeType === 'action') {
      const owner = metadata.owner
      const repo = metadata.repo
      const ref = metadata.ref || 'main'
      const subdir = metadata.subdir
      
      if (owner && repo) {
        // Try action.yml first, then action.yaml
        let filePath = 'action.yml'
        if (subdir) {
          filePath = `${subdir}/action.yml`
        }
        // Link to action.yml with line number if available
        if (issue.line_number) {
          const lineNum = parseInt(issue.line_number, 10)
          if (!isNaN(lineNum) && lineNum > 0) {
            return `https://github.com/${owner}/${repo}/blob/${ref}/${filePath}#L${lineNum}`
          }
        }
        // Link to action.yml - GitHub will show the file
        return `https://github.com/${owner}/${repo}/blob/${ref}/${filePath}`
      } else {
        // Fallback: try to parse from node ID
        const nodeId = node.id
        if (nodeId.includes('@')) {
          const [repoPart, refPart] = nodeId.split('@')
          const parts = repoPart.split('/')
          if (parts.length >= 2) {
            const owner = parts[0]
            const repo = parts[1]
            const subdir = parts.length > 2 ? parts.slice(2).join('/') : null
            const ref = refPart || 'main'
            
            let filePath = 'action.yml'
            if (subdir) {
              filePath = `${subdir}/action.yml`
            }
            return `https://github.com/${owner}/${repo}/blob/${ref}/${filePath}`
          }
        }
      }
    } else if (nodeType === 'repository') {
      // For repository nodes, link to the repo
      const owner = metadata.owner || node.id.split('/')[0]
      const repo = metadata.repo || node.id.split('/')[1]
      if (owner && repo) {
        return `https://github.com/${owner}/${repo}`
      }
    }
    
    // Fallback to general GitHub URL
    return githubUrl
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

  // Get issues from original node in graphData to ensure we have line_number
  const originalNodeId = node.data?.originalId || node.id
  let originalNode = null
  if (graphData?.nodes && originalNodeId) {
    originalNode = graphData.nodes.find(n => n.id === originalNodeId)
  }
  
  // Get issues from original node if available, otherwise from ReactFlow node
  const issues = originalNode?.issues || node.data?.issues || []
  const hasIssues = issues.length > 0

  return (
    <>
      <div className="node-details-backdrop" onClick={shareMode ? undefined : onClose}>
      </div>
      <div className="node-details-panel">
        <div className="panel-header">
        <h2>Node Details</h2>
        <div className="panel-header-actions">
          {!shareMode && (
            <button
              onClick={handleShareClick}
              className="share-link-button-header"
              title="Copy shareable link"
              aria-label="Copy shareable link"
            >
              <i className="fas fa-link"></i>
              Share
            </button>
          )}
          <button className="close-button" onClick={onClose} aria-label="Close">
            ×
          </button>
        </div>
      </div>

      <div className="panel-content">
        <div className="detail-section">
          <div className="detail-label">Name</div>
          <div className="detail-value">{node.data?.nodeLabel || node.id}</div>
        </div>

        <div className="detail-section">
          <div className="detail-label">Type</div>
          <div className="detail-value">{getNodeTypeLabel(node.data?.nodeType || node.data?.type)}</div>
        </div>

        <div className="detail-section">
          <div className="detail-label">Node ID</div>
          <div className="detail-value detail-value-small">{node.id}</div>
        </div>

        {getScannedRepository() && (
          <div className="detail-section">
            <div className="detail-label">Scanned Repository</div>
            <div className="detail-value">{getScannedRepository()}</div>
          </div>
        )}

        {githubUrl && (
          <div className="detail-section">
            <div className="detail-label">GitHub Link</div>
            <div className="detail-value">
              <a 
                href={githubUrl} 
                target="_blank" 
                rel="noopener noreferrer"
                className="github-link"
              >
                <i className="fab fa-github"></i>
                Open on GitHub
              </a>
            </div>
          </div>
        )}

        {/* Dependency Chain Section - Moved before Security Status */}
        {shareMode && (!graphData || (!dependencies.length && !dependents.length)) ? (
          <div className="detail-section dependency-section">
            <div className="detail-label">Dependency Chain</div>
            <div className="detail-value" style={{ color: '#6b7280', fontStyle: 'italic', marginBottom: '1rem' }}>
              Dependency information is not available in share mode. Scan the repository to view full dependency chain.
            </div>
            {!repositoryAuditStatus?.isAudited && getScannedRepository() && (
              <button
                className="submit-button"
                onClick={() => {
                  const scannedRepository = getScannedRepository()
                  if (scannedRepository && setRepositoryInput) {
                    setRepositoryInput(scannedRepository)
                    // Close the modal after filling in the input
                    onClose()
                  }
                }}
                style={{ width: '100%', marginTop: '0.5rem' }}
              >
                Scan the entire repository
              </button>
            )}
          </div>
        ) : (dependencies.length > 0 || dependents.length > 0) && (
          <div className="detail-section dependency-section">
            <div className="detail-label">Dependency Chain</div>
            
            {dependents.length > 0 && (
              <div className="dependency-group">
                <div className="dependency-group-label">Depends On This Node</div>
                <div className="dependency-chain">
                  {dependents.map((depNode, index) => (
                    <React.Fragment key={depNode.id}>
                      {index > 0 && <span className="chain-arrow">→</span>}
                      <div 
                        className="chain-node chain-node-clickable"
                        onClick={(e) => {
                          e.stopPropagation()
                          if (onNodeSelect) {
                            onNodeSelect({
                              id: depNode.id,
                              data: {
                                nodeLabel: depNode.label || depNode.id,
                                type: depNode.type,
                                nodeType: depNode.type,
                                issues: depNode.issues || [],
                                metadata: depNode.metadata || {},
                                originalId: depNode.id,
                              }
                            })
                          }
                        }}
                        title="Click to view node details"
                      >
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
                      <div 
                        className="chain-node chain-node-clickable"
                        onClick={(e) => {
                          e.stopPropagation()
                          if (onNodeSelect) {
                            onNodeSelect({
                              id: depNode.id,
                              data: {
                                nodeLabel: depNode.label || depNode.id,
                                type: depNode.type,
                                nodeType: depNode.type,
                                issues: depNode.issues || [],
                                metadata: depNode.metadata || {},
                                originalId: depNode.id,
                              }
                            })
                          }
                        }}
                        title="Click to view node details"
                      >
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
                // Ensure we have the issue with line_number if available
                const issueWithLineNumber = issue
                const issueGitHubUrl = getIssueGitHubUrl(issueWithLineNumber)
                const otherInstances = findOtherInstances(issue.type)
                
                return (
                  <div key={index} className="issue-item" style={{ borderLeftColor: color }}>
                    <div className="issue-header">
                      <span className="issue-severity" style={{ backgroundColor: color }}>
                        {severity.toUpperCase()}
                      </span>
                      <span className="issue-type">{issue.type || 'Unknown Issue'}</span>
                      <div className="issue-actions">
                        <button
                          className="issue-icon-button"
                          onClick={() => setSelectedIssue({ ...issue, otherInstances })}
                          title="View details"
                          aria-label="View issue details"
                        >
                          <i className="fas fa-info-circle"></i>
                        </button>
                        {(issueGitHubUrl || githubUrl) ? (
                          <a
                            href={issueGitHubUrl || githubUrl}
                            target="_blank"
                            rel="noopener noreferrer"
                            className="issue-icon-button"
                            title={issue.line_number ? `Open on GitHub (line ${issue.line_number})` : "Open on GitHub"}
                            aria-label={issue.line_number ? `Open on GitHub at line ${issue.line_number}` : "Open on GitHub"}
                          >
                            <i className="fab fa-github"></i>
                          </a>
                        ) : null}
                      </div>
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

      {selectedIssue && (
        <IssueDetailsModal
          issue={selectedIssue}
          otherInstances={selectedIssue.otherInstances || []}
          onClose={() => setSelectedIssue(null)}
        />
      )}

      {showShareModal && (
        <ShareModal
          shareUrl={generateShareLink()}
          repository={getRepository()}
          onClose={() => setShowShareModal(false)}
          onStartAnalysis={onStartAnalysis}
        />
      )}
    </>
  )
}

export default NodeDetailsPanel

