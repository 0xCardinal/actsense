import React, { useMemo, useState, useCallback, memo, useRef } from 'react'
import './TransitiveDependenciesTable.css'

// AccordionItem component
const AccordionItem = ({ 
  rowId,
  row, 
  isExpanded, 
  onToggle, 
  onNodeClick, 
  getNodeTypeIcon, 
  getSeverityColor 
}) => {
  const handleToggle = (e) => {
    e.preventDefault()
    e.stopPropagation()
    onToggle(rowId)
  }

  return (
    <div className={`accordion-item ${row.hasIssues ? 'has-issues' : ''}`}>
      <div className="accordion-header" onClick={handleToggle}>
        <div className="accordion-header-content">
          <div className="accordion-toggle">
            <span className={`toggle-icon ${isExpanded ? 'expanded' : ''}`}>
              ▶
            </span>
            <span className="path-length-badge">{row.pathLength}</span>
          </div>
          <div className="accordion-summary">
            <div className="summary-node">
              <span className="node-icon">{getNodeTypeIcon(row.rootNode.type)}</span>
              <span className="node-label">{row.rootNode.label}</span>
            </div>
            <span className="arrow-separator">→</span>
            <div className="summary-node">
              <span className="node-icon">{getNodeTypeIcon(row.leafNode.type)}</span>
              <span className="node-label">{row.leafNode.label}</span>
            </div>
          </div>
          <div className="accordion-meta">
            {row.totalIssues > 0 ? (
              <span 
                className="issue-badge"
                style={{ backgroundColor: getSeverityColor(row.maxSeverity) }}
              >
                {row.totalIssues} issue{row.totalIssues !== 1 ? 's' : ''}
              </span>
            ) : (
              <span className="no-issues">No issues</span>
            )}
          </div>
        </div>
      </div>
      {isExpanded ? (
        <div 
          className="accordion-content"
        >
          {row.path && Array.isArray(row.path) && row.path.length > 0 ? (
            <div className="dependency-chain">
              {row.path.map((node, index) => {
                if (!node || !node.id) {
                  return null
                }
                return (
                  <React.Fragment key={`${rowId}-${node.id}-${index}`}>
                    <div 
                      className="chain-node"
                      onClick={(e) => onNodeClick(node, e)}
                    >
                      <span className="node-icon">{getNodeTypeIcon(node.type)}</span>
                      <span className="node-label">{node.label || node.id || 'Unknown'}</span>
                      <span className="node-type-badge">{node.type || 'unknown'}</span>
                      {node.issue_count > 0 && (
                        <span 
                          className="node-issue-badge"
                          style={{ backgroundColor: getSeverityColor(node.severity) }}
                        >
                          {node.issue_count}
                        </span>
                      )}
                    </div>
                    {index < row.path.length - 1 && (
                      <span className="chain-arrow">→</span>
                    )}
                  </React.Fragment>
                )
              })}
            </div>
          ) : (
            <div style={{ padding: '1rem', color: '#6b7280' }}>
              No path data available (path: {row.path ? 'exists but empty' : 'missing'})
            </div>
          )}
        </div>
      ) : null}
    </div>
  )
}

AccordionItem.displayName = 'AccordionItem'

function TransitiveDependenciesTable({ graphData, onNodeSelect, filter }) {
  const [expandedPaths, setExpandedPaths] = useState([])
  const expandedPathsRef = useRef(new Set()) // Keep ref in sync for fast lookups
  const accordionRef = useRef(null)
  const graphDataRef = useRef(null)
  
  // Track when graphData actually changes (not just length)
  React.useEffect(() => {
    if (graphData && graphData !== graphDataRef.current) {
      graphDataRef.current = graphData
      setExpandedPaths([])
      expandedPathsRef.current = new Set()
    }
  }, [graphData])
  
  // Keep ref in sync with state
  React.useEffect(() => {
    expandedPathsRef.current = new Set(expandedPaths)
  }, [expandedPaths])

  // Build a map of node ID to node data
  const nodeMap = useMemo(() => {
    const map = new Map()
    if (graphData?.nodes) {
      graphData.nodes.forEach(node => {
        map.set(node.id, node)
      })
    }
    return map
  }, [graphData?.nodes])

  // Build adjacency list for dependencies
  const adjacencyList = useMemo(() => {
    const adj = new Map()
    if (graphData?.edges) {
      graphData.edges.forEach(edge => {
        if (!adj.has(edge.source)) {
          adj.set(edge.source, [])
        }
        adj.get(edge.source).push(edge.target)
      })
    }
    return adj
  }, [graphData?.edges])

  // Find root nodes (nodes that are not targets of any edge, or are repositories/workflows)
  const rootNodes = useMemo(() => {
    const targets = new Set()
    if (graphData?.edges) {
      graphData.edges.forEach(edge => {
        targets.add(edge.target)
      })
    }
    
    return (graphData?.nodes || []).filter(node => {
      // Root nodes are either:
      // 1. Not a target of any edge (top-level)
      // 2. A repository or workflow type
      return !targets.has(node.id) || node.type === 'repository' || node.type === 'workflow'
    })
  }, [graphData?.nodes, graphData?.edges])

  // Calculate all transitive dependency paths from root nodes
  const dependencyPaths = useMemo(() => {
    const paths = []
    const pathSet = new Set() // To avoid duplicate paths

    const dfs = (currentPath, currentNodeId, visited = new Set()) => {
      // Avoid cycles
      if (visited.has(currentNodeId)) {
        return
      }
      visited.add(currentNodeId)

      const node = nodeMap.get(currentNodeId)
      if (!node) return

      // Add current node to path
      const newPath = [...currentPath, node]
      const pathKey = newPath.map(n => n.id).join('->')

      // If this node has dependencies, continue traversing
      const dependencies = adjacencyList.get(currentNodeId) || []
      if (dependencies.length > 0) {
        dependencies.forEach(depId => {
          dfs(newPath, depId, new Set(visited))
        })
      } else {
        // Leaf node - save the path if it's unique and has at least 2 nodes
        if (newPath.length > 1 && !pathSet.has(pathKey)) {
          pathSet.add(pathKey)
          paths.push(newPath)
        }
      }
    }

    // Start DFS from each root node
    rootNodes.forEach(rootNode => {
      dfs([], rootNode.id)
    })

    return paths
  }, [rootNodes, nodeMap, adjacencyList])

  // Flatten paths into table rows - one row per path showing the full chain
  const tableRows = useMemo(() => {
    const rows = []
    
    dependencyPaths.forEach((path, pathIndex) => {
      // Skip invalid paths
      if (!path || !Array.isArray(path) || path.length === 0) {
        return
      }
      
      const totalIssues = path.reduce((sum, node) => sum + (node.issue_count || 0), 0)
      const hasIssues = totalIssues > 0
      
      // Create a completely stable ID based on the path content (hash-like)
      // This ensures IDs don't change when filtering or sorting
      const pathKey = path.map(n => n?.id || 'unknown').join('->')
      
      // Create a simple hash from the path key for a stable, unique ID
      let hash = 0
      for (let i = 0; i < pathKey.length; i++) {
        const char = pathKey.charCodeAt(i)
        hash = ((hash << 5) - hash) + char
        hash = hash & hash // Convert to 32-bit integer
      }
      const stableId = `path-${Math.abs(hash)}`
      
      // Validate path data before adding
      if (!path[0] || !path[path.length - 1]) {
        return
      }
      
      rows.push({
        id: String(stableId), // Ensure ID is always a string
        pathIndex,
        path,
        pathLength: path.length,
        rootNode: path[0],
        leafNode: path[path.length - 1],
        totalIssues,
        hasIssues,
        // Get highest severity in the path
        maxSeverity: path.reduce((max, node) => {
          const nodeSeverity = node.severity || 'none'
          const severityOrder = { critical: 4, high: 3, medium: 2, low: 1, none: 0 }
          return severityOrder[nodeSeverity] > severityOrder[max] ? nodeSeverity : max
        }, 'none')
      })
    })

    // Apply filter if present
    let filteredRows = rows
    if (filter) {
      if (filter.type === 'has_issues') {
        // Only show paths with issues
        filteredRows = rows.filter(row => row.hasIssues)
      } else if (filter.type === 'severity' && filter.severity) {
        // Only show paths with the specified severity
        filteredRows = rows.filter(row => {
          return row.path.some(node => {
            const issues = node.issues || []
            return issues.some(issue => issue.severity === filter.severity)
          })
        })
      }
    }

    // Sort by path length (longest first) then by issues
    filteredRows.sort((a, b) => {
      if (b.pathLength !== a.pathLength) {
        return b.pathLength - a.pathLength
      }
      return b.totalIssues - a.totalIssues
    })

    return filteredRows
  }, [dependencyPaths, filter])

  const togglePath = useCallback((pathId) => {
    const pathIdStr = String(pathId) // Ensure pathId is a string
    
    // Save current scroll position before state update
    const scrollContainer = accordionRef.current
    const scrollTop = scrollContainer?.scrollTop || 0
    
    // Use functional update
    setExpandedPaths(prev => {
      const isCurrentlyExpanded = prev.some(id => String(id) === pathIdStr)
      
      // Create new array to ensure React detects the change
      return isCurrentlyExpanded 
        ? prev.filter(id => String(id) !== pathIdStr)
        : [...prev, pathIdStr]
    })
    
    // Restore scroll position after DOM update
    // Use double requestAnimationFrame to ensure it runs after React's render
    requestAnimationFrame(() => {
      requestAnimationFrame(() => {
        if (scrollContainer) {
          scrollContainer.scrollTop = scrollTop
        }
      })
    })
  }, [tableRows])

  const handleNodeClick = useCallback((node, e) => {
    e.stopPropagation() // Prevent accordion toggle
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
  }, [onNodeSelect])

  // Memoize helper functions to prevent re-creation on every render
  const getNodeTypeIconMemo = useCallback((type) => {
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
  }, [])

  const getSeverityColorMemo = useCallback((severity) => {
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
  }, [])

  return (
    <div className="transitive-dependencies-container">
      <div className="dependencies-header">
        <h2>Transitive Dependencies</h2>
        <div className="dependencies-count">
          {tableRows.length} dependency path{tableRows.length !== 1 ? 's' : ''}
        </div>
      </div>
      
      {tableRows.length === 0 ? (
        <div className="dependencies-empty">
          <p>No dependencies found</p>
        </div>
      ) : (
        <div className="dependencies-accordion" ref={accordionRef}>
          {tableRows.map((row, index) => {
            // Use array directly to ensure React detects changes
            // Ensure both are strings for comparison
            const rowIdStr = String(row.id)
            // Use both state and ref for checking (ref is faster, state ensures React sees changes)
            const isExpandedInState = expandedPaths.some(id => String(id) === rowIdStr)
            const isExpandedInRef = expandedPathsRef.current.has(rowIdStr)
            const isExpanded = isExpandedInState || isExpandedInRef
            
            return (
              <AccordionItem
                key={rowIdStr}
                rowId={rowIdStr}
                row={row}
                isExpanded={isExpanded}
                onToggle={togglePath}
                onNodeClick={handleNodeClick}
                getNodeTypeIcon={getNodeTypeIconMemo}
                getSeverityColor={getSeverityColorMemo}
              />
            )
          })}
        </div>
      )}
    </div>
  )
}

export default TransitiveDependenciesTable
