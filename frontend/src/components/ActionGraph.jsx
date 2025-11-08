import React, { useMemo, useEffect, useState, useCallback } from 'react'
import ReactFlow, {
  Background,
  Controls,
  MarkerType,
  useNodesState,
  useEdgesState,
} from 'reactflow'
import 'reactflow/dist/style.css'
import NodeDetailsPanel from './NodeDetailsPanel'
import CustomNode from './CustomNode'
import { filterNodes } from '../utils/nodeFilters'
import './ActionGraph.css'

const nodeTypes = {
  custom: CustomNode,
}

function ActionGraph({ graphData, onNodeSelect, filter, onClearFilter }) {
  const [selectedNode, setSelectedNode] = useState(null)

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

  const getNodeType = (type) => {
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

  // Calculate layout based on filter type
  const calculateLayout = (nodes, edges, currentFilter) => {
    if (!nodes || nodes.length === 0) {
      return []
    }

    // If filter is for dependencies, use dependency grouping layout
    if (currentFilter?.type === 'has_dependencies') {
      return calculateDependencyLayout(nodes, edges)
    }
    
    // Otherwise use hierarchical layout
    return calculateHierarchicalLayout(nodes, edges)
  }
  
  // Dependency layout: show each node individually with its dependencies below
  // Each dependency node can appear multiple times (once per parent)
  const calculateDependencyLayout = (nodes, edges) => {
    // Build adjacency lists - children are dependencies
    const children = new Map()
    
    nodes.forEach(node => {
      children.set(node.id, [])
    })
    
    if (edges && edges.length > 0) {
      edges.forEach(edge => {
        if (edge.source && edge.target) {
          children.get(edge.source)?.push(edge.target)
        }
      })
    }
    
    // Create a group for each node showing its dependencies
    // Important: Each dependency node will be duplicated for each parent
    // Only show groups for nodes that actually have dependencies
    const nodeGroups = nodes
      .filter(node => {
        const nodeDeps = children.get(node.id) || []
        return nodeDeps.length > 0 // Only show nodes that have dependencies
      })
      .map(node => {
        const nodeDeps = children.get(node.id) || []
        // Include all dependencies, even if they appear in other groups
        const validDeps = nodeDeps
          .map(depId => {
            const depNode = nodes.find(n => n.id === depId)
            // Create a unique instance for this parent by adding a suffix to the ID
            if (depNode) {
              return {
                ...depNode,
                id: `${depNode.id}__from__${node.id}`, // Unique ID for this instance
                originalId: depNode.id, // Keep reference to original
                parentId: node.id, // Track which parent this instance belongs to
                // Preserve all node data
                data: {
                  ...depNode.data,
                  originalId: depNode.id,
                  parentId: node.id
                }
              }
            }
            return null
          })
          .filter(Boolean)
        
        return {
          root: node,
          dependencies: validDeps
        }
      })
    
    // Layout constants
    const GROUP_HORIZONTAL_SPACING = 350
    const GROUP_VERTICAL_SPACING = 200
    const NODE_VERTICAL_SPACING = 100
    const START_X = 100
    const START_Y = 100
    
    // Position nodes in groups - each node gets its own column
    const positionedNodes = []
    
    nodeGroups.forEach((group, groupIndex) => {
      const groupX = START_X + groupIndex * GROUP_HORIZONTAL_SPACING
      let currentY = START_Y
      
      // Position root node
      positionedNodes.push({
        ...group.root,
        position: { x: groupX, y: currentY }
      })
      
      // Position dependencies below root
      if (group.dependencies.length > 0) {
        currentY += GROUP_VERTICAL_SPACING
        
        group.dependencies.forEach((dep, depIndex) => {
          positionedNodes.push({
            ...dep,
            position: { x: groupX, y: currentY + depIndex * NODE_VERTICAL_SPACING }
          })
        })
      }
    })
    
    return positionedNodes
  }
  
  // Hierarchical layout for non-dependency views
  const calculateHierarchicalLayout = (nodes, edges) => {
    // Build adjacency lists (deduplicated)
    const children = new Map()
    const parents = new Map()
    
    nodes.forEach(node => {
      children.set(node.id, [])
      parents.set(node.id, [])
    })
    
    // Deduplicate edges when building adjacency lists
    const edgeSet = new Set()
    if (edges && edges.length > 0) {
      edges.forEach(edge => {
        if (edge.source && edge.target) {
          const edgeKey = `${edge.source}->${edge.target}`
          if (!edgeSet.has(edgeKey)) {
            edgeSet.add(edgeKey)
            children.get(edge.source)?.push(edge.target)
            parents.get(edge.target)?.push(edge.source)
          }
        }
      })
    }
    
    // Find root nodes (nodes with no parents, or repositories/workflows)
    const roots = []
    
    // First, prioritize repositories and workflows as roots
    nodes.forEach(node => {
      if (node.type === 'repository') {
        roots.push(node)
      }
    })
    
    // Then add workflows that aren't already included
    nodes.forEach(node => {
      if (node.type === 'workflow' && !roots.find(r => r.id === node.id)) {
        const nodeParents = parents.get(node.id) || []
        // Only add if it's a direct child of a repository or has no parents
        const hasRepoParent = nodeParents.some(parentId => {
          const parentNode = nodes.find(n => n.id === parentId)
          return parentNode && parentNode.type === 'repository'
        })
        if (hasRepoParent || nodeParents.length === 0) {
          roots.push(node)
        }
      }
    })
    
    // Finally, add any nodes with no parents that aren't already included
    if (roots.length === 0) {
      nodes.forEach(node => {
        const nodeParents = parents.get(node.id) || []
        if (nodeParents.length === 0 && !roots.find(r => r.id === node.id)) {
          roots.push(node)
        }
      })
    }
    
    // Calculate depth for each node using BFS for better handling of multiple parents
    const depths = new Map()
    const visited = new Set()
    const queue = []
    
    // Initialize roots at depth 0
    roots.forEach(root => {
      depths.set(root.id, 0)
      visited.add(root.id)
      queue.push({ id: root.id, depth: 0 })
    })
    
    // BFS to calculate depths
    while (queue.length > 0) {
      const { id, depth } = queue.shift()
      const nodeChildren = children.get(id) || []
      
      nodeChildren.forEach(childId => {
        if (!visited.has(childId)) {
          visited.add(childId)
          depths.set(childId, depth + 1)
          queue.push({ id: childId, depth: depth + 1 })
        } else {
          // If already visited, use the minimum depth
          const currentDepth = depths.get(childId) || 0
          depths.set(childId, Math.min(currentDepth, depth + 1))
        }
      })
    }
    
    // Set depth 0 for any unvisited nodes (orphans)
    nodes.forEach(node => {
      if (!depths.has(node.id)) {
        depths.set(node.id, 0)
      }
    })
    
    // Group nodes by depth
    const nodesByDepth = new Map()
    nodes.forEach(node => {
      const depth = depths.get(node.id) || 0
      if (!nodesByDepth.has(depth)) {
        nodesByDepth.set(depth, [])
      }
      nodesByDepth.get(depth).push(node)
    })
    
    // Calculate positions with better distribution
    const HORIZONTAL_SPACING = 250
    const VERTICAL_SPACING = 180
    const START_Y = 80
    
    // Calculate max depth and max nodes per depth for centering
    const depthValues = Array.from(depths.values())
    const maxDepth = depthValues.length > 0 ? Math.max(...depthValues) : 0
    const maxNodesInDepth = Math.max(...Array.from(nodesByDepth.values()).map(arr => arr.length), 1)
    const centerX = (maxNodesInDepth - 1) * HORIZONTAL_SPACING / 2
    
    const positionedNodes = nodes.map(node => {
      const depth = depths.get(node.id) || 0
      const depthNodes = nodesByDepth.get(depth) || []
      const indexInDepth = depthNodes.findIndex(n => n.id === node.id)
      const totalInDepth = depthNodes.length
      
      // Center nodes horizontally within their depth
      const totalWidth = (totalInDepth - 1) * HORIZONTAL_SPACING
      const startX = centerX - totalWidth / 2
      
      const x = startX + indexInDepth * HORIZONTAL_SPACING
      const y = START_Y + depth * VERTICAL_SPACING
      
      return {
        ...node,
        position: { x, y }
      }
    })
    
    return positionedNodes
  }

  // Handle node click - using custom node component
  const handleNodeClick = useCallback((nodeData) => {
    console.log('Node clicked via handler:', nodeData)
    // Create a node object from the data
    const nodeObj = {
      id: nodeData.nodeLabel || nodeData.label || 'unknown',
      data: nodeData
    }
    setSelectedNode(nodeObj)
    if (onNodeSelect) {
      onNodeSelect(nodeObj)
    }
  }, [onNodeSelect])

  // Initialize state hooks first with empty arrays
  const [nodesState, setNodes, onNodesChange] = useNodesState([])
  const [edgesState, setEdges, onEdgesChange] = useEdgesState([])

  // Filter nodes based on filter criteria - use shared filtering logic
  const filteredNodes = useMemo(() => {
    return filterNodes(graphData, filter)
  }, [graphData, filter])
  
  // Filter edges to only include edges between filtered nodes
  const filteredEdges = useMemo(() => {
    if (!graphData?.edges || !Array.isArray(graphData.edges)) {
      return []
    }
    
    // First, deduplicate edges - only keep unique source-target pairs
    const edgeMap = new Map()
    graphData.edges.forEach(edge => {
      if (edge.source && edge.target) {
        const edgeKey = `${edge.source}->${edge.target}`
        if (!edgeMap.has(edgeKey)) {
          edgeMap.set(edgeKey, edge)
        }
      }
    })
    const uniqueEdges = Array.from(edgeMap.values())
    
    if (!filter) {
      return uniqueEdges
    }
    
    const filteredNodeIds = new Set(filteredNodes.map(n => n.id))
    return uniqueEdges.filter(edge =>
      filteredNodeIds.has(edge.source) && filteredNodeIds.has(edge.target)
    )
  }, [graphData?.edges, filteredNodes, filter])

  // Compute nodes and edges with animation
  const computedNodes = useMemo(() => {
    if (filteredNodes.length === 0) {
      return []
    }
    const baseNodes = filteredNodes.map((node) => {
      const severity = node.severity || 'none'
      const color = getSeverityColor(severity)
      const hasIssues = node.issue_count > 0
      
      return {
        id: node.id,
        type: 'custom',
        data: {
          label: node.label,
          icon: getNodeType(node.type),
          hasIssues: hasIssues,
          color: color,
          issueCount: node.issue_count || 0,
          issues: node.issues || [],
          nodeType: node.type,
          nodeLabel: node.label,
          originalId: node.id, // Keep original ID for reference
          onNodeClick: handleNodeClick,
        },
        draggable: false,
        selectable: true,
        connectable: false,
        position: { x: 0, y: 0 },
      }
    })
    
    const positionedNodes = calculateLayout(baseNodes, filteredEdges, filter)
    
    // For dependency view, ensure duplicated nodes have correct data
    if (filter?.type === 'has_dependencies') {
      return positionedNodes.map(node => {
        // If this is a duplicated node (has originalId), use original node data
        if (node.originalId) {
          const originalNode = baseNodes.find(n => n.id === node.originalId)
          if (originalNode) {
            return {
              ...node,
              data: {
                ...originalNode.data,
                nodeLabel: originalNode.data.label,
              }
            }
          }
        }
        return node
      })
    }
    
    return positionedNodes
  }, [filteredNodes, filteredEdges, filter, handleNodeClick])

  const computedEdges = useMemo(() => {
    if (filteredEdges.length === 0) {
      return []
    }
    
    // Deduplicate edges one more time to be safe
    const edgeMap = new Map()
    filteredEdges.forEach(edge => {
      if (edge.source && edge.target) {
        const edgeKey = `${edge.source}-${edge.target}`
        if (!edgeMap.has(edgeKey)) {
          edgeMap.set(edgeKey, edge)
        }
      }
    })
    const uniqueEdges = Array.from(edgeMap.values())
    
    // In dependency view, show edges from each node to its duplicated dependencies
    if (filter?.type === 'has_dependencies') {
      const dependencyEdges = []
      
      // For each edge, create an edge to the duplicated dependency node
      // The duplicated node has ID: `${target}__from__${source}`
      uniqueEdges.forEach(edge => {
        if (edge.source && edge.target) {
          const duplicatedTargetId = `${edge.target}__from__${edge.source}`
          dependencyEdges.push({
            id: `${edge.source}-${duplicatedTargetId}`,
            source: edge.source,
            target: duplicatedTargetId,
            type: 'straight',
            animated: false,
            style: {
              stroke: '#9ca3af',
              strokeWidth: 2,
              strokeOpacity: 0.6,
            },
            markerEnd: {
              type: MarkerType.ArrowClosed,
              color: '#9ca3af',
              width: 16,
              height: 16,
            },
          })
        }
      })
      
      return dependencyEdges
    }
    
    // For other views, show all edges
    return uniqueEdges.map((edge) => ({
      id: `${edge.source}-${edge.target}`,
      source: edge.source,
      target: edge.target,
      type: 'smoothstep',
      animated: false,
      style: {
        stroke: '#9ca3af',
        strokeWidth: 1.5,
        strokeOpacity: 0.5,
      },
      markerEnd: {
        type: MarkerType.ArrowClosed,
        color: '#9ca3af',
        width: 16,
        height: 16,
      },
    }))
  }, [filteredEdges, filter])

  // Update state when computed values change with smooth transition
  useEffect(() => {
    // Add transition class for smooth animation
    setNodes(computedNodes.map(node => ({
      ...node,
      style: {
        ...node.style,
        transition: 'opacity 0.3s ease, transform 0.3s ease',
      }
    })))
  }, [computedNodes, setNodes])

  useEffect(() => {
    setEdges(computedEdges.map(edge => ({
      ...edge,
      style: {
        ...edge.style,
        transition: 'opacity 0.3s ease',
      }
    })))
  }, [computedEdges, setEdges])
  
  // Auto-fit view when filter changes - ReactFlow will handle this via fitView prop
  // The key prop on ReactFlow will force a re-render when filter changes

  // Close panel on Escape key (handled at App level)
  useEffect(() => {
    const handleEscape = (event) => {
      if (event.key === 'Escape' && selectedNode && onNodeSelect) {
        onNodeSelect(null)
      }
    }
    window.addEventListener('keydown', handleEscape)
    return () => window.removeEventListener('keydown', handleEscape)
  }, [selectedNode, onNodeSelect])

  if (!graphData || !graphData.nodes || graphData.nodes.length === 0) {
        return (
          <div className="action-graph">
            <div className="empty-state">
              <p>No graph data available</p>
            </div>
          </div>
        )
      }

      // Don't render ReactFlow until we have computed nodes
      if (!computedNodes || computedNodes.length === 0) {
        return (
          <div className="action-graph">
            <div className="empty-state">
              <p>{filter ? 'No nodes match the current filter' : 'Loading graph...'}</p>
              {filter && (
                <button 
                  onClick={() => onClearFilter && onClearFilter()}
                  style={{
                    marginTop: '1rem',
                    padding: '0.5rem 1rem',
                    background: '#111827',
                    color: 'white',
                    border: 'none',
                    borderRadius: '6px',
                    cursor: 'pointer',
                    fontFamily: 'Inter, sans-serif',
                    fontSize: '0.875rem',
                    fontWeight: '500'
                  }}
                >
                  Clear Filter
                </button>
              )}
            </div>
          </div>
        )
      }

  return (
    <div className="action-graph">
      <ReactFlow
        nodes={nodesState}
        edges={edgesState}
        nodeTypes={nodeTypes}
        onNodesChange={onNodesChange}
        onEdgesChange={onEdgesChange}
        onPaneClick={() => onNodeSelect && onNodeSelect(null)}
        nodesDraggable={false}
        nodesConnectable={false}
        elementsSelectable={true}
        selectNodesOnDrag={false}
        panOnDrag={true}
        zoomOnScroll={true}
        fitView
        fitViewOptions={{ padding: 0.2, maxZoom: 1.5, duration: 500 }}
        attributionPosition="bottom-left"
        defaultViewport={{ x: 0, y: 0, zoom: 0.8 }}
        key={`graph-${filter ? JSON.stringify(filter) : 'no-filter'}-${computedEdges.length}-${computedNodes.length}`}
      >
        <Background color="#f9fafb" gap={16} />
        <Controls />
      </ReactFlow>
      
      <div className={`graph-legend ${selectedNode ? 'panel-open' : ''}`}>
        <div className="legend-item">
          <span className="legend-icon">📦</span>
          <span>Repository</span>
        </div>
        <div className="legend-item">
          <span className="legend-icon">⚙️</span>
          <span>Workflow</span>
        </div>
        <div className="legend-item">
          <span className="legend-icon">🔧</span>
          <span>Action</span>
        </div>
        <div className="legend-severity">
          <div className="legend-severity-item">
            <span className="legend-dot" style={{ backgroundColor: '#f85149' }} />
            <span>Critical</span>
          </div>
          <div className="legend-severity-item">
            <span className="legend-dot" style={{ backgroundColor: '#f0883e' }} />
            <span>High</span>
          </div>
          <div className="legend-severity-item">
            <span className="legend-dot" style={{ backgroundColor: '#d29922' }} />
            <span>Medium</span>
          </div>
          <div className="legend-severity-item">
            <span className="legend-dot" style={{ backgroundColor: '#238636' }} />
            <span>Safe</span>
          </div>
        </div>
      </div>
      
      {/* Panel will be rendered at App level */}
    </div>
  )
}

export default ActionGraph

