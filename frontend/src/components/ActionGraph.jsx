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
    const nodeGroups = nodes.map(node => {
      const nodeDeps = children.get(node.id) || []
      // Only include dependencies that are in the filtered nodes list
      const validDeps = nodeDeps
        .map(depId => nodes.find(n => n.id === depId))
        .filter(Boolean)
      
      return {
        root: node,
        dependencies: validDeps
      }
    })
    
    // Layout constants
    const GROUP_HORIZONTAL_SPACING = 300
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
    // Build adjacency lists
    const children = new Map()
    const parents = new Map()
    
    nodes.forEach(node => {
      children.set(node.id, [])
      parents.set(node.id, [])
    })
    
    if (edges && edges.length > 0) {
      edges.forEach(edge => {
        if (edge.source && edge.target) {
          children.get(edge.source)?.push(edge.target)
          parents.get(edge.target)?.push(edge.source)
        }
      })
    }
    
    // Find root nodes (nodes with no parents)
    const roots = nodes.filter(node => {
      const nodeParents = parents.get(node.id) || []
      return nodeParents.length === 0
    })
    
    // Calculate depth for each node
    const depths = new Map()
    const visited = new Set()
    
    const calculateDepth = (nodeId, depth = 0) => {
      if (visited.has(nodeId)) return
      visited.add(nodeId)
      depths.set(nodeId, Math.max(depths.get(nodeId) || 0, depth))
      
      const nodeChildren = children.get(nodeId) || []
      nodeChildren.forEach(childId => {
        calculateDepth(childId, depth + 1)
      })
    }
    
    roots.forEach(root => calculateDepth(root.id, 0))
    
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
    const HORIZONTAL_SPACING = 300
    const VERTICAL_SPACING = 200
    const START_Y = 80
    
    // Calculate max depth to center the layout
    const depthValues = Array.from(depths.values())
    const maxDepth = depthValues.length > 0 ? Math.max(...depthValues) : 0
    const centerX = depthValues.length > 0 ? (maxDepth * HORIZONTAL_SPACING) / 2 : 0
    
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

  // Filter nodes based on filter criteria
  const filteredNodes = useMemo(() => {
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
      const nodesWithEdges = new Set()
      if (graphData?.edges) {
        graphData.edges.forEach(edge => {
          nodesWithEdges.add(edge.source)
        })
      }
      return graphData.nodes.filter(node => nodesWithEdges.has(node.id))
    }
    
    if (filter.type === 'severity' && filter.severity) {
      return graphData.nodes.filter(node => {
        const issues = node.issues || []
        return issues.some(issue => issue.severity === filter.severity)
      })
    }
    
    return graphData.nodes
  }, [graphData?.nodes, graphData?.edges, filter])
  
  // Filter edges to only include edges between filtered nodes
  const filteredEdges = useMemo(() => {
    if (!graphData?.edges || !Array.isArray(graphData.edges)) {
      return []
    }
    
    if (!filter) {
      return graphData.edges
    }
    
    const filteredNodeIds = new Set(filteredNodes.map(n => n.id))
    return graphData.edges.filter(edge => 
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
          onNodeClick: handleNodeClick,
        },
        draggable: false,
        selectable: true,
        connectable: false,
        position: { x: 0, y: 0 },
      }
    })
    
    return calculateLayout(baseNodes, filteredEdges, filter)
  }, [filteredNodes, filteredEdges, filter, handleNodeClick])

  const computedEdges = useMemo(() => {
    if (filteredEdges.length === 0) {
      return []
    }
    
    // In dependency view, only show direct dependency edges (from node to its dependencies)
    if (filter?.type === 'has_dependencies') {
      // Only show edges where source is a root node in a group and target is its dependency
      const dependencyEdges = filteredEdges.filter(edge => {
        // Check if this edge represents a direct dependency relationship
        // (source node has target as a direct dependency)
        return true // Show all edges in dependency view to show relationships
      })
      
      return dependencyEdges.map((edge) => ({
        id: `${edge.source}-${edge.target}`,
        source: edge.source,
        target: edge.target,
        type: 'straight', // Use straight edges for cleaner dependency view
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
      }))
    }
    
    // For other views, show all edges
    return filteredEdges.map((edge) => ({
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
        key={filter ? JSON.stringify(filter) : 'no-filter'}
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

