import React, { useMemo, useEffect, useState, useCallback } from 'react'
import ReactFlow, {
  Background,
  BackgroundVariant,
  Controls,
  MarkerType,
  useNodesState,
  useEdgesState,
} from 'reactflow'
import 'reactflow/dist/style.css'
import dagre from 'dagre'
import NodeDetailsPanel from './NodeDetailsPanel'
import CustomNode from './CustomNode'
import { filterNodes } from '../utils/nodeFilters'
import './ActionGraph.css'

const nodeTypes = {
  custom: CustomNode,
}

function ActionGraph({ graphData, onNodeSelect, filter, onClearFilter }) {
  const [selectedNode, setSelectedNode] = useState(null)
  const [hoveredNodeId, setHoveredNodeId] = useState(null)

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
    const GROUP_HORIZONTAL_SPACING = 400
    const START_X = 100
    const START_Y = 100
    const nodeWidth = 200
    const nodeHeight = 60
    
    // Position nodes in groups using dagre for each group
    const positionedNodes = []
    
    nodeGroups.forEach((group, groupIndex) => {
      // Create a dagre graph for this group
      const g = new dagre.graphlib.Graph()
      g.setDefaultEdgeLabel(() => ({}))
      g.setGraph({ 
        rankdir: 'LR', // Left to right
        nodesep: 30,   // Vertical spacing between nodes (further reduced)
        ranksep: 100,  // Horizontal spacing between ranks
        align: 'UL',   // Align nodes to upper left
        acyclicer: 'greedy',
        ranker: 'tight-tree'
      })

      // Add root node
      g.setNode(group.root.id, { 
        width: nodeWidth, 
        height: nodeHeight
      })

      // Add dependency nodes
      group.dependencies.forEach(dep => {
        g.setNode(dep.id, { 
          width: nodeWidth, 
          height: nodeHeight
        })
        // Add edge from root to dependency
        g.setEdge(group.root.id, dep.id)
      })

      // Run dagre layout for this group
      dagre.layout(g)

      // Calculate group offset
      const groupX = START_X + groupIndex * GROUP_HORIZONTAL_SPACING
      
      // Position root node
      const rootDagreNode = g.node(group.root.id)
      positionedNodes.push({
        ...group.root,
        position: {
          x: groupX + rootDagreNode.x - nodeWidth / 2,
          y: START_Y + rootDagreNode.y - nodeHeight / 2
        }
      })

      // Position dependency nodes
      group.dependencies.forEach(dep => {
        const depDagreNode = g.node(dep.id)
        positionedNodes.push({
          ...dep,
          position: {
            x: groupX + depDagreNode.x - nodeWidth / 2,
            y: START_Y + depDagreNode.y - nodeHeight / 2
          }
        })
      })
    })
    
    return positionedNodes
  }
  
  // Hierarchical layout using dagre to minimize edge crossings
  const calculateHierarchicalLayout = (nodes, edges) => {
    // Create a new dagre graph
    const g = new dagre.graphlib.Graph()
    g.setDefaultEdgeLabel(() => ({}))
      g.setGraph({ 
        rankdir: 'LR', // Left to right
        nodesep: 40,   // Vertical spacing between nodes (further reduced)
        ranksep: 120, // Horizontal spacing between ranks
        align: 'UL',   // Align nodes to upper left
        acyclicer: 'greedy', // Handle cycles
        ranker: 'tight-tree' // Use tight-tree ranking for better clustering
      })

    // Add nodes to dagre graph with estimated width/height
    // ReactFlow nodes are typically around 200px wide and 60px tall
    const nodeWidth = 200
    const nodeHeight = 60
    
    nodes.forEach(node => {
      g.setNode(node.id, { 
        width: nodeWidth, 
        height: nodeHeight
      })
    })

    // Deduplicate edges and add to dagre graph
    const edgeSet = new Set()
    if (edges && edges.length > 0) {
      edges.forEach(edge => {
        if (edge.source && edge.target) {
          const edgeKey = `${edge.source}->${edge.target}`
          if (!edgeSet.has(edgeKey)) {
            edgeSet.add(edgeKey)
            g.setEdge(edge.source, edge.target)
          }
        }
      })
    }

    // Run dagre layout algorithm
    dagre.layout(g)

    // Extract positions from dagre and map back to nodes
    const positionedNodes = nodes.map(node => {
      const dagreNode = g.node(node.id)
      return {
        ...node,
        position: {
          x: dagreNode.x - nodeWidth / 2, // Center the node
          y: dagreNode.y - nodeHeight / 2
        }
      }
    })

    return positionedNodes
  }

  // Calculate path from root to a given node (including all ancestors and descendants)
  const calculatePathToNode = useCallback((nodeId, nodes, edges) => {
    if (!nodeId || !nodes || !edges) return new Set()
    
    // Build parent map (reverse of edges) and children map
    const parents = new Map()
    const children = new Map()
    edges.forEach(edge => {
      if (edge.source && edge.target) {
        // Build parent map
        if (!parents.has(edge.target)) {
          parents.set(edge.target, [])
        }
        parents.get(edge.target).push(edge.source)
        
        // Build children map
        if (!children.has(edge.source)) {
          children.set(edge.source, [])
        }
        children.get(edge.source).push(edge.target)
      }
    })
    
    // Find all ancestors using BFS
    const pathNodes = new Set([nodeId])
    const queue = [nodeId]
    const visited = new Set([nodeId])
    
    // First, find all ancestors (parents)
    while (queue.length > 0) {
      const currentId = queue.shift()
      const nodeParents = parents.get(currentId) || []
      
      nodeParents.forEach(parentId => {
        if (!visited.has(parentId)) {
          visited.add(parentId)
          pathNodes.add(parentId)
          queue.push(parentId)
        }
      })
    }
    
    // Then, find all descendants (children)
    const childrenQueue = [nodeId]
    const childrenVisited = new Set([nodeId])
    
    while (childrenQueue.length > 0) {
      const currentId = childrenQueue.shift()
      const nodeChildren = children.get(currentId) || []
      
      nodeChildren.forEach(childId => {
        if (!childrenVisited.has(childId)) {
          childrenVisited.add(childId)
          pathNodes.add(childId)
          childrenQueue.push(childId)
        }
      })
    }
    
    return pathNodes
  }, [])

  // Handle node hover
  const handleNodeHover = useCallback((nodeId) => {
    setHoveredNodeId(nodeId)
  }, [])

  // Handle node unhover
  const handleNodeUnhover = useCallback(() => {
    setHoveredNodeId(null)
  }, [])

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
          nodeId: node.id, // Pass node ID for hover handler
          originalId: node.id, // Keep reference to original
          onNodeClick: handleNodeClick,
          onNodeHover: handleNodeHover,
          onNodeUnhover: handleNodeUnhover,
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
                nodeId: node.id, // Use the duplicated node's ID for hover
              }
            }
          }
        }
        return node
      })
    }
    
    return positionedNodes
  }, [filteredNodes, filteredEdges, filter, handleNodeClick, handleNodeHover, handleNodeUnhover])

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
            type: 'smoothstep',
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

  // Calculate highlighted path nodes (after computedEdges is defined)
  const highlightedPathNodes = useMemo(() => {
    if (!hoveredNodeId || !computedNodes || !computedEdges) return new Set()
    // Use computedEdges which includes the correct edge structure for dependency view
    return calculatePathToNode(hoveredNodeId, computedNodes, computedEdges)
  }, [hoveredNodeId, computedNodes, computedEdges, calculatePathToNode])

  // Update state when computed values change with smooth transition and highlighting
  useEffect(() => {
    // Add transition class and highlighting for nodes
    setNodes(computedNodes.map(node => {
      const isHighlighted = highlightedPathNodes.has(node.id)
      return {
        ...node,
        data: {
          ...node.data,
          isHighlighted: isHighlighted,
        },
        style: {
          ...node.style,
          transition: 'opacity 0.3s ease, transform 0.3s ease',
          opacity: isHighlighted ? 1 : (hoveredNodeId ? 0.3 : 1),
          zIndex: isHighlighted ? 20 : 10, // Always above edges (edges default to 0)
        }
      }
    }))
  }, [computedNodes, highlightedPathNodes, hoveredNodeId, setNodes])

  useEffect(() => {
    setEdges(computedEdges.map(edge => {
      const isHighlighted = highlightedPathNodes.has(edge.source) && highlightedPathNodes.has(edge.target)
      return {
        ...edge,
        style: {
          ...edge.style,
          transition: 'opacity 0.3s ease, stroke-width 0.3s ease',
          stroke: isHighlighted ? '#3b82f6' : '#9ca3af',
          strokeWidth: isHighlighted ? 3 : (edge.style?.strokeWidth || 1.5),
          strokeOpacity: isHighlighted ? 1 : (hoveredNodeId ? 0.2 : (edge.style?.strokeOpacity || 0.5)),
          zIndex: 0, // Edges should be below nodes
        },
        markerEnd: {
          ...edge.markerEnd,
          color: isHighlighted ? '#3b82f6' : '#9ca3af',
        }
      }
    }))
  }, [computedEdges, highlightedPathNodes, hoveredNodeId, setEdges])
  
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
        panOnScroll={true}
        zoomOnScroll={true}
        zoomOnPinch={true}
        zoomOnDoubleClick={true}
        fitView
        fitViewOptions={{ padding: 0.2, maxZoom: 1.5, duration: 500 }}
        proOptions={{ hideAttribution: true }}
        defaultViewport={{ x: 0, y: 0, zoom: 0.8 }}
        defaultEdgeOptions={{
          type: 'smoothstep',
          animated: false,
        }}
        key={`graph-${filter ? JSON.stringify(filter) : 'no-filter'}-${computedEdges.length}-${computedNodes.length}`}
      >
        <Background 
          variant={BackgroundVariant.Dots}
          gap={16}
          size={1}
          color="#e5e7eb"
          bgColor="#ffffff"
        />
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
