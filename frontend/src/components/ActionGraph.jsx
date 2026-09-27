import React, { useMemo, useEffect, useState, useCallback } from 'react'
import ReactFlow, {
  Background,
  BackgroundVariant,
  Controls,
  MiniMap,
  MarkerType,
  useNodesState,
  useEdgesState,
} from 'reactflow'
import 'reactflow/dist/style.css'
import dagre from 'dagre'
import CustomNode, { NODE_WIDTH, NODE_HEIGHT } from './CustomNode'
import { filterNodes } from '../utils/nodeFilters'
import { getNodeTypeIcon, normalizeNodeType } from '../utils/nodeIcons'
import './ActionGraph.css'

const nodeTypes = {
  custom: CustomNode,
}

const SEVERITY_VAR = {
  critical: '#dc2626',
  high: '#ea580c',
  medium: '#ca8a04',
  low: '#6b7280',
  none: '#16a34a',
}

const EDGE_COLOR = '#c3c8d0'
const EDGE_HIGHLIGHT = '#2563eb'

const LEGEND_TYPES = [
  ['repository', 'Repository'],
  ['workflow', 'Workflow'],
  ['reusable_workflow', 'Reusable workflow'],
  ['action', 'Action'],
  ['image', 'Image'],
  ['package', 'Package'],
]

function layoutGraph(nodes, edges, graphOptions) {
  const g = new dagre.graphlib.Graph()
  g.setDefaultEdgeLabel(() => ({}))
  g.setGraph({
    rankdir: 'LR',
    nodesep: 16,
    ranksep: 84,
    marginx: 24,
    marginy: 24,
    acyclicer: 'greedy',
    ranker: 'network-simplex',
    ...graphOptions,
  })
  nodes.forEach(node => g.setNode(node.id, { width: NODE_WIDTH, height: NODE_HEIGHT }))
  edges.forEach(edge => {
    if (g.hasNode(edge.source) && g.hasNode(edge.target)) {
      g.setEdge(edge.source, edge.target)
    }
  })
  dagre.layout(g)
  return nodes.map(node => {
    const pos = g.node(node.id)
    return { ...node, position: { x: pos.x - NODE_WIDTH / 2, y: pos.y - NODE_HEIGHT / 2 } }
  })
}

// Dependency view: each parent with its direct dependencies, one group per
// parent, dependency nodes duplicated per parent so every group is readable.
function layoutDependencyGroups(nodes, edges) {
  const byId = new Map(nodes.map(n => [n.id, n]))
  const children = new Map()
  edges.forEach(edge => {
    if (!children.has(edge.source)) children.set(edge.source, [])
    children.get(edge.source).push(edge.target)
  })

  const positioned = []
  let offsetY = 0
  nodes.forEach(root => {
    const deps = (children.get(root.id) || []).map(id => byId.get(id)).filter(Boolean)
    if (deps.length === 0) return
    const copies = deps.map(dep => ({
      ...dep,
      id: `${dep.id}__from__${root.id}`,
      data: { ...dep.data, nodeId: `${dep.id}__from__${root.id}`, originalId: dep.id },
    }))
    const groupEdges = copies.map(c => ({ source: root.id, target: c.id }))
    const laid = layoutGraph([root, ...copies], groupEdges)
    const height = Math.max(...laid.map(n => n.position.y)) + NODE_HEIGHT
    laid.forEach(n => positioned.push({ ...n, position: { x: n.position.x, y: n.position.y + offsetY } }))
    offsetY += height + 48
  })
  return positioned
}

// All ancestors and descendants of a node.
function lineageOf(nodeId, edges) {
  if (!nodeId) return null
  const parents = new Map()
  const children = new Map()
  edges.forEach(({ source, target }) => {
    if (!parents.has(target)) parents.set(target, [])
    parents.get(target).push(source)
    if (!children.has(source)) children.set(source, [])
    children.get(source).push(target)
  })
  const seen = new Set([nodeId])
  const walk = (map) => {
    const queue = [nodeId]
    while (queue.length) {
      const current = queue.shift()
      for (const next of map.get(current) || []) {
        if (!seen.has(next)) {
          seen.add(next)
          queue.push(next)
        }
      }
    }
  }
  walk(parents)
  walk(children)
  return seen
}

function ActionGraph({ graphData, onNodeSelect, filter, onClearFilter, selectedNodeId }) {
  const [hoveredNodeId, setHoveredNodeId] = useState(null)
  const [showMiniMap, setShowMiniMap] = useState(true)

  const handleNodeHover = useCallback((nodeId) => setHoveredNodeId(nodeId), [])
  const handleNodeUnhover = useCallback(() => setHoveredNodeId(null), [])

  const handleNodeClick = useCallback((nodeData) => {
    const id = nodeData.originalId || nodeData.nodeId
    onNodeSelect && onNodeSelect({
      id,
      data: { ...nodeData, originalId: id },
    })
  }, [onNodeSelect])

  const [nodesState, setNodes, onNodesChange] = useNodesState([])
  const [edgesState, setEdges, onEdgesChange] = useEdgesState([])

  const filteredNodes = useMemo(() => filterNodes(graphData, filter), [graphData, filter])

  const filteredEdges = useMemo(() => {
    if (!Array.isArray(graphData?.edges)) return []
    const ids = new Set(filteredNodes.map(n => n.id))
    const seen = new Set()
    return graphData.edges.filter(edge => {
      const key = `${edge.source}->${edge.target}`
      if (!edge.source || !edge.target || seen.has(key)) return false
      seen.add(key)
      return ids.has(edge.source) && ids.has(edge.target)
    })
  }, [graphData?.edges, filteredNodes])

  const isDependencyView = filter?.type === 'has_dependencies'

  // Layout depends only on graph shape, never on hover/selection.
  const laidOutNodes = useMemo(() => {
    if (filteredNodes.length === 0) return []
    const base = filteredNodes.map(node => ({
      id: node.id,
      type: 'custom',
      data: {
        label: node.label,
        icon: getNodeTypeIcon(node.type),
        hasIssues: (node.issue_count || 0) > 0,
        severity: node.severity || 'none',
        issueCount: node.issue_count || 0,
        issues: node.issues || [],
        nodeType: node.type,
        nodeLabel: node.label,
        metadata: node.metadata || {},
        isLocal: Boolean(node.metadata?.local),
        roles: Array.isArray(node.metadata?.roles) ? node.metadata.roles : [],
        nodeId: node.id,
        originalId: node.id,
        onNodeClick: handleNodeClick,
        onNodeHover: handleNodeHover,
        onNodeUnhover: handleNodeUnhover,
      },
      draggable: false,
      connectable: false,
      position: { x: 0, y: 0 },
    }))
    return isDependencyView ? layoutDependencyGroups(base, filteredEdges) : layoutGraph(base, filteredEdges)
  }, [filteredNodes, filteredEdges, isDependencyView, handleNodeClick, handleNodeHover, handleNodeUnhover])

  const renderedEdges = useMemo(() => {
    if (isDependencyView) {
      return filteredEdges.map(edge => ({
        id: `${edge.source}->${edge.target}__from__${edge.source}`,
        source: edge.source,
        target: `${edge.target}__from__${edge.source}`,
      }))
    }
    return filteredEdges.map(edge => ({ id: `${edge.source}->${edge.target}`, source: edge.source, target: edge.target }))
  }, [filteredEdges, isDependencyView])

  const focusId = hoveredNodeId || selectedNodeId || null
  const lineage = useMemo(() => lineageOf(focusId, renderedEdges), [focusId, renderedEdges])

  useEffect(() => {
    setNodes(laidOutNodes.map(node => {
      const inLineage = lineage ? lineage.has(node.id) : false
      return {
        ...node,
        selected: node.id === selectedNodeId,
        zIndex: inLineage ? 2 : 1,
        data: {
          ...node.data,
          isHighlighted: Boolean(lineage) && inLineage,
          isDimmed: Boolean(lineage) && !inLineage,
          isSelected: node.id === selectedNodeId || node.data.originalId === selectedNodeId,
        },
      }
    }))
  }, [laidOutNodes, lineage, selectedNodeId, setNodes])

  useEffect(() => {
    setEdges(renderedEdges.map(edge => {
      const active = lineage ? lineage.has(edge.source) && lineage.has(edge.target) : false
      const color = active ? EDGE_HIGHLIGHT : EDGE_COLOR
      return {
        ...edge,
        type: 'smoothstep',
        pathOptions: { borderRadius: 10 },
        animated: false,
        zIndex: active ? 1 : 0,
        style: {
          stroke: color,
          strokeWidth: active ? 2 : 1.25,
          opacity: lineage && !active ? 0.25 : 1,
          transition: 'opacity 0.2s ease, stroke 0.2s ease',
        },
        markerEnd: { type: MarkerType.ArrowClosed, color, width: 14, height: 14 },
      }
    }))
  }, [renderedEdges, lineage, setEdges])

  useEffect(() => {
    const handleEscape = (event) => {
      if (event.key === 'Escape' && selectedNodeId && onNodeSelect) {
        onNodeSelect(null)
      }
    }
    window.addEventListener('keydown', handleEscape)
    return () => window.removeEventListener('keydown', handleEscape)
  }, [selectedNodeId, onNodeSelect])

  const presentTypes = useMemo(
    () => new Set((graphData?.nodes || []).map(n => normalizeNodeType(n.type))),
    [graphData?.nodes]
  )

  if (!graphData?.nodes?.length) {
    return (
      <div className="action-graph">
        <div className="graph-empty">
          <p>This audit produced no graph.</p>
        </div>
      </div>
    )
  }

  if (laidOutNodes.length === 0) {
    return (
      <div className="action-graph">
        <div className="graph-empty">
          <p>No nodes match the current filter.</p>
          {filter && onClearFilter && (
            <button className="graph-empty-action" onClick={onClearFilter}>Clear filter</button>
          )}
        </div>
      </div>
    )
  }

  return (
    <div className={`action-graph ${selectedNodeId ? 'panel-open' : ''}`}>
      <ReactFlow
        nodes={nodesState}
        edges={edgesState}
        nodeTypes={nodeTypes}
        onNodesChange={onNodesChange}
        onEdgesChange={onEdgesChange}
        onPaneClick={() => onNodeSelect && onNodeSelect(null)}
        nodesDraggable={false}
        nodesConnectable={false}
        elementsSelectable
        selectNodesOnDrag={false}
        panOnScroll
        zoomOnPinch
        zoomOnDoubleClick={false}
        minZoom={0.1}
        maxZoom={2}
        fitView
        fitViewOptions={{ padding: 0.15, maxZoom: 1.1 }}
        proOptions={{ hideAttribution: true }}
        key={`graph-${filter ? JSON.stringify(filter) : 'all'}-${laidOutNodes.length}-${renderedEdges.length}`}
      >
        <Background variant={BackgroundVariant.Dots} gap={18} size={1} color="#d9dce1" />
        <Controls showInteractive={false} position="bottom-left" />
        {showMiniMap && laidOutNodes.length > 12 && (
          <MiniMap
            position="bottom-right"
            pannable
            zoomable
            nodeColor={(n) => SEVERITY_VAR[n.data?.hasIssues ? n.data.severity : 'none'] || '#9ca3af'}
            nodeStrokeWidth={0}
            nodeBorderRadius={4}
            maskColor="rgba(244, 245, 247, 0.7)"
            ariaLabel="Graph overview"
          />
        )}
      </ReactFlow>

      <div className="graph-legend" aria-label="Legend">
        <div className="legend-group">
          {LEGEND_TYPES.filter(([type]) => presentTypes.has(type)).map(([type, label]) => (
            <span key={type} className="legend-item">
              <span className="legend-icon">{getNodeTypeIcon(type)}</span>
              {label}
            </span>
          ))}
        </div>
        <span className="legend-divider" />
        <div className="legend-group">
          {['critical', 'high', 'medium', 'low', 'none'].map(sev => (
            <span key={sev} className="legend-item">
              <span className="sev-dot" style={{ background: SEVERITY_VAR[sev] }} />
              {sev === 'none' ? 'No findings' : sev[0].toUpperCase() + sev.slice(1)}
            </span>
          ))}
        </div>
        {laidOutNodes.length > 12 && (
          <>
            <span className="legend-divider" />
            <button
              type="button"
              className="legend-toggle"
              onClick={() => setShowMiniMap(v => !v)}
              aria-pressed={showMiniMap}
            >
              Map
            </button>
          </>
        )}
      </div>
    </div>
  )
}

export default ActionGraph
