import React, { memo } from 'react'
import { Handle, Position } from 'reactflow'

export const NODE_WIDTH = 248
export const NODE_HEIGHT = 62

const TYPE_LABELS = {
  repository: 'Repository',
  workflow: 'Workflow',
  reusable_workflow: 'Reusable workflow',
  action: 'Action',
  docker_image: 'Docker image',
  container_image: 'Container image',
  package: 'Package',
}

function CustomNode({ data }) {
  const severity = data.hasIssues ? data.severity : 'none'
  const classes = [
    'graph-node',
    `sev-${severity}`,
    data.isHighlighted ? 'is-highlighted' : '',
    data.isDimmed ? 'is-dimmed' : '',
    data.isSelected ? 'is-selected' : '',
  ].filter(Boolean).join(' ')

  const activate = (e) => {
    e.stopPropagation()
    data.onNodeClick && data.onNodeClick(data)
  }

  return (
    <div
      className={classes}
      style={{ width: NODE_WIDTH, height: NODE_HEIGHT }}
      onClick={activate}
      onKeyDown={(e) => {
        if (e.key === 'Enter' || e.key === ' ') {
          e.preventDefault()
          activate(e)
        }
      }}
      onMouseEnter={() => data.onNodeHover && data.onNodeHover(data.nodeId)}
      onMouseLeave={() => data.onNodeUnhover && data.onNodeUnhover()}
      role="button"
      tabIndex={0}
      aria-label={`${TYPE_LABELS[data.nodeType] || 'Node'} ${data.label}${data.hasIssues ? `, ${data.issueCount} findings` : ''}`}
      title={data.label}
    >
      <span className="graph-node-rail" aria-hidden="true" />
      <span className="graph-node-icon" aria-hidden="true">{data.icon}</span>
      <span className="graph-node-body">
        <span className="graph-node-type">
          {TYPE_LABELS[data.nodeType] || data.nodeType}
          {data.isLocal && <span className="graph-node-tag">local</span>}
        </span>
        <span className="graph-node-label">{data.label}</span>
      </span>
      {data.hasIssues ? (
        <span className="graph-node-badge">{data.issueCount}</span>
      ) : (
        <span className="graph-node-ok" aria-hidden="true">
          <svg width="12" height="12" viewBox="0 0 12 12"><path d="M2.5 6.2 5 8.5l4.5-5" fill="none" stroke="currentColor" strokeWidth="1.6" strokeLinecap="round" strokeLinejoin="round" /></svg>
        </span>
      )}
      <Handle type="target" position={Position.Left} className="graph-node-handle" isConnectable={false} />
      <Handle type="source" position={Position.Right} className="graph-node-handle" isConnectable={false} />
    </div>
  )
}

export default memo(CustomNode)
