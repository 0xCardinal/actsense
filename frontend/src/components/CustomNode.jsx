import React from 'react'
import { Handle, Position } from 'reactflow'

function CustomNode({ data, selected }) {
  const handleClick = (e) => {
    e.stopPropagation()
    e.preventDefault()
    console.log('CustomNode clicked:', data)
    if (data && data.onNodeClick) {
      data.onNodeClick(data)
    }
  }

  const handleMouseEnter = (e) => {
    e.stopPropagation()
    if (data && data.onNodeHover) {
      // Use nodeId if available, otherwise fall back to originalId or nodeLabel
      const nodeId = data.nodeId || data.originalId || data.nodeLabel
      data.onNodeHover(nodeId)
    }
  }

  const handleMouseLeave = (e) => {
    e.stopPropagation()
    if (data && data.onNodeUnhover) {
      data.onNodeUnhover()
    }
  }

  const isHighlighted = data?.isHighlighted || false

  return (
    <div
      onClick={handleClick}
      onMouseEnter={handleMouseEnter}
      onMouseLeave={handleMouseLeave}
      style={{
        background: isHighlighted 
          ? (data.hasIssues ? `${data.color}20` : '#eff6ff')
          : (data.hasIssues ? `${data.color}08` : '#ffffff'),
        border: `2px solid ${isHighlighted 
          ? '#3b82f6' 
          : (data.hasIssues ? data.color : '#e5e7eb')}`,
        borderRadius: '8px',
        color: '#111827',
        width: 220,
        padding: '12px',
        fontSize: '0.875rem',
        cursor: 'pointer',
        boxShadow: isHighlighted 
          ? '0 4px 12px 0 rgba(59, 130, 246, 0.3)' 
          : '0 1px 2px 0 rgba(0, 0, 0, 0.05)',
        transition: 'all 0.15s ease',
        transform: isHighlighted ? 'scale(1.05)' : 'scale(1)',
      }}
      className="custom-node"
    >
      <div className="node-label">
        <span className="node-icon">{data.icon}</span>
        <span className="node-text">{data.label}</span>
        {data.hasIssues && (
          <span className="node-badge" style={{ backgroundColor: data.color }}>
            {data.issueCount}
          </span>
        )}
      </div>
      <Handle type="target" position={Position.Left} />
      <Handle type="source" position={Position.Right} />
    </div>
  )
}

export default CustomNode

