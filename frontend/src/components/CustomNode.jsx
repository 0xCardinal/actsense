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
  const hasChildren = data?.hasChildren || false
  const isCollapsed = data?.isCollapsed || false

  const handleCollapseClick = (e) => {
    e.stopPropagation()
    e.preventDefault()
    if (data?.onToggleCollapse && data?.nodeId) {
      data.onToggleCollapse(data.nodeId, e)
    }
  }

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
        position: 'relative',
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
        {hasChildren && (
          <button
            onClick={handleCollapseClick}
            className="node-collapse-button"
            title={isCollapsed ? 'Expand' : 'Collapse'}
            style={{
              background: 'transparent',
              border: '1px solid #d1d5db',
              cursor: 'pointer',
              padding: '0',
              marginLeft: '6px',
              fontSize: '0.75rem',
              fontWeight: '600',
              color: '#6b7280',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center',
              borderRadius: '50%',
              width: '20px',
              height: '20px',
              transition: 'all 0.15s ease',
            }}
            onMouseEnter={(e) => {
              e.currentTarget.style.background = '#f3f4f6'
              e.currentTarget.style.borderColor = '#9ca3af'
              e.currentTarget.style.color = '#374151'
            }}
            onMouseLeave={(e) => {
              e.currentTarget.style.background = 'transparent'
              e.currentTarget.style.borderColor = '#d1d5db'
              e.currentTarget.style.color = '#6b7280'
            }}
          >
            {isCollapsed ? '+' : '−'}
          </button>
        )}
      </div>
      <Handle type="target" position={Position.Left} />
      <Handle type="source" position={Position.Right} />
    </div>
  )
}

export default CustomNode

