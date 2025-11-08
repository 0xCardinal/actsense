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

  return (
    <div
      onClick={handleClick}
      style={{
        background: data.hasIssues ? `${data.color}08` : '#ffffff',
        border: `1px solid ${data.hasIssues ? data.color : '#e5e7eb'}`,
        borderRadius: '8px',
        color: '#111827',
        width: 220,
        padding: '12px',
        fontSize: '0.875rem',
        cursor: 'pointer',
        boxShadow: '0 1px 2px 0 rgba(0, 0, 0, 0.05)',
        transition: 'all 0.15s ease',
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
      <Handle type="target" position={Position.Top} />
      <Handle type="source" position={Position.Bottom} />
    </div>
  )
}

export default CustomNode

