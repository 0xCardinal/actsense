import React, { useState, useEffect } from 'react'
import './Statistics.css'

function Statistics({ data, onFilterChange, onViewModeChange, currentViewMode }) {
  const [viewMode, setViewMode] = useState(currentViewMode || 'graph') // 'graph' or 'table'
  
  // Sync local state with prop
  React.useEffect(() => {
    if (currentViewMode) {
      setViewMode(currentViewMode)
    }
  }, [currentViewMode])
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

  return (
    <div className="statistics">
      <h3>Statistics</h3>
      <div className="stat-grid">
        <div 
          className="stat-item clickable" 
          onClick={() => {
            onFilterChange && onFilterChange(null)
          }}
          title="Click to view nodes"
        >
          <div className="stat-value">{data.total_nodes}</div>
          <div className="stat-label">Total Nodes</div>
        </div>
        <div 
          className="stat-item clickable"
          onClick={() => {
            onFilterChange && onFilterChange({ type: 'has_dependencies' })
          }}
          title="Click to view dependencies"
        >
          <div className="stat-value">{data.total_edges}</div>
          <div className="stat-label">Dependencies</div>
        </div>
        <div 
          className="stat-item clickable"
          onClick={() => {
            onFilterChange && onFilterChange({ type: 'has_issues' })
          }}
          title="Click to view security issues"
        >
          <div className="stat-value">{data.total_issues}</div>
          <div className="stat-label">Security Issues</div>
        </div>
      </div>
      
      <div className="view-mode-toggle">
        <button
          className={(currentViewMode || viewMode) === 'graph' ? 'active' : ''}
          onClick={() => {
            setViewMode('graph')
            onViewModeChange && onViewModeChange('graph')
          }}
        >
          Graph View
        </button>
        <button
          className={(currentViewMode || viewMode) === 'table' ? 'active' : ''}
          onClick={() => {
            setViewMode('table')
            onViewModeChange && onViewModeChange('table')
          }}
        >
          Table View
        </button>
      </div>
      
      {Object.keys(data.severity_counts).length > 0 && (
        <div className="severity-breakdown">
          <h4>Issues by Severity</h4>
          <div className="severity-list">
            {Object.entries(data.severity_counts).map(([severity, count]) => (
              <div 
                key={severity} 
                className="severity-item clickable"
                onClick={() => {
                  onFilterChange && onFilterChange({ type: 'severity', severity })
                  onViewModeChange && onViewModeChange('graph')
                }}
                title={`Click to view ${severity} issues in graph`}
              >
                <span
                  className="severity-dot"
                  style={{ backgroundColor: getSeverityColor(severity) }}
                />
                <span className="severity-label">{severity}</span>
                <span className="severity-count">{count}</span>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  )
}

export default Statistics

