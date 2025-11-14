import React, { useState, useEffect } from 'react'
import './Statistics.css'

function Statistics({ data, onFilterChange, onViewModeChange, currentViewMode, currentFilter }) {
  const [viewMode, setViewMode] = useState(currentViewMode || 'graph') // 'graph' or 'table'
  
  // Sync local state with prop
  React.useEffect(() => {
    if (currentViewMode) {
      setViewMode(currentViewMode)
    }
  }, [currentViewMode])

  // Check if current filter requires table view (dependencies or security issues)
  const requiresTableView = currentFilter?.type === 'has_dependencies' || currentFilter?.type === 'has_issues'
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
            // Reset to graph view when clearing filter
            onViewModeChange && onViewModeChange('graph')
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
            // Automatically switch to table view for dependencies
            onViewModeChange && onViewModeChange('table')
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
            // Automatically switch to table view for security issues
            onViewModeChange && onViewModeChange('table')
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
            if (!requiresTableView) {
              setViewMode('graph')
              onViewModeChange && onViewModeChange('graph')
            }
          }}
          disabled={requiresTableView}
          style={{ opacity: requiresTableView ? 0.5 : 1, cursor: requiresTableView ? 'not-allowed' : 'pointer' }}
        >
          Graph View
        </button>
        <button
          className={(currentViewMode || viewMode) === 'table' ? 'active' : ''}
          onClick={() => {
            if (!requiresTableView) {
              setViewMode('table')
              onViewModeChange && onViewModeChange('table')
            }
          }}
          disabled={requiresTableView}
          style={{ opacity: requiresTableView ? 0.5 : 1, cursor: requiresTableView ? 'not-allowed' : 'pointer' }}
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

