import React from 'react'
import './Statistics.css'

const SEVERITY_ORDER = ['critical', 'high', 'medium', 'low']

function Statistics({ data, onFilterChange, onViewModeChange, currentViewMode, currentFilter }) {
  const viewMode = currentViewMode || 'graph'
  // Dependency and issue lists only exist as tables.
  const requiresTableView = currentFilter?.type === 'has_dependencies' || currentFilter?.type === 'has_issues'

  const severityCounts = data.severity_counts || {}
  const severities = SEVERITY_ORDER.filter(s => severityCounts[s] > 0)
  const maxCount = Math.max(1, ...severities.map(s => severityCounts[s]))

  const applyFilter = (filter, mode) => {
    onFilterChange && onFilterChange(filter)
    onViewModeChange && onViewModeChange(mode)
  }

  const isActive = (type, severity) =>
    type === null
      ? !currentFilter
      : currentFilter?.type === type && (severity === undefined || currentFilter?.severity === severity)

  const tiles = [
    { key: 'nodes', label: 'Nodes', value: data.total_nodes, type: null, mode: 'graph', title: 'Show the full graph' },
    { key: 'deps', label: 'Edges', value: data.total_edges, type: 'has_dependencies', mode: 'table', title: 'List every dependency' },
    { key: 'issues', label: 'Findings', value: data.total_issues, type: 'has_issues', mode: 'table', title: 'List every finding' },
  ]

  return (
    <section className="statistics" aria-label="Audit summary">
      <div className="statistics-head">
        <h2 className="sidebar-section-title">Results</h2>
        {currentFilter && (
          <button type="button" className="clear-filter" onClick={() => applyFilter(null, 'graph')}>
            Clear filter
          </button>
        )}
        {typeof data.max_depth === 'number' && (
          <span className="depth-chip" title="Number of layers from the root to the deepest dependency">
            {data.max_depth + 1} levels
          </span>
        )}
      </div>

      <div className="stat-grid">
        {tiles.map(tile => (
          <button
            key={tile.key}
            type="button"
            className={`stat-item clickable ${isActive(tile.type) ? 'active' : ''}`}
            onClick={() => applyFilter(tile.type ? { type: tile.type } : null, tile.mode)}
            title={tile.title}
            aria-pressed={isActive(tile.type)}
          >
            <span className="stat-value">{tile.value ?? 0}</span>
            <span className="stat-label">{tile.label}</span>
          </button>
        ))}
      </div>

      <div className="view-mode-toggle" role="tablist" aria-label="View">
        {['graph', 'table'].map(mode => (
          <button
            key={mode}
            type="button"
            role="tab"
            aria-selected={viewMode === mode}
            className={viewMode === mode ? 'active' : ''}
            onClick={() => !requiresTableView && onViewModeChange && onViewModeChange(mode)}
            disabled={requiresTableView && mode === 'graph'}
            title={requiresTableView && mode === 'graph' ? 'This list is only available as a table' : undefined}
          >
            {mode === 'graph' ? 'Graph' : 'Table'}
          </button>
        ))}
      </div>

      {severities.length > 0 && (
        <div className="severity-breakdown">
          <h4>By severity</h4>
          <div className="severity-list">
            {severities.map(severity => {
              const active = isActive('severity', severity)
              return (
                <button
                  key={severity}
                  type="button"
                  className={`severity-item clickable ${active ? 'active' : ''}`}
                  onClick={() => active
                    ? applyFilter(null, 'graph')
                    : applyFilter({ type: 'severity', severity }, 'graph')}
                  title={active ? 'Clear filter' : `Show nodes with ${severity} findings`}
                  aria-pressed={active}
                >
                  <span className="sev-dot" style={{ background: `var(--sev-${severity})` }} />
                  <span className="severity-label">{severity}</span>
                  <span className="severity-bar" aria-hidden="true">
                    <span
                      style={{
                        width: `${(severityCounts[severity] / maxCount) * 100}%`,
                        background: `var(--sev-${severity})`,
                      }}
                    />
                  </span>
                  <span className="severity-count">{severityCounts[severity]}</span>
                </button>
              )
            })}
          </div>
        </div>
      )}

    </section>
  )
}

export default Statistics
