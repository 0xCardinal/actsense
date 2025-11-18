import React, { useState } from 'react'
import './SearchResultsPage.css'
import IssueDetailsModal from './IssueDetailsModal'

function SearchResultsPage({ searchQuery, searchResults, graphData, onNodeSelect, onClose }) {
  const [selectedIssue, setSelectedIssue] = useState(null)

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

  const highlightMatch = (text, query) => {
    if (!query.trim()) return text
    
    const queryWords = query.toLowerCase().split(/\s+/).filter(w => w.length > 0)
    let highlighted = text
    
    queryWords.forEach(word => {
      if (word.length < 2) return
      const regex = new RegExp(`(${word})`, 'gi')
      highlighted = highlighted.replace(regex, '<mark>$1</mark>')
    })
    
    return <span dangerouslySetInnerHTML={{ __html: highlighted }} />
  }

  const handleIssueClick = (result) => {
    setSelectedIssue(result.issue)
  }

  const handleNodeClick = (result) => {
    if (onNodeSelect) {
      onNodeSelect({
        id: result.node.id,
        data: {
          nodeLabel: result.node.label,
          type: result.node.type,
          nodeType: result.node.type,
          issues: result.node.issues || [],
          metadata: result.node.metadata || {},
        }
      })
    }
    onClose()
  }

  // Separate issues and assets
  const issueResults = searchResults.filter(r => r.type === 'issue')
  const assetResults = searchResults.filter(r => r.type === 'asset')

  // Group issue results by severity
  const groupedIssues = issueResults.reduce((acc, result) => {
    const severity = result.issue.severity || 'unknown'
    if (!acc[severity]) {
      acc[severity] = []
    }
    acc[severity].push(result)
    return acc
  }, {})

  // Group asset results by type
  const groupedAssets = assetResults.reduce((acc, result) => {
    const assetType = result.node.type || 'asset'
    if (!acc[assetType]) {
      acc[assetType] = []
    }
    acc[assetType].push(result)
    return acc
  }, {})

  const severityOrder = ['critical', 'high', 'medium', 'low', 'unknown']
  const assetTypeOrder = ['repository', 'workflow', 'action']

  return (
    <div className="search-results-page">
      <div className="search-results-header">
        <div className="search-results-header-content">
          <button className="back-button" onClick={onClose}>
            ← Back
          </button>
          <div className="search-results-title">
            <h1>Search Results</h1>
            <p className="search-query-display">"{searchQuery}"</p>
            <p className="search-results-count">
              {searchResults.length} result{searchResults.length !== 1 ? 's' : ''} found
              {issueResults.length > 0 && assetResults.length > 0 && (
                <span className="search-results-breakdown">
                  {' '}({issueResults.length} issue{issueResults.length !== 1 ? 's' : ''}, {assetResults.length} asset{assetResults.length !== 1 ? 's' : ''})
                </span>
              )}
            </p>
          </div>
        </div>
      </div>

      <div className="search-results-content">
        <div className="search-results-content-inner">
          {/* Security Issues Section */}
          {issueResults.length > 0 && (
            <div className="results-section">
              <h2 className="results-section-title">Security Issues ({issueResults.length})</h2>
              {severityOrder.map(severity => {
                const results = groupedIssues[severity]
                if (!results || results.length === 0) return null

                return (
                  <div key={severity} className="severity-group">
                    <h3 className="severity-group-title">
                      <span 
                        className="severity-dot"
                        style={{ backgroundColor: getSeverityColor(severity) }}
                      />
                      {severity.toUpperCase()} ({results.length})
                    </h3>
                    <div className="results-grid">
                      {results.map((result, index) => (
                        <div
                          key={`issue-${result.node.id}-${result.issue.type}-${index}`}
                          className="result-card"
                        >
                          <div className="result-card-header">
                            <span 
                              className="severity-badge"
                              style={{ backgroundColor: getSeverityColor(result.issue.severity) }}
                            >
                              {result.issue.severity?.toUpperCase() || 'UNKNOWN'}
                            </span>
                            <span className="result-type">{result.issue.type || 'Unknown'}</span>
                          </div>
                          <div className="result-card-body">
                            <div className="result-message">
                              {highlightMatch(result.issue.message || 'No message', searchQuery)}
                            </div>
                            <div className="result-node-info">
                              <span className="result-node-label">{result.node.label || result.node.id}</span>
                              <span className="result-node-type">{result.node.type}</span>
                            </div>
                            {result.issue.action && (
                              <div className="result-action">
                                <code>{result.issue.action}</code>
                              </div>
                            )}
                          </div>
                          <div className="result-card-actions">
                            <button 
                              className="result-button"
                              onClick={() => handleIssueClick(result)}
                            >
                              View Details
                            </button>
                            <button 
                              className="result-button primary"
                              onClick={() => handleNodeClick(result)}
                            >
                              Go to Node
                            </button>
                          </div>
                        </div>
                      ))}
                    </div>
                  </div>
                )
              })}
            </div>
          )}

          {/* Assets Section */}
          {assetResults.length > 0 && (
            <div className="results-section">
              <h2 className="results-section-title">Assets ({assetResults.length})</h2>
              {assetTypeOrder.map(assetType => {
                const results = groupedAssets[assetType]
                if (!results || results.length === 0) return null

                return (
                  <div key={assetType} className="severity-group">
                    <h3 className="severity-group-title">
                      <span className="asset-type-icon">
                        {assetType === 'repository' ? '📦' : assetType === 'workflow' ? '⚙️' : '🔧'}
                      </span>
                      {assetType.toUpperCase()} ({results.length})
                    </h3>
                    <div className="results-grid">
                      {results.map((result, index) => (
                        <div
                          key={`asset-${result.node.id}-${index}`}
                          className="result-card"
                        >
                          <div className="result-card-header">
                            <span className="asset-badge">
                              {result.node.type === 'repository' ? '📦' : result.node.type === 'workflow' ? '⚙️' : '🔧'}
                            </span>
                            <span className="result-type">{result.node.type || 'Asset'}</span>
                          </div>
                          <div className="result-card-body">
                            <div className="result-message">
                              {highlightMatch(result.node.label || result.node.id, searchQuery)}
                            </div>
                            {result.node.metadata && (result.node.metadata.owner || result.node.metadata.repo) && (
                              <div className="result-node-info">
                                <span className="result-node-label">
                                  {result.node.metadata.owner && result.node.metadata.repo 
                                    ? `${result.node.metadata.owner}/${result.node.metadata.repo}`
                                    : result.node.metadata.owner || result.node.metadata.repo}
                                </span>
                                {result.node.metadata.path && (
                                  <span className="result-node-type">{result.node.metadata.path}</span>
                                )}
                              </div>
                            )}
                            {result.node.issues && result.node.issues.length > 0 && (
                              <div className="result-issue-count">
                                {result.node.issues.length} issue{result.node.issues.length !== 1 ? 's' : ''}
                              </div>
                            )}
                          </div>
                          <div className="result-card-actions">
                            <button 
                              className="result-button primary"
                              onClick={() => handleNodeClick(result)}
                            >
                              View Node
                            </button>
                          </div>
                        </div>
                      ))}
                    </div>
                  </div>
                )
              })}
            </div>
          )}
        </div>
      </div>

      {selectedIssue && (
        <IssueDetailsModal
          issue={selectedIssue}
          otherInstances={[]}
          onClose={() => setSelectedIssue(null)}
        />
      )}
    </div>
  )
}

export default SearchResultsPage

