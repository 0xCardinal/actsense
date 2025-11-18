import React, { useState, useMemo, useCallback, useEffect, useRef } from 'react'
import './SearchOverlay.css'

function SearchOverlay({ graphData, onClose, onNodeSelect, onViewAll }) {
  const [searchQuery, setSearchQuery] = useState('')
  const inputRef = useRef(null)

  // Focus input on mount
  useEffect(() => {
    if (inputRef.current) {
      inputRef.current.focus()
    }
  }, [])

  // Handle keyboard shortcuts
  useEffect(() => {
    const handleKeyDown = (e) => {
      // Escape to close
      if (e.key === 'Escape') {
        onClose()
      }
      // Prevent default for Escape
      if (e.key === 'Escape') {
        e.preventDefault()
      }
    }

    window.addEventListener('keydown', handleKeyDown)
    return () => window.removeEventListener('keydown', handleKeyDown)
  }, [onClose])

  // Natural language search function - searches both issues and assets (nodes)
  const searchIssues = useCallback((query, data) => {
    if (!query.trim() || !data?.nodes) {
      return []
    }

    const queryLower = query.toLowerCase().trim()
    const queryWords = queryLower.split(/\s+/).filter(w => w.length > 0)
    
    const results = []
    
    // Search through all nodes and their issues
    data.nodes.forEach(node => {
      const nodeIssues = node.issues || []
      
      // Search issues
      nodeIssues.forEach(issue => {
        let score = 0
        const matches = []
        
        // Build searchable text from issue
        const searchableText = [
          issue.type || '',
          issue.message || '',
          issue.action || '',
          issue.job || '',
          issue.severity || '',
          node.label || node.id || '',
          node.type || '',
        ].join(' ').toLowerCase()
        
        // Check for exact phrase match
        if (searchableText.includes(queryLower)) {
          score += 100
          matches.push('exact phrase')
        }
        
        // Check for individual word matches
        queryWords.forEach(word => {
          if (word.length < 2) return
          
          // Exact word match
          if (searchableText.includes(` ${word} `) || searchableText.startsWith(word) || searchableText.endsWith(` ${word}`)) {
            score += 20
            matches.push(`word: ${word}`)
          }
          // Partial word match
          else if (searchableText.includes(word)) {
            score += 10
            matches.push(`partial: ${word}`)
          }
        })
        
        // Natural language patterns
        const naturalPatterns = {
          'unpinned': ['unpinned', 'not pinned', 'missing version', 'no version'],
          'secret': ['secret', 'password', 'token', 'key', 'credential', 'api key'],
          'permission': ['permission', 'write', 'read', 'access', 'grant'],
          'vulnerability': ['vulnerability', 'security', 'risk', 'threat', 'exploit'],
          'deprecated': ['deprecated', 'outdated', 'old version', 'legacy'],
          'injection': ['injection', 'script', 'code injection', 'command injection'],
          'docker': ['docker', 'container', 'image'],
          'action': ['action', 'github action', 'workflow action'],
          'critical': ['critical', 'severe', 'urgent', 'high priority'],
          'high': ['high severity', 'high risk', 'important'],
          'medium': ['medium severity', 'moderate'],
          'low': ['low severity', 'minor', 'informational'],
        }
        
        Object.entries(naturalPatterns).forEach(([key, patterns]) => {
          if (queryWords.some(qw => patterns.some(p => qw.includes(p) || p.includes(qw)))) {
            if (searchableText.includes(key)) {
              score += 15
              matches.push(`pattern: ${key}`)
            }
          }
        })
        
        // Type-specific matching
        if (issue.type) {
          const typeWords = issue.type.split('_').join(' ').toLowerCase()
          if (queryWords.some(qw => typeWords.includes(qw) || qw.includes(typeWords))) {
            score += 30
            matches.push('type match')
          }
        }
        
        // Severity matching
        if (issue.severity && queryWords.some(qw => issue.severity.toLowerCase().includes(qw) || qw.includes(issue.severity.toLowerCase()))) {
          score += 25
          matches.push('severity match')
        }
        
        // Node label matching
        if (node.label && queryWords.some(qw => node.label.toLowerCase().includes(qw))) {
          score += 15
          matches.push('node match')
        }
        
        if (score > 0) {
          results.push({
            type: 'issue',
            issue,
            node,
            score,
            matches,
            searchableText,
          })
        }
      })
      
      // Search nodes/assets themselves
      let nodeScore = 0
      const nodeMatches = []
      
      // Build searchable text from node
      const nodeMetadata = node.metadata || {}
      const nodeSearchableText = [
        node.label || node.id || '',
        node.type || '',
        nodeMetadata.owner || '',
        nodeMetadata.repo || '',
        nodeMetadata.path || '',
        node.id || '',
      ].join(' ').toLowerCase()
      
      // Check for exact phrase match
      if (nodeSearchableText.includes(queryLower)) {
        nodeScore += 100
        nodeMatches.push('exact phrase')
      }
      
      // Check for individual word matches
      queryWords.forEach(word => {
        if (word.length < 2) return
        
        // Exact word match
        if (nodeSearchableText.includes(` ${word} `) || nodeSearchableText.startsWith(word) || nodeSearchableText.endsWith(` ${word}`)) {
          nodeScore += 20
          nodeMatches.push(`word: ${word}`)
        }
        // Partial word match
        else if (nodeSearchableText.includes(word)) {
          nodeScore += 10
          nodeMatches.push(`partial: ${word}`)
        }
      })
      
      // Node type matching
      if (node.type) {
        const typeWords = node.type.toLowerCase()
        if (queryWords.some(qw => typeWords.includes(qw) || qw.includes(typeWords) || qw === 'repository' || qw === 'workflow' || qw === 'action')) {
          nodeScore += 30
          nodeMatches.push('type match')
        }
      }
      
      // Repository/owner matching
      if (nodeMetadata.owner && queryWords.some(qw => nodeMetadata.owner.toLowerCase().includes(qw))) {
        nodeScore += 25
        nodeMatches.push('owner match')
      }
      
      if (nodeMetadata.repo && queryWords.some(qw => nodeMetadata.repo.toLowerCase().includes(qw))) {
        nodeScore += 25
        nodeMatches.push('repo match')
      }
      
      // Natural language patterns for assets
      const assetPatterns = {
        'repository': ['repository', 'repo', 'project', 'codebase'],
        'workflow': ['workflow', 'ci', 'cd', 'pipeline', 'automation'],
        'action': ['action', 'github action', 'workflow action', 'plugin'],
      }
      
      Object.entries(assetPatterns).forEach(([key, patterns]) => {
        if (queryWords.some(qw => patterns.some(p => qw.includes(p) || p.includes(qw)))) {
          if (node.type === key) {
            nodeScore += 20
            nodeMatches.push(`asset pattern: ${key}`)
          }
        }
      })
      
      if (nodeScore > 0) {
        results.push({
          type: 'asset',
          node,
          score: nodeScore,
          matches: nodeMatches,
          searchableText: nodeSearchableText,
        })
      }
    })
    
    // Sort by score (highest first)
    results.sort((a, b) => b.score - a.score)
    
    return results
  }, [])

  // Memoize search results
  const searchResults = useMemo(() => {
    if (!searchQuery.trim() || !graphData) {
      return []
    }
    return searchIssues(searchQuery, graphData)
  }, [searchQuery, graphData, searchIssues])

  const handleResultClick = (result) => {
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

  const handleViewAll = () => {
    if (onViewAll && searchQuery.trim()) {
      onViewAll(searchQuery, searchResults)
      onClose()
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
    <div className="search-overlay" onClick={onClose}>
      <div className="search-overlay-content" onClick={(e) => e.stopPropagation()}>
        <div className="search-input-container">
          <svg 
            className="search-icon" 
            width="20" 
            height="20" 
            viewBox="0 0 20 20" 
            fill="none" 
            xmlns="http://www.w3.org/2000/svg"
          >
            <path 
              d="M9 3.5a5.5 5.5 0 1 0 0 11 5.5 5.5 0 0 0 0-11zM2 9a7 7 0 1 1 12.452 4.391l3.328 3.329a.75.75 0 1 1-1.06 1.06l-3.329-3.328A7 7 0 0 1 2 9z" 
              fill="currentColor"
            />
          </svg>
          <input
            ref={inputRef}
            type="text"
            className="search-overlay-input"
            placeholder="Search issues and assets... (e.g., 'unpinned actions', 'secrets', 'actions/checkout', 'workflows')"
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            onKeyDown={(e) => {
              if (e.key === 'Enter' && searchResults.length > 0) {
                handleResultClick(searchResults[0])
              }
              if (e.key === 'Escape') {
                onClose()
              }
            }}
          />
          {searchQuery && (
            <div className="search-shortcut-hint">
              <kbd>Esc</kbd> to close
            </div>
          )}
        </div>
        
        {searchQuery.trim() && (
          <div className="search-results-container">
            {searchResults.length > 0 ? (
              <>
                <div className="search-results-list">
                  {searchResults.slice(0, 8).map((result, index) => (
                    <div
                      key={`${result.type}-${result.node.id}-${result.issue?.type || 'asset'}-${index}`}
                      className="search-result-item"
                      onClick={() => handleResultClick(result)}
                    >
                      <div className="search-result-left">
                        {result.type === 'issue' ? (
                          <>
                            <span 
                              className="severity-badge"
                              style={{ backgroundColor: getSeverityColor(result.issue.severity) }}
                            >
                              {result.issue.severity?.toUpperCase() || 'UNKNOWN'}
                            </span>
                            <div className="search-result-content">
                              <div className="search-result-type">{result.issue.type || 'Unknown'}</div>
                              <div className="search-result-message">
                                {highlightMatch(result.issue.message || 'No message', searchQuery)}
                              </div>
                              <div className="search-result-node">
                                <span className="search-result-node-label">{result.node.label || result.node.id}</span>
                                <span className="search-result-node-type">{result.node.type}</span>
                              </div>
                            </div>
                          </>
                        ) : (
                          <>
                            <span className={`asset-badge asset-badge-${result.node.type || 'asset'}`}>
                              {result.node.type === 'repository' ? '📦' : result.node.type === 'workflow' ? '⚙️' : '🔧'}
                            </span>
                            <div className="search-result-content">
                              <div className="search-result-asset-type">{result.node.type || 'Asset'}</div>
                              <div className="search-result-message">
                                {highlightMatch(result.node.label || result.node.id, searchQuery)}
                              </div>
                              {result.node.metadata && (result.node.metadata.owner || result.node.metadata.repo) && (
                                <div className="search-result-node">
                                  <span className="search-result-node-label">
                                    {result.node.metadata.owner && result.node.metadata.repo 
                                      ? `${result.node.metadata.owner}/${result.node.metadata.repo}`
                                      : result.node.metadata.owner || result.node.metadata.repo}
                                  </span>
                                  {result.node.metadata.path && (
                                    <span className="search-result-node-type">{result.node.metadata.path}</span>
                                  )}
                                </div>
                              )}
                              {result.node.issues && result.node.issues.length > 0 && (
                                <div className="search-result-issue-count">
                                  {result.node.issues.length} issue{result.node.issues.length !== 1 ? 's' : ''}
                                </div>
                              )}
                            </div>
                          </>
                        )}
                      </div>
                      <div className="search-result-shortcut">
                        <kbd>↵</kbd>
                      </div>
                    </div>
                  ))}
                </div>
                {searchResults.length > 8 && (
                  <div className="search-view-all" onClick={handleViewAll}>
                    <span>View all {searchResults.length} results</span>
                    <kbd>⌘K</kbd>
                  </div>
                )}
              </>
            ) : (
              <div className="search-empty">
                <div className="search-empty-icon">🔍</div>
              <div className="search-empty-text">No results found</div>
              <div className="search-empty-hint">
                Try searching for:
                <ul>
                  <li>Issues: "unpinned", "secret", "permission", "critical"</li>
                  <li>Assets: "actions/checkout", "workflow", "repository", node names</li>
                </ul>
              </div>
              </div>
            )}
          </div>
        )}
        
        {!searchQuery.trim() && (
            <div className="search-placeholder">
              <div className="search-placeholder-icon">🔍</div>
              <div className="search-placeholder-text">Search security issues and assets...</div>
              <div className="search-placeholder-hints">
                <div className="search-hint-item">
                  <kbd>⌘K</kbd> or <kbd>Ctrl+K</kbd> to open search
                </div>
                <div className="search-hint-item">
                  <kbd>Esc</kbd> to close
                </div>
              </div>
            </div>
        )}
      </div>
    </div>
  )
}

export default SearchOverlay

