import React, { useState, useEffect, useCallback, useRef } from 'react'
import InputForm from './components/InputForm'
import ActionGraph from './components/ActionGraph'
import Statistics from './components/Statistics'
import NodeDetailsPanel from './components/NodeDetailsPanel'
import AnalysisHistory from './components/AnalysisHistory'
import TransitiveDependenciesTable from './components/TransitiveDependenciesTable'
import NodesTable from './components/NodesTable'
import IssuesTable from './components/IssuesTable'
import SearchOverlay from './components/SearchOverlay'
import SearchResultsPage from './components/SearchResultsPage'
import './App.css'

function App() {
  const [graphData, setGraphData] = useState(null)
  const [statistics, setStatistics] = useState(null)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState(null)
  const [selectedNode, setSelectedNode] = useState(null)
  const [graphFilter, setGraphFilter] = useState(null)
  const [viewMode, setViewMode] = useState('graph')
  const [shareMode, setShareMode] = useState(false)
  const [repositoryAuditStatus, setRepositoryAuditStatus] = useState(null)
  const [showSearchOverlay, setShowSearchOverlay] = useState(false)
  const [showSearchResults, setShowSearchResults] = useState(false)
  const [searchQuery, setSearchQuery] = useState('')
  const [searchResults, setSearchResults] = useState([])
  const inputFormRef = useRef(null)

  // Debug: Log when component mounts
  useEffect(() => {
    console.log('App component mounted')
  }, [])

  // Handle Cmd+K / Ctrl+K keyboard shortcut
  useEffect(() => {
    const handleKeyDown = (e) => {
      // Cmd+K on Mac, Ctrl+K on Windows/Linux
      if ((e.metaKey || e.ctrlKey) && e.key === 'k') {
        e.preventDefault()
        if (graphData) {
          setShowSearchOverlay(true)
        }
      }
    }

    window.addEventListener('keydown', handleKeyDown)
    return () => window.removeEventListener('keydown', handleKeyDown)
  }, [graphData])

  // Reset application state
  const handleReset = () => {
    setGraphData(null)
    setStatistics(null)
    setError(null)
    setSelectedNode(null)
    setGraphFilter(null)
    setViewMode('graph')
    setShareMode(false)
    setRepositoryAuditStatus(null)
    // Clear input form
    if (inputFormRef.current) {
      inputFormRef.current.setRepository('')
    }
  }

  // Check if repository is audited
  const checkRepositoryAudited = useCallback(async (repository) => {
    // First check: if graphData exists and contains nodes from that repository
    if (graphData?.nodes) {
      const hasRepoNodes = graphData.nodes.some(node => {
        if (node.type === 'repository') {
          return node.id === repository
        } else if (node.type === 'workflow' && node.id.includes(':')) {
          return node.id.split(':')[0] === repository
        } else if (node.type === 'action') {
          const metadata = node.metadata || {}
          if (metadata.owner && metadata.repo) {
            return `${metadata.owner}/${metadata.repo}` === repository
          }
          if (node.id.includes('@')) {
            return node.id.split('@')[0] === repository
          }
        }
        return false
      })
      
      if (hasRepoNodes) {
        return { isAudited: true }
      }
    }
    
    // Second check: query API for saved analyses
    try {
      const response = await fetch(`/api/analyses?repository=${encodeURIComponent(repository)}`)
      if (response.ok) {
        const analyses = await response.json()
        if (analyses && analyses.length > 0) {
          // Return the most recent analysis
          return { isAudited: true, analysisId: analyses[0].id }
        }
      }
    } catch (error) {
      console.error('Error checking repository audit status:', error)
    }
    
    return { isAudited: false }
  }, [graphData])

  // Handle share link parsing (only on mount)
  useEffect(() => {
    const urlParams = new URLSearchParams(window.location.search)
    const shareParam = urlParams.get('share')
    
    if (shareParam) {
      const parseShareLink = async () => {
        try {
          // Decode base64
          const decoded = atob(shareParam)
          const payload = JSON.parse(decoded)
          
          const { repository, scannedRepository, node: nodeData } = payload
          
          // Check if repository is audited (will use current graphData if available)
          const status = await checkRepositoryAudited(repository)
          setRepositoryAuditStatus(status)
          
          // Construct node object for NodeDetailsPanel
          const shareNode = {
            id: nodeData.id,
            data: {
              nodeLabel: nodeData.label,
              type: nodeData.type,
              nodeType: nodeData.type,
              issues: nodeData.issues || [],
              metadata: nodeData.metadata || {},
              originalId: nodeData.id,
              scannedRepository: scannedRepository, // Store scannedRepository from share link
            }
          }
          
          setSelectedNode(shareNode)
          setShareMode(true)
          
          // Clean up URL
          const url = new URL(window.location)
          url.searchParams.delete('share')
          window.history.replaceState({}, '', url)
        } catch (error) {
          console.error('Error parsing share link:', error)
        }
      }
      
      parseShareLink()
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []) // Only run once on mount

  // Handle scanning repository from share mode
  const handleShareScanRepository = async (repository) => {
    setLoading(true)
    setError(null)
    
    try {
      const response = await fetch('/api/audit', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({ repository }),
      })
      
      if (!response.ok) {
        let errorMessage = 'Failed to audit'
        try {
          const errorData = await response.json()
          errorMessage = errorData.detail || errorData.message || errorMessage
        } catch (e) {
          errorMessage = response.statusText || errorMessage
        }
        throw new Error(errorMessage)
      }
      
      const result = await response.json()
      setGraphData(result.graph)
      setStatistics(result.statistics)
      setShareMode(false)
      setRepositoryAuditStatus({ isAudited: true })
      
      // Find the shared node in the new graphData
      if (selectedNode) {
        const nodeId = selectedNode.id
        const foundNode = result.graph.nodes.find(n => n.id === nodeId)
        if (foundNode) {
          setSelectedNode({
            id: foundNode.id,
            data: {
              nodeLabel: foundNode.label,
              type: foundNode.type,
              nodeType: foundNode.type,
              issues: foundNode.issues || [],
              metadata: foundNode.metadata || {},
              originalId: foundNode.id,
            }
          })
        }
      }
      
      if (window.refreshAnalysisHistory) {
        window.refreshAnalysisHistory()
      }
    } catch (err) {
      setError(err.message)
    } finally {
      setLoading(false)
    }
  }

  // Handle viewing existing analysis from share mode
  const handleShareViewAnalysis = async (analysisId) => {
    try {
      const response = await fetch(`/api/analyses/${analysisId}`)
      if (response.ok) {
        const analysis = await response.json()
        setGraphData(analysis.graph)
        setStatistics(analysis.statistics)
        setShareMode(false)
        setViewMode('graph')
        
        // Find the shared node in the loaded graphData
        if (selectedNode) {
          const nodeId = selectedNode.id
          const foundNode = analysis.graph.nodes.find(n => n.id === nodeId)
          if (foundNode) {
            setSelectedNode({
              id: foundNode.id,
              data: {
                nodeLabel: foundNode.label,
                type: foundNode.type,
                nodeType: foundNode.type,
                issues: foundNode.issues || [],
                metadata: foundNode.metadata || {},
                originalId: foundNode.id,
              }
            })
          }
        }
      }
    } catch (error) {
      console.error('Error loading analysis:', error)
      setError('Failed to load analysis')
    }
  }

  const handleLoadAnalysis = (analysis) => {
    setGraphData(analysis.graph)
    setStatistics(analysis.statistics)
    setError(null)
    
    // Fill the input field with the repository/action name
    if (inputFormRef.current) {
      const repositoryName = analysis.repository || analysis.action || ''
      if (repositoryName) {
        inputFormRef.current.setRepository(repositoryName)
      }
    }
  }

  const handleAudit = async (data) => {
    setLoading(true)
    setError(null)
    
    try {
      // Use relative URL (works in both dev with proxy and production)
      const apiUrl = '/api/audit'
      const response = await fetch(apiUrl, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify(data),
      })
      
      if (!response.ok) {
        let errorMessage = 'Failed to audit'
        try {
          const errorData = await response.json()
          errorMessage = errorData.detail || errorData.message || errorMessage
        } catch (e) {
          // If response is not JSON, use status text
          errorMessage = response.statusText || errorMessage
        }
        
        // Provide helpful message for rate limit errors
        if (response.status === 403 && errorMessage.includes('rate limit')) {
          errorMessage = 'GitHub API rate limit exceeded. Please provide a GitHub Personal Access Token in the form to increase your rate limit from 60/hour to 5000/hour. You can create a token at https://github.com/settings/tokens'
        }
        
        throw new Error(errorMessage)
      }
      
      const result = await response.json()
      setGraphData(result.graph)
      setStatistics(result.statistics)
      setGraphFilter(null) // Reset filter on new analysis
      setViewMode('graph') // Reset to graph view
      
      // Refresh analysis history after new analysis
      if (window.refreshAnalysisHistory) {
        window.refreshAnalysisHistory()
      }
    } catch (err) {
      setError(err.message)
    } finally {
      setLoading(false)
    }
  }

  return (
    <div className="app">
      <div className="app-content">
        <div className="sidebar">
          <div className="sidebar-header">
            <h1 
              onClick={handleReset}
              style={{ cursor: 'pointer' }}
              title="Click to reset"
            >
              actsense
            </h1>
            <p>Analyze security issues in GitHub Actions and their dependencies</p>
            <a
              className="sidebar-doc-link"
              href="https://actsense.dev/vulnerabilities/"
              target="_blank"
              rel="noopener noreferrer"
            >
              <svg
                width="16"
                height="16"
                viewBox="0 0 24 24"
                fill="none"
                xmlns="http://www.w3.org/2000/svg"
                aria-hidden="true"
              >
                <path
                  d="M12 6c0-1.1-.9-2-2-2H4a2 2 0 0 0-2 2v12a.5.5 0 0 0 .8.4c.7-.52 1.56-.84 2.5-.84h4.7a2 2 0 0 1 2 2V6Zm0 0c0-1.1.9-2 2-2h6a2 2 0 0 1 2 2v12a.5.5 0 0 1-.8.4 4 4 0 0 0-2.5-.84H14a2 2 0 0 0-2 2V6Z"
                  stroke="currentColor"
                  strokeWidth="1.5"
                  strokeLinecap="round"
                  strokeLinejoin="round"
                />
              </svg>
              <span>Docs</span>
            </a>
          </div>
          <InputForm ref={inputFormRef} onAudit={handleAudit} loading={loading} />
          {statistics && (
            <Statistics 
              data={statistics} 
              onFilterChange={setGraphFilter}
              onViewModeChange={setViewMode}
              currentViewMode={viewMode}
              currentFilter={graphFilter}
            />
          )}
          {error && (
            <div className="error-message">
              <strong>Error:</strong> {error}
            </div>
          )}
          <AnalysisHistory onLoadAnalysis={handleLoadAnalysis} />
        </div>
        
        {showSearchResults ? (
          <SearchResultsPage
            searchQuery={searchQuery}
            searchResults={searchResults}
            graphData={graphData}
            onNodeSelect={(node) => {
              setSelectedNode(node)
              setShowSearchResults(false)
            }}
            onClose={() => setShowSearchResults(false)}
          />
        ) : (
          <div className="main-content">
            {graphData && (
              <button
                className="floating-search-button"
                onClick={() => setShowSearchOverlay(true)}
                title="Search issues and assets (⌘K or Ctrl+K)"
                aria-label="Search"
              >
                <svg 
                  width="18" 
                  height="18" 
                  viewBox="0 0 16 16" 
                  fill="none" 
                  xmlns="http://www.w3.org/2000/svg"
                >
                  <path 
                    d="M11.5 10h-.79l-.28-.27C11.41 8.59 12 7.11 12 5.5 12 2.46 9.54 0 6.5 0S1 2.46 1 5.5 3.46 11 6.5 11c1.61 0 3.09-.59 4.23-1.57l.27.28v.79l5 4.99L16.49 15l-4.99-5zm-5 0C4.01 10 2 7.99 2 5.5S4.01 1 6.5 1 11 3.01 11 5.5 8.99 10 6.5 10z" 
                    fill="currentColor"
                  />
                </svg>
                <span>Search</span>
                <kbd>{navigator.platform.toUpperCase().indexOf('MAC') >= 0 ? '⌘K' : 'Ctrl+K'}</kbd>
              </button>
            )}
            {graphData ? (
              viewMode === 'graph' ? (
                <ActionGraph 
                  graphData={graphData} 
                  onNodeSelect={setSelectedNode}
                  filter={graphFilter}
                  onClearFilter={() => setGraphFilter(null)}
                />
              ) : (
                // Table view: show different tables based on filter
                graphFilter?.type === 'has_dependencies' ? (
                  <TransitiveDependenciesTable 
                    graphData={graphData}
                    onNodeSelect={setSelectedNode}
                    filter={graphFilter}
                  />
                ) : graphFilter?.type === 'has_issues' ? (
                  <IssuesTable 
                    graphData={graphData}
                    onNodeSelect={setSelectedNode}
                    filter={graphFilter}
                  />
                ) : (
                  <NodesTable 
                    graphData={graphData}
                    onNodeSelect={setSelectedNode}
                    filter={graphFilter}
                  />
                )
              )
            ) : (
              <div className="empty-state">
                <h1 
                  className="logo-text"
                  onClick={handleReset}
                  style={{ cursor: 'pointer' }}
                  title="Click to reset"
                >
                  actsense
                </h1>
                <p>
                  Enter a repository (e.g., <code>owner/repo</code>) or action reference to begin auditing.<br />
                  We'll fetch its workflow graph, uncover risky actions, and surface mitigation steps.
                </p>
                {graphData && (
                  <div className="empty-state-hint">
                    <p className="hint-text">Tip: Press <kbd>{navigator.platform.toUpperCase().indexOf('MAC') >= 0 ? '⌘K' : 'Ctrl+K'}</kbd> to search issues and assets</p>
                  </div>
                )}
              </div>
            )}
          </div>
        )}
      </div>
      
      {selectedNode && (
        <NodeDetailsPanel 
          node={selectedNode}
          graphData={graphData}
          onClose={() => {
            setSelectedNode(null)
            setShareMode(false)
            setRepositoryAuditStatus(null)
          }}
          onNodeSelect={setSelectedNode}
          shareMode={shareMode}
          onScanRepository={handleShareScanRepository}
          onViewAnalysis={handleShareViewAnalysis}
          repositoryAuditStatus={repositoryAuditStatus}
          onStartAnalysis={(repository) => handleAudit({ repository })}
          setRepositoryInput={(value) => {
            if (inputFormRef.current) {
              inputFormRef.current.setRepository(value)
            }
          }}
        />
      )}

      {showSearchOverlay && graphData && (
        <SearchOverlay
          graphData={graphData}
          onClose={() => setShowSearchOverlay(false)}
          onNodeSelect={(node) => {
            setSelectedNode(node)
            setShowSearchOverlay(false)
          }}
          onViewAll={(query, results) => {
            setSearchQuery(query)
            setSearchResults(results)
            setShowSearchOverlay(false)
            setShowSearchResults(true)
          }}
        />
      )}

    </div>
  )
}

export default App

