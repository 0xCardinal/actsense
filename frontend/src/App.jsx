import React, { useState, useEffect, useCallback, useRef } from 'react'
import InputForm from './components/InputForm'
import ActionGraph from './components/ActionGraph'
import Statistics from './components/Statistics'
import NodeDetailsPanel from './components/NodeDetailsPanel'
import AnalysisHistory from './components/AnalysisHistory'
import TransitiveDependenciesTable from './components/TransitiveDependenciesTable'
import NodesTable from './components/NodesTable'
import IssuesTable from './components/IssuesTable'
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
  const inputFormRef = useRef(null)

  // Debug: Log when component mounts
  useEffect(() => {
    console.log('App component mounted')
  }, [])

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
        
        <div className="main-content">
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
              <p>Enter a repository (e.g., <code>owner/repo</code>) or action reference to begin auditing</p>
            </div>
          )}
        </div>
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
    </div>
  )
}

export default App

