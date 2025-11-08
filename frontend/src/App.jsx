import React, { useState, useEffect } from 'react'
import InputForm from './components/InputForm'
import ActionGraph from './components/ActionGraph'
import Statistics from './components/Statistics'
import NodeDetailsPanel from './components/NodeDetailsPanel'
import AnalysisHistory from './components/AnalysisHistory'
import TransitiveDependenciesTable from './components/TransitiveDependenciesTable'
import NodesTable from './components/NodesTable'
import './App.css'

function App() {
  const [graphData, setGraphData] = useState(null)
  const [statistics, setStatistics] = useState(null)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState(null)
  const [selectedNode, setSelectedNode] = useState(null)
  const [graphFilter, setGraphFilter] = useState(null)
  const [viewMode, setViewMode] = useState('graph')

  // Debug: Log when component mounts
  useEffect(() => {
    console.log('App component mounted')
  }, [])

  const handleLoadAnalysis = (analysis) => {
    setGraphData(analysis.graph)
    setStatistics(analysis.statistics)
    setError(null)
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
            <h1>actsense</h1>
            <p>Analyze security issues in GitHub Actions and their dependencies</p>
          </div>
          <InputForm onAudit={handleAudit} loading={loading} />
          {statistics && (
            <Statistics 
              data={statistics} 
              onFilterChange={setGraphFilter}
              onViewModeChange={setViewMode}
              currentViewMode={viewMode}
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
              <p>Enter a repository (e.g., <code>owner/repo</code>) or action reference to begin auditing</p>
            </div>
          )}
        </div>
      </div>
      
      {selectedNode && (
        <NodeDetailsPanel 
          node={selectedNode} 
          onClose={() => setSelectedNode(null)} 
        />
      )}
    </div>
  )
}

export default App

