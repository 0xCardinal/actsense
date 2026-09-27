import React, { useState, useEffect, useCallback, useRef } from 'react'
import { flushSync } from 'react-dom'
import InputForm from './components/InputForm'
import ActionGraph from './components/ActionGraph'
import Statistics from './components/Statistics'
import NodeDetailsPanel from './components/NodeDetailsPanel'
import AnalysisHistory from './components/AnalysisHistory'
import TransitiveDependenciesTable from './components/TransitiveDependenciesTable'
import NodesTable from './components/NodesTable'
import IssuesTable from './components/IssuesTable'
import IssueDetailsModal from './components/IssueDetailsModal'
import SearchOverlay from './components/SearchOverlay'
import SearchResultsPage from './components/SearchResultsPage'
import YAMLEditorPanel from './components/YAMLEditorPanel'
import HomeBackdrop from './components/HomeBackdrop'
import './App.css'

function App() {
  const [graphData, setGraphData] = useState(null)
  const [statistics, setStatistics] = useState(null)
  const [loading, setLoading] = useState(false)
  const [loadingStage, setLoadingStage] = useState('')
  const [loadingLogs, setLoadingLogs] = useState([])
  const [showLogs, setShowLogs] = useState(false)
  const [error, setError] = useState(null)
  const [selectedNode, setSelectedNode] = useState(null)
  const [selectedIssue, setSelectedIssue] = useState(null)
  const [graphFilter, setGraphFilter] = useState(null)
  const [viewMode, setViewMode] = useState('graph')
  const [shareMode, setShareMode] = useState(false)
  const [repositoryAuditStatus, setRepositoryAuditStatus] = useState(null)
  const [showSearchOverlay, setShowSearchOverlay] = useState(false)
  const [showSearchResults, setShowSearchResults] = useState(false)
  const [searchQuery, setSearchQuery] = useState('')
  const [searchResults, setSearchResults] = useState([])
  const [showYAMLEditor, setShowYAMLEditor] = useState(false)
  const [savedYAMLContent, setSavedYAMLContent] = useState(null)
  const [auditTarget, setAuditTarget] = useState('')
  const [elapsed, setElapsed] = useState(0)
  const inputFormRef = useRef(null)
  // Form values survive the home <-> workspace switch (the form remounts).
  const formValuesRef = useRef({ input: '', token: '', useClone: false })
  const handleFormValues = useCallback((values) => { formValuesRef.current = values }, [])
  const setFormInput = useCallback((value) => {
    formValuesRef.current = { ...formValuesRef.current, input: value }
    inputFormRef.current?.setRepository(value)
  }, [])
  const auditAbortRef = useRef(null)
  const logsEndRef = useRef(null)

  useEffect(() => {
    if (!loading) {
      setElapsed(0)
      return undefined
    }
    const started = Date.now()
    const timer = setInterval(() => setElapsed(Math.floor((Date.now() - started) / 1000)), 1000)
    return () => clearInterval(timer)
  }, [loading])

  const isMac = typeof navigator !== 'undefined' && /mac/i.test(navigator.platform)

  // First run shows a single search box; anything else is the workspace.
  const isHome = !graphData && !loading && !showSearchResults

  // Morph between the home and workspace layouts with the View Transitions
  // API where available; elsewhere (or with reduced motion) switch instantly.
  const runLayoutTransition = useCallback((update) => {
    const reduce = window.matchMedia?.('(prefers-reduced-motion: reduce)').matches
    if (!document.startViewTransition || reduce) {
      update()
      return
    }
    document.startViewTransition(() => flushSync(update))
  }, [])

  useEffect(() => {
    if (logsEndRef.current) {
      logsEndRef.current.scrollIntoView({ behavior: 'smooth' })
    }
  }, [loadingLogs])

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
  const handleReset = () => runLayoutTransition(() => {
    setGraphData(null)
    setStatistics(null)
    setError(null)
    setSelectedNode(null)
    setSelectedIssue(null)
    setGraphFilter(null)
    setViewMode('graph')
    setShareMode(false)
    setRepositoryAuditStatus(null)
    setFormInput('')
  })

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

  const findOtherIssueInstances = useCallback((issue) => {
    if (!graphData?.nodes || !issue?.type) {
      return []
    }

    return graphData.nodes.flatMap(node => {
      if (node.id === issue.nodeId) {
        return []
      }

      return (node.issues || [])
        .filter(nodeIssue => nodeIssue.type === issue.type)
        .map(nodeIssue => ({
          ...nodeIssue,
          nodeLabel: node.label,
          id: node.id,
        }))
    })
  }, [graphData])

  const handleIssueSelect = useCallback((issue) => {
    setSelectedNode(null)
    setSelectedIssue({
      ...issue,
      otherInstances: findOtherIssueInstances(issue),
    })
  }, [findOtherIssueInstances])

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

  const handleLoadAnalysis = (analysis) => runLayoutTransition(() => {
    setGraphData(analysis.graph)
    setStatistics(analysis.statistics)
    setError(null)
    // A filter or selection from the previous analysis refers to nodes that
    // may not exist in this one.
    setGraphFilter(null)
    setViewMode('graph')
    setSelectedNode(null)
    setSelectedIssue(null)
    
    const repositoryName = analysis.repository || analysis.action || ''
    if (repositoryName) {
      setFormInput(repositoryName)
    }
  })

  const handleAudit = async (data) => {
    if (auditAbortRef.current) {
      auditAbortRef.current.abort()
    }
    const controller = new AbortController()
    auditAbortRef.current = controller

    runLayoutTransition(() => {
      setLoading(true)
      setError(null)
      setAuditTarget(data.repository || data.action || '')
      setLoadingLogs([])
      setLoadingStage('Connecting…')
    })
    let receivedResult = false

    const addLog = (text) => {
      setLoadingLogs(prev => [...prev, { time: new Date(), text }])
    }

    try {
      const response = await fetch('/api/audit/stream', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(data),
        signal: controller.signal,
      })

      if (!response.ok) {
        let errorMessage = 'Failed to audit'
        try {
          const errorData = await response.json()
          errorMessage = errorData.detail || errorData.message || errorMessage
        } catch (e) {
          errorMessage = response.statusText || errorMessage
        }
        if (response.status === 403 && errorMessage.includes('rate limit')) {
          errorMessage = 'GitHub API rate limit exceeded. Please provide a GitHub Personal Access Token in the form to increase your rate limit from 60/hour to 5000/hour. You can create a token at https://github.com/settings/tokens'
        }
        throw new Error(errorMessage)
      }

      const reader = response.body.getReader()
      const decoder = new TextDecoder()
      let buffer = ''
      let eventType = null

      while (true) {
        const { done, value } = await reader.read()
        if (done) break
        buffer += decoder.decode(value, { stream: true })

        const parts = buffer.split('\n')
        buffer = parts.pop() || ''

        for (const line of parts) {
          if (line.startsWith('event: ')) {
            eventType = line.slice(7).trim()
          } else if (line.startsWith('data: ') && eventType) {
            try {
              const parsed = JSON.parse(line.slice(6))
              if (eventType === 'log') {
                const msg = parsed.message || ''
                addLog(msg)
                if (!msg.startsWith('  ')) {
                  setLoadingStage(msg)
                }
              } else if (eventType === 'result') {
                receivedResult = true
                setSelectedNode(null)
                setSelectedIssue(null)
                setGraphData(parsed.graph)
                setStatistics(parsed.statistics)
                setGraphFilter(null)
                setViewMode('graph')
                addLog('Audit complete')
                if (window.refreshAnalysisHistory) {
                  window.refreshAnalysisHistory()
                }
              } else if (eventType === 'error') {
                receivedResult = true
                throw new Error(parsed.detail || 'Audit failed')
              }
            } catch (parseErr) {
              if (parseErr instanceof SyntaxError) continue
              throw parseErr
            }
            eventType = null
          } else if (line.trim() === '') {
            eventType = null
          }
        }
      }
      if (!receivedResult) {
        throw new Error('The connection to the server closed before the audit finished. Check the server logs and try again.')
      }
    } catch (err) {
      if (err.name === 'AbortError') return
      setError(err.message)
    } finally {
      if (!controller.signal.aborted) {
        setLoading(false)
        setLoadingStage('')
        setLoadingLogs([])
        setShowLogs(false)
      }
    }
  }

  return (
    <div className={`app ${isHome ? 'app--home' : ''}`}>
      {isHome ? (
        <main className="home">
          <HomeBackdrop />
          <div className="home-center">
            <h1 className="home-brand" onClick={handleReset}>actsense</h1>
            <p className="home-eyebrow">Workflow Security Auditor</p>
            <p className="home-tagline">Map every dependency your CI workflows run and audit each one.</p>
            <div className="home-card">
              <InputForm
                ref={inputFormRef}
                variant="hero"
                onAudit={handleAudit}
                loading={loading}
                onOpenYAMLEditor={() => setShowYAMLEditor(true)}
                defaults={formValuesRef.current}
                onValuesChange={handleFormValues}
              />
            </div>
            {error && (
              <div className="error-message home-error" role="alert">
                <svg width="16" height="16" viewBox="0 0 16 16" fill="none" aria-hidden="true">
                  <circle cx="8" cy="8" r="6.5" stroke="currentColor" strokeWidth="1.5" />
                  <path d="M8 4.75v3.75M8 11h.01" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" />
                </svg>
                <div>
                  <strong>Audit failed</strong>
                  {error}
                </div>
                <button className="error-dismiss" onClick={() => setError(null)} aria-label="Dismiss error">×</button>
              </div>
            )}
            <div className="home-platform" title="Other workflow platforms are planned">
              <svg width="14" height="14" viewBox="0 0 16 16" fill="currentColor" aria-hidden="true"><path d="M8 0C3.58 0 0 3.58 0 8c0 3.54 2.29 6.53 5.47 7.59.4.07.55-.17.55-.38 0-.19-.01-.82-.01-1.49-2.01.37-2.53-.49-2.69-.94-.09-.23-.48-.94-.82-1.13-.28-.15-.68-.52-.01-.53.63-.01 1.08.58 1.23.82.72 1.21 1.87.87 2.33.66.07-.52.28-.87.51-1.07-1.78-.2-3.64-.89-3.64-3.95 0-.87.31-1.59.82-2.15-.08-.2-.36-1.02.08-2.12 0 0 .67-.21 2.2.82.64-.18 1.32-.27 2-.27.68 0 1.36.09 2 .27 1.53-1.04 2.2-.82 2.2-.82.44 1.1.16 1.92.08 2.12.51.56.82 1.27.82 2.15 0 3.07-1.87 3.75-3.65 3.95.29.25.54.73.54 1.48 0 1.07-.01 1.93-.01 2.2 0 .21.15.46.55.38A8.013 8.013 0 0016 8c0-4.42-3.58-8-8-8z"/></svg>
              Works with <strong>GitHub Actions</strong>
            </div>
            <div className="home-examples">
              <span className="home-examples-label">Try</span>
              {['actions/checkout@v4', 'astral-sh/ruff', 'sigstore/cosign'].map(example => (
                <button
                  key={example}
                  type="button"
                  className="example-chip"
                  onClick={() => {
                    setFormInput(example)
                    const token = formValuesRef.current.token || undefined
                    handleAudit(example.includes('@')
                      ? { action: example, github_token: token }
                      : { repository: example, github_token: token })
                  }}
                >
                  {example}
                </button>
              ))}
            </div>
          </div>
          <footer className="home-footer">
            <a
              className="sidebar-doc-link home-link"
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
            <div className="home-history">
              <AnalysisHistory onLoadAnalysis={handleLoadAnalysis} popover />
            </div>
          </footer>
        </main>
      ) : (
      <div className="app-content">
        <aside className="sidebar" aria-label="Audit controls">
          <header className="sidebar-header">
            <h1 onClick={handleReset} title="Start over">actsense</h1>
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
          </header>

          <div className="sidebar-body">
            <section className="sidebar-section" aria-labelledby="new-audit-heading">
              <h2 id="new-audit-heading" className="sidebar-section-title">New audit</h2>
              <InputForm
                ref={inputFormRef}
                onAudit={handleAudit}
                loading={loading}
                onOpenYAMLEditor={() => setShowYAMLEditor(true)}
                defaults={formValuesRef.current}
                onValuesChange={handleFormValues}
              />
              {error && (
                <div className="error-message" role="alert">
                  <svg width="16" height="16" viewBox="0 0 16 16" fill="none" aria-hidden="true">
                    <circle cx="8" cy="8" r="6.5" stroke="currentColor" strokeWidth="1.5" />
                    <path d="M8 4.75v3.75M8 11h.01" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" />
                  </svg>
                  <div>
                    <strong>Audit failed</strong>
                    {error}
                  </div>
                  <button className="error-dismiss" onClick={() => setError(null)} aria-label="Dismiss error">×</button>
                </div>
              )}
            </section>

            {statistics && (
              <section className="sidebar-section sidebar-section-results" aria-label="Results">
                <Statistics
                  data={statistics}
                  onFilterChange={setGraphFilter}
                  onViewModeChange={setViewMode}
                  currentViewMode={viewMode}
                  currentFilter={graphFilter}
                />
              </section>
            )}
          </div>

          <footer className="sidebar-footer">
            <AnalysisHistory onLoadAnalysis={handleLoadAnalysis} />
          </footer>
        </aside>
        
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
            {graphData && viewMode === 'graph' && (
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
                <span>Search issues and nodes</span>
                <kbd>{isMac ? '⌘K' : 'Ctrl K'}</kbd>
              </button>
            )}
            {loading && (
              <div className="audit-loading-overlay">
                <div className="audit-loading-card" role="status" aria-live="polite">
                  <div className="audit-loading-head">
                    <div className="audit-loading-spinner" />
                    <div style={{ minWidth: 0 }}>
                      <div className="audit-loading-title">Auditing {auditTarget || 'workflow'}</div>
                      <div className="audit-loading-stage">{loadingStage || 'Working…'}</div>
                    </div>
                    <div className="audit-loading-meta">
                      {elapsed}s · {loadingLogs.length} steps
                    </div>
                  </div>
                  <div className="audit-loading-bar-track">
                    <div className="audit-loading-bar-fill" />
                  </div>
                  <div className="audit-loading-actions">
                    <button
                      className="audit-loading-toggle"
                      onClick={() => setShowLogs(prev => !prev)}
                      aria-expanded={showLogs}
                    >
                      <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" style={{ transform: showLogs ? 'rotate(180deg)' : 'none', transition: 'transform 0.2s' }}>
                        <polyline points="6 9 12 15 18 9" />
                      </svg>
                      {showLogs ? 'Hide log' : 'Show log'}
                    </button>
                    {auditAbortRef.current && (
                      <button
                        className="audit-cancel"
                        onClick={() => {
                          auditAbortRef.current?.abort()
                          setLoading(false)
                          setLoadingStage('')
                          setLoadingLogs([])
                        }}
                      >
                        Cancel
                      </button>
                    )}
                  </div>
                  {showLogs && (
                    <div className="audit-loading-logs">
                      {loadingLogs.map((log, i) => (
                        <div key={i} className="audit-log-line">
                          <span className="audit-log-time">
                            {log.time.toLocaleTimeString('en-US', { hour12: false, hour: '2-digit', minute: '2-digit', second: '2-digit' })}
                          </span>
                          <span className="audit-log-text">{log.text}</span>
                        </div>
                      ))}
                      <div ref={logsEndRef} />
                    </div>
                  )}
                </div>
              </div>
            )}
            {graphData ? (
              viewMode === 'graph' ? (
                <ActionGraph 
                  graphData={graphData} 
                  onNodeSelect={setSelectedNode}
                  filter={graphFilter}
                  onClearFilter={() => setGraphFilter(null)}
                  selectedNodeId={selectedNode?.id}
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
                    onIssueSelect={handleIssueSelect}
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
                  title="Start over"
                >
                  actsense
                </h1>
                <p>
                  Enter a repository (<code>owner/repo</code>) or an action reference (<code>owner/repo@ref</code>).
                  actsense maps every workflow, action, reusable workflow and image it depends on, then checks each one.
                </p>
                <div className="empty-state-examples">
                  {['actions/checkout@v4', 'astral-sh/ruff', 'sigstore/cosign'].map(example => (
                    <button
                      key={example}
                      className="example-chip"
                      disabled={loading}
                      onClick={() => {
                        inputFormRef.current?.setRepository(example)
                        handleAudit(example.includes('@')
                          ? { action: example, github_token: inputFormRef.current?.getToken?.() || undefined }
                          : { repository: example, github_token: inputFormRef.current?.getToken?.() || undefined })
                      }}
                    >
                      {example}
                    </button>
                  ))}
                </div>
              </div>
            )}
          </div>
        )}
      </div>
      )}

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

      {selectedIssue && (
        <IssueDetailsModal
          issue={selectedIssue}
          otherInstances={selectedIssue.otherInstances || []}
          onClose={() => setSelectedIssue(null)}
        />
      )}

      {showSearchOverlay && graphData && (
        <SearchOverlay
          graphData={graphData}
          onClose={() => setShowSearchOverlay(false)}
          onNodeSelect={(node) => {
            setSelectedIssue(null)
            setSelectedNode(node)
            setShowSearchOverlay(false)
          }}
          onIssueSelect={handleIssueSelect}
          onViewAll={(query, results) => {
            setSearchQuery(query)
            setSearchResults(results)
            setShowSearchOverlay(false)
            setShowSearchResults(true)
          }}
        />
      )}

      {showYAMLEditor && (
        <YAMLEditorPanel
          onClose={() => setShowYAMLEditor(false)}
          onAnalyze={async (yamlContent, token) => {
            setLoading(true)
            // Don't set error in main app - errors should only show in editor panel
            
            try {
              const response = await fetch('/api/audit/yaml', {
                method: 'POST',
                headers: {
                  'Content-Type': 'application/json',
                },
                body: JSON.stringify({
                  yaml_content: yamlContent,
                  github_token: token || undefined,
                }),
              })
              
              if (!response.ok) {
                let errorData
                try {
                  errorData = await response.json()
                } catch {
                  errorData = { detail: `HTTP ${response.status}: ${response.statusText}` }
                }
                throw new Error(errorData.detail || errorData.message || 'Failed to analyze workflow')
              }
              
              const result = await response.json()
              setGraphData(result.graph)
              setStatistics(result.statistics)
              setGraphFilter(null)
              setViewMode('graph')
              
              // Save YAML content for future editing
              setSavedYAMLContent(yamlContent)
              
              // Close editor after successful analysis
              setShowYAMLEditor(false)
              
              // Refresh analysis history
              if (window.refreshAnalysisHistory) {
                window.refreshAnalysisHistory()
              }
            } catch (err) {
              // Re-throw error so YAMLEditorPanel can display it
              throw err
            } finally {
              setLoading(false)
            }
          }}
          githubToken={inputFormRef.current?.getToken?.() || ''}
          loading={loading}
          initialContent={savedYAMLContent || ''}
        />
      )}

    </div>
  )
}

export default App

