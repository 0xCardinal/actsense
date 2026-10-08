import React, { useState, useEffect, useCallback, useMemo, useRef } from 'react'
import { flushSync } from 'react-dom'
import InputForm from './components/InputForm'
import ThemeToggle from './components/ThemeToggle'
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
import OrgWorkspace from './components/OrgWorkspace'
import { DismissalContext, withoutDismissed } from './dismissals'
import './App.css'

// Keep ?org-scan=<id> in the address bar so a scan survives a reload and can be shared.
function setOrgScanParam(id) {
  const url = new URL(window.location.href)
  if (id) url.searchParams.set('org-scan', id)
  else url.searchParams.delete('org-scan')
  window.history.replaceState({}, '', url)
}

function App() {
  const [graphData, setGraphData] = useState(null)
  const [statistics, setStatistics] = useState(null)
  // Which stored analysis is on screen, and the repository or action it
  // audited (dismissals are remembered per target).
  const [analysisMeta, setAnalysisMeta] = useState(null)
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
  // Organization scans: the repository picker, the scan (live or stored),
  // and whether the org view or a single repository's graph is showing.
  const [orgPicker, setOrgPicker] = useState(null)
  const [orgScan, setOrgScan] = useState(null)
  const [orgRunning, setOrgRunning] = useState(false)
  const [orgProgress, setOrgProgress] = useState(null)
  const [orgView, setOrgView] = useState(false)
  const orgAbortRef = useRef(null)
  // The finding an org-level click came from, highlighted in the side panel.
  const [focusFingerprint, setFocusFingerprint] = useState(null)
  // Bumped when a finding is dismissed or restored, so org findings reload.
  const [orgFindingsVersion, setOrgFindingsVersion] = useState(0)
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

  const showAnalysis = useCallback((analysis) => {
    setGraphData(analysis?.graph || null)
    setStatistics(analysis?.statistics || null)
    setAnalysisMeta(analysis?.id
      ? { id: analysis.id, target: analysis.repository || analysis.action || null }
      : null)
  }, [])

  // Every view but the findings table works on active findings only.
  const visibleGraph = useMemo(() => withoutDismissed(graphData), [graphData])

  const isMac = typeof navigator !== 'undefined' && /mac/i.test(navigator.platform)

  // First run shows a single search box; anything else is the workspace.
  const isHome = !graphData && !loading && !showSearchResults && !orgView

  // Morph between the home and workspace layouts with the View Transitions
  // API where available; elsewhere (or with reduced motion) switch instantly.
  const runLayoutTransition = useCallback((update) => {
    const reduce = window.matchMedia?.('(prefers-reduced-motion: reduce)').matches
    if (!document.startViewTransition || reduce) {
      update()
      return
    }
    const transition = document.startViewTransition(() => flushSync(update))
    // The browser aborts a transition when, for example, the tab is hidden;
    // the update still applies, so only the animation is lost.
    transition.ready?.catch(() => {})
    transition.finished?.catch(() => {})
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
        if (graphData && !orgView) {
          setShowSearchOverlay(true)
        }
      }
    }

    window.addEventListener('keydown', handleKeyDown)
    return () => window.removeEventListener('keydown', handleKeyDown)
  }, [graphData, orgView])

  // Reset application state
  const handleReset = () => runLayoutTransition(() => {
    showAnalysis(null)
    setError(null)
    setSelectedNode(null)
    setSelectedIssue(null)
    setGraphFilter(null)
    setViewMode('graph')
    setShareMode(false)
    setRepositoryAuditStatus(null)
    setFormInput('')
    orgAbortRef.current?.abort()
    setOrgPicker(null)
    setOrgScan(null)
    setOrgRunning(false)
    setOrgProgress(null)
    setOrgView(false)
    setOrgScanParam(null)
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
    if (!visibleGraph?.nodes || !issue?.type) {
      return []
    }

    return visibleGraph.nodes.flatMap(node => {
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
  }, [visibleGraph])

  const handleIssueSelect = useCallback((issue) => {
    setSelectedNode(null)
    setSelectedIssue({
      ...issue,
      otherInstances: findOtherIssueInstances(issue),
    })
  }, [findOtherIssueInstances])

  // Open a stored org scan from an ?org-scan=<id> link (only on mount)
  useEffect(() => {
    const scanId = new URLSearchParams(window.location.search).get('org-scan')
    if (!scanId) return
    fetch(`/api/org-scans/${encodeURIComponent(scanId)}`)
      .then(r => (r.ok ? r.json() : Promise.reject(new Error('Org scan not found'))))
      .then(scan => {
        setOrgScan(scan)
        setOrgView(true)
        setFormInput(scan.org)
      })
      .catch(err => {
        setError(err.message)
        setOrgScanParam(null)
      })
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [])

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
      showAnalysis(result)
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
        showAnalysis(analysis)
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
    showAnalysis(analysis)
    setOrgView(false)
    setOrgScanParam(null)
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

  // Reload the stored org scan so its counts reflect current dismissals.
  const refreshOrgScan = useCallback(() => {
    if (!orgScan?.id) return
    fetch(`/api/org-scans/${encodeURIComponent(orgScan.id)}`)
      .then(r => (r.ok ? r.json() : null))
      .then(scan => { if (scan) setOrgScan(scan) })
      .catch(() => {})
  }, [orgScan?.id])

  // Dismiss or restore a finding. The server answers with the analysis as it
  // now reads, counts included.
  const updateDismissal = useCallback(async (request) => {
    const response = await fetch(`/api/analyses/${analysisMeta.id}/dismissals${request.path}`, {
      method: request.method,
      headers: { 'Content-Type': 'application/json' },
      body: request.body ? JSON.stringify(request.body) : undefined,
    })
    if (!response.ok) {
      let detail = 'Could not update the finding'
      try {
        detail = (await response.json()).detail || detail
      } catch {
        // keep the generic message
      }
      throw new Error(detail)
    }
    showAnalysis(await response.json())
    if (orgScan) {
      setOrgFindingsVersion(v => v + 1)
      refreshOrgScan()
    }
  }, [analysisMeta, showAnalysis, orgScan, refreshOrgScan])

  const dismissalActions = useMemo(() => ({
    canDismiss: Boolean(analysisMeta?.target) && !shareMode,
    dismiss: (issue, reason) => updateDismissal({
      method: 'POST',
      path: '',
      body: { fingerprint: issue.fingerprint, reason },
    }),
    restore: (issue) => updateDismissal({
      method: 'DELETE',
      path: `/${encodeURIComponent(issue.fingerprint)}`,
    }),
  }), [analysisMeta, shareMode, updateDismissal])

  const readErrorDetail = async (response, fallback) => {
    try {
      const body = await response.json()
      return body.detail || body.message || fallback
    } catch {
      return response.statusText || fallback
    }
  }

  // Read a Server-Sent Events response, calling onEvent(type, data) per event.
  const readEventStream = async (response, onEvent) => {
    const reader = response.body.getReader()
    const decoder = new TextDecoder()
    let buffer = ''
    let eventType = null
    while (true) {
      const { done, value } = await reader.read()
      if (done) break
      buffer += decoder.decode(value, { stream: true })
      const lines = buffer.split('\n')
      buffer = lines.pop() || ''
      for (const line of lines) {
        if (line.startsWith('event: ')) {
          eventType = line.slice(7).trim()
        } else if (line.startsWith('data: ') && eventType) {
          let parsed
          try {
            parsed = JSON.parse(line.slice(6))
          } catch {
            continue
          }
          onEvent(eventType, parsed)
          eventType = null
        } else if (line.trim() === '') {
          eventType = null
        }
      }
    }
  }

  // Load the repositories of an organization or user so some can be picked.
  const handleOrgLookup = async ({ org, github_token, use_clone }) => {
    orgAbortRef.current?.abort()
    runLayoutTransition(() => {
      setError(null)
      showAnalysis(null)
      setSelectedNode(null)
      setSelectedIssue(null)
      setOrgScan(null)
      setOrgProgress(null)
      setOrgView(true)
      setOrgPicker({ org, loading: true, token: github_token, useClone: use_clone })
    })
    setOrgScanParam(null)
    try {
      const response = await fetch(`/api/orgs/${encodeURIComponent(org)}/repos`, {
        headers: github_token ? { 'X-GitHub-Token': github_token } : {},
      })
      if (!response.ok) {
        throw new Error(await readErrorDetail(response, 'Failed to list repositories'))
      }
      const body = await response.json()
      setOrgPicker({
        org: body.org,
        repositories: body.repositories,
        maxSelectable: body.max_selectable,
        ownerType: body.owner_type,
        privateIncluded: body.private_included,
        token: github_token,
        useClone: use_clone,
      })
    } catch (err) {
      setOrgPicker({ org, error: err.message, token: github_token, useClone: use_clone })
    }
  }

  // Scan the chosen repositories, updating each row as it finishes.
  const handleOrgScan = async (repositories) => {
    const picker = orgPicker
    const controller = new AbortController()
    orgAbortRef.current = controller
    setOrgRunning(true)
    setOrgProgress({ completed: 0, total: repositories.length })
    setOrgScan({
      org: picker.org,
      owner_type: picker.ownerType,
      repositories: repositories.map(name => ({ repository: name, status: 'pending', workflows: 0, statistics: {} })),
    })
    let finished = false
    try {
      const response = await fetch('/api/audit/org/stream', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          org: picker.org,
          repositories,
          github_token: picker.token || undefined,
          use_clone: Boolean(picker.useClone),
          owner_type: picker.ownerType || undefined,
        }),
        signal: controller.signal,
      })
      if (!response.ok) {
        throw new Error(await readErrorDetail(response, 'Failed to scan repositories'))
      }
      await readEventStream(response, (type, data) => {
        // The server logs "<owner/repo>: auditing" when a repository starts.
        const started = type === 'log' && /^(\S+\/\S+): auditing$/.exec(data.message || '')
        if (started) {
          const name = started[1].toLowerCase()
          setOrgScan(prev => prev && ({
            ...prev,
            repositories: prev.repositories.map(r => (
              r.status === 'pending' && r.repository.toLowerCase() === name ? { ...r, status: 'running' } : r
            )),
          }))
        } else if (type === 'progress') {
          setOrgProgress({ completed: data.completed, total: data.total })
          setOrgScan(prev => prev && ({
            ...prev,
            repositories: prev.repositories.map(r => (
              r.repository.toLowerCase() === data.result.repository.toLowerCase() ? data.result : r
            )),
          }))
        } else if (type === 'result') {
          finished = true
          setOrgScan(data)
          setOrgScanParam(data.id)
          if (window.refreshAnalysisHistory) window.refreshAnalysisHistory()
        } else if (type === 'error') {
          finished = true
          throw new Error(data.detail || 'Scan failed')
        }
      })
      if (!finished) {
        throw new Error('The connection to the server closed before the scan finished. Check the server logs and try again.')
      }
    } catch (err) {
      if (err.name === 'AbortError') {
        setOrgScan(null)
        return
      }
      setOrgScan(prev => ({ ...(prev || { org: picker.org, repositories: [] }), error: err.message }))
    } finally {
      if (orgAbortRef.current === controller) {
        orgAbortRef.current = null
        setOrgRunning(false)
        setOrgProgress(null)
      }
    }
  }

  const handleOpenOrgRepository = async (result) => {
    try {
      const response = await fetch(`/api/analyses/${result.analysis_id}`)
      if (!response.ok) throw new Error(await readErrorDetail(response, 'Failed to load analysis'))
      const analysis = await response.json()
      runLayoutTransition(() => {
        showAnalysis(analysis)
        setGraphFilter(null)
        setViewMode('graph')
        setSelectedNode(null)
        setSelectedIssue(null)
        setOrgView(false)
      })
    } catch (err) {
      setError(err.message)
    }
  }

  // Coming back from a repository's graph: reload the scan so dismissals
  // made there show in the org counts.
  const handleBackToOrgScan = () => {
    setOrgView(true)
    setSelectedNode(null)
    setFocusFingerprint(null)
    if (orgScan?.id) setOrgScanParam(orgScan.id)
    refreshOrgScan()
  }

  // Open an org-wide finding in the same side panel the graph uses: load the
  // repository's analysis (for the graph context and dismissals) and select
  // the node the finding sits on. With inGraph, also switch to that graph.
  // Open a node of one scanned repository: in the side panel over the org
  // view, or (inGraph) in that repository's graph. A node that is not in the
  // graph (an old scan, a renamed ref) still opens the graph, unselected.
  const handleOpenOrgNode = async (repository, nodeId, { inGraph = true, fingerprint = null } = {}) => {
    const result = orgScan?.repositories?.find(r => r.repository === repository)
    if (!result?.analysis_id) return
    try {
      const response = await fetch(`/api/analyses/${result.analysis_id}`)
      if (!response.ok) throw new Error(await readErrorDetail(response, 'Failed to load analysis'))
      const analysis = await response.json()
      const graphNode = analysis.graph?.nodes?.find(n => n.id === nodeId)
      const select = () => {
        showAnalysis(analysis)
        setSelectedIssue(null)
        setFocusFingerprint(fingerprint)
        setSelectedNode(graphNode ? {
          id: graphNode.id,
          data: {
            label: graphNode.label,
            nodeLabel: graphNode.label,
            nodeType: graphNode.type,
            type: graphNode.type,
            issues: graphNode.issues || [],
            metadata: graphNode.metadata || {},
            severity: graphNode.severity,
            issueCount: graphNode.issue_count,
            nodeId: graphNode.id,
            originalId: graphNode.id,
          },
        } : null)
        if (inGraph) {
          setGraphFilter(null)
          setViewMode('graph')
          setOrgView(false)
        }
      }
      if (inGraph) runLayoutTransition(select)
      else select()
    } catch (err) {
      setError(err.message)
    }
  }

  const handleOpenOrgFinding = (finding, { inGraph = false } = {}) =>
    handleOpenOrgNode(finding.repository, finding.node?.id, { inGraph, fingerprint: finding.fingerprint || null })

  const handleLoadOrgScan = (scan) => runLayoutTransition(() => {
    showAnalysis(null)
    setSelectedNode(null)
    setSelectedIssue(null)
    setError(null)
    setOrgPicker(null)
    setOrgScan(scan)
    setOrgView(true)
    setOrgScanParam(scan.id)
    setFormInput(scan.org)
  })

  const handleAudit = async (data) => {
    if (data.org) {
      handleOrgLookup(data)
      return
    }
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
                setOrgView(false)
                setOrgScanParam(null)
                setSelectedNode(null)
                setSelectedIssue(null)
                showAnalysis(parsed)
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
    <DismissalContext.Provider value={dismissalActions}>
    <div className={`app ${isHome ? 'app--home' : ''}`}>
      {isHome ? (
        <main className="home">
          <HomeBackdrop />
          <div className="home-center">
            <p className="home-eyebrow">Workflow Security Auditor</p>
            <h1 className="home-brand" onClick={handleReset}>actsense</h1>
            <p className="home-tagline">Map every dependency your CI workflows run and audit each one.</p>
            <div className="home-meta">
              <div className="home-platform home-event">
                <span>Presented at</span>
                <span className="home-bh-logo" role="img" aria-label="Black Hat" />
              </div>
              <span className="home-meta-sep" aria-hidden="true">·</span>
              <div className="home-platform" title="Other workflow platforms are planned">
                <svg width="14" height="14" viewBox="0 0 16 16" fill="currentColor" aria-hidden="true"><path d="M8 0C3.58 0 0 3.58 0 8c0 3.54 2.29 6.53 5.47 7.59.4.07.55-.17.55-.38 0-.19-.01-.82-.01-1.49-2.01.37-2.53-.49-2.69-.94-.09-.23-.48-.94-.82-1.13-.28-.15-.68-.52-.01-.53.63-.01 1.08.58 1.23.82.72 1.21 1.87.87 2.33.66.07-.52.28-.87.51-1.07-1.78-.2-3.64-.89-3.64-3.95 0-.87.31-1.59.82-2.15-.08-.2-.36-1.02.08-2.12 0 0 .67-.21 2.2.82.64-.18 1.32-.27 2-.27.68 0 1.36.09 2 .27 1.53-1.04 2.2-.82 2.2-.82.44 1.1.16 1.92.08 2.12.51.56.82 1.27.82 2.15 0 3.07-1.87 3.75-3.65 3.95.29.25.54.73.54 1.48 0 1.07-.01 1.93-.01 2.2 0 .21.15.46.55.38A8.013 8.013 0 0016 8c0-4.42-3.58-8-8-8z"/></svg>
                <span>Works with <strong>GitHub Actions</strong></span>
              </div>
            </div>
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
            <ThemeToggle className="theme-toggle--quiet" />
            <div className="home-history">
              <AnalysisHistory onLoadAnalysis={handleLoadAnalysis} onLoadOrgScan={handleLoadOrgScan} popover />
            </div>
          </footer>
        </main>
      ) : (
      <div className="app-content">
        <aside className="sidebar" aria-label="Audit controls">
          <header className="sidebar-header">
            <h1 onClick={handleReset} title="Start over">actsense</h1>
            <div className="sidebar-header-actions">
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
              <ThemeToggle />
            </div>
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

            {orgScan && !orgView && (
              <button type="button" className="org-back" onClick={handleBackToOrgScan}>
                <svg width="12" height="12" viewBox="0 0 12 12" aria-hidden="true">
                  <path d="M7.5 2.5 4 6l3.5 3.5" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round" />
                </svg>
                Back to {orgScan.org} scan
              </button>
            )}

            {statistics && !orgView && (
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
            <AnalysisHistory onLoadAnalysis={handleLoadAnalysis} onLoadOrgScan={handleLoadOrgScan} />
          </footer>
        </aside>
        
        {orgView ? (
          <div className="main-content">
            <OrgWorkspace
              picker={orgPicker}
              scan={orgScan}
              running={orgRunning}
              progress={orgProgress}
              onScan={handleOrgScan}
              onOpenRepository={handleOpenOrgRepository}
              onCancel={() => orgAbortRef.current?.abort()}
              onOpenFinding={handleOpenOrgFinding}
              onOpenNode={handleOpenOrgNode}
              activeFingerprint={selectedNode ? focusFingerprint : null}
              refreshKey={orgFindingsVersion}
              onChooseRepositories={orgPicker?.repositories && orgPicker.org.toLowerCase() === orgScan?.org?.toLowerCase() ? () => { setOrgScan(null); setOrgScanParam(null) } : () => handleOrgLookup({
                org: orgScan.org,
                github_token: formValuesRef.current.token || undefined,
                use_clone: formValuesRef.current.useClone,
              })}
            />
          </div>
        ) : showSearchResults ? (
          <SearchResultsPage
            searchQuery={searchQuery}
            searchResults={searchResults}
            graphData={visibleGraph}
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
                  graphData={visibleGraph} 
                  onNodeSelect={(node) => { setFocusFingerprint(null); setSelectedNode(node) }}
                  filter={graphFilter}
                  onClearFilter={() => setGraphFilter(null)}
                  selectedNodeId={selectedNode?.id}
                />
              ) : (
                // Table view: show different tables based on filter
                graphFilter?.type === 'has_dependencies' ? (
                  <TransitiveDependenciesTable 
                    graphData={visibleGraph}
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
                    graphData={visibleGraph}
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
          graphData={visibleGraph}
          onClose={() => {
            setSelectedNode(null)
            setShareMode(false)
            setRepositoryAuditStatus(null)
            setFocusFingerprint(null)
          }}
          focusFingerprint={focusFingerprint}
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
          graphData={visibleGraph}
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
              showAnalysis(result)
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
    </DismissalContext.Provider>
  )
}

export default App

