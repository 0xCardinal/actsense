import React, { useState, useEffect, useRef } from 'react'
import './AnalysisHistory.css'

function AnalysisHistory({ onLoadAnalysis, popover = false }) {
  const [analyses, setAnalyses] = useState([])
  const [loading, setLoading] = useState(true)
  const [expanded, setExpanded] = useState(false)
  const rootRef = useRef(null)

  // As a popover, close on an outside click or Escape.
  useEffect(() => {
    if (!popover || !expanded) return undefined
    const onPointer = (e) => {
      if (rootRef.current && !rootRef.current.contains(e.target)) setExpanded(false)
    }
    const onKey = (e) => { if (e.key === 'Escape') setExpanded(false) }
    document.addEventListener('mousedown', onPointer)
    document.addEventListener('keydown', onKey)
    return () => {
      document.removeEventListener('mousedown', onPointer)
      document.removeEventListener('keydown', onKey)
    }
  }, [popover, expanded])

  useEffect(() => {
    fetchAnalyses()
    // Expose refresh function globally so App can call it
    window.refreshAnalysisHistory = fetchAnalyses
    return () => {
      delete window.refreshAnalysisHistory
    }
  }, [])

  const fetchAnalyses = async () => {
    try {
      const response = await fetch('/api/analyses?limit=20')
      if (response.ok) {
        const data = await response.json()
        setAnalyses(data)
      }
    } catch (error) {
      console.error('Failed to fetch analyses:', error)
    } finally {
      setLoading(false)
    }
  }

  const handleLoad = async (analysisId) => {
    try {
      const response = await fetch(`/api/analyses/${analysisId}`)
      if (response.ok) {
        const analysis = await response.json()
        onLoadAnalysis(analysis)
      }
    } catch (error) {
      console.error('Failed to load analysis:', error)
    }
  }

  const formatDate = (dateString) => {
    const date = new Date(dateString)
    return date.toLocaleString()
  }

  if (!expanded && analyses.length === 0) {
    return null
  }

  return (
    <div className="analysis-history" ref={rootRef}>
      <button
        type="button"
        className="history-header"
        onClick={() => setExpanded(!expanded)}
        aria-expanded={expanded}
      >
        <h3>Previous analyses</h3>
        <span className="history-count">{analyses.length}</span>
        <svg className={`toggle-icon ${expanded ? 'open' : ''}`} width="12" height="12" viewBox="0 0 12 12" aria-hidden="true">
          <path d="M4 2.5 7.5 6 4 9.5" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round" />
        </svg>
      </button>
      
      {expanded && (
        <div className="history-content">
          {loading ? (
            <div className="history-loading">Loading...</div>
          ) : analyses.length === 0 ? (
            <div className="history-empty">No previous analyses</div>
          ) : (
            <div className="history-list">
              {analyses.map((analysis) => (
                <div key={analysis.id} className="history-item">
                  <div className="history-item-header">
                    <div className="history-item-title">
                      <strong>{analysis.repository || analysis.action || 'Unknown'}</strong>
                      <div className="history-item-meta">
                        <span className="history-method">{analysis.method || 'api'}</span>
                        <span className="history-item-date">{formatDate(analysis.timestamp)}</span>
                      </div>
                    </div>
                  </div>
                  {analysis.statistics && (
                    <div className="history-item-stats">
                      <span>{analysis.statistics.total_issues || 0} issues</span>
                      <span>{analysis.statistics.total_nodes || 0} nodes</span>
                    </div>
                  )}
                  <button
                    className="history-load-button"
                    onClick={() => handleLoad(analysis.id)}
                  >
                    Load
                  </button>
                </div>
              ))}
            </div>
          )}
        </div>
      )}
    </div>
  )
}

export default AnalysisHistory

