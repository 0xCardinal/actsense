import React, { useState, useRef, useEffect } from 'react'
import './YAMLEditorPanel.css'

const SEVERITY_COLORS = {
  critical: '#dc2626',
  high: '#f97316',
  medium: '#eab308',
  low: '#6b7280',
}

function YAMLEditorPanel({ onClose, onAnalyze, githubToken, loading, initialContent }) {
  const [yamlContent, setYamlContent] = useState(initialContent || '')
  const [error, setError] = useState(null)
  const [validationError, setValidationError] = useState(null)
  const [fixes, setFixes] = useState([])
  const [issues, setIssues] = useState([])
  const [appliedFixes, setAppliedFixes] = useState(new Set())
  const [fixing, setFixing] = useState(false)
  const [rateLimited, setRateLimited] = useState(false)
  const textareaRef = useRef(null)
  const lineNumbersRef = useRef(null)

  useEffect(() => {
    if (initialContent !== undefined) {
      setYamlContent(initialContent || '')
    }
  }, [initialContent])

  useEffect(() => {
    const textarea = textareaRef.current
    const lineNumbers = lineNumbersRef.current
    if (!textarea || !lineNumbers) return
    const handleScroll = () => { lineNumbers.scrollTop = textarea.scrollTop }
    textarea.addEventListener('scroll', handleScroll)
    return () => textarea.removeEventListener('scroll', handleScroll)
  }, [])

  useEffect(() => {
    const content = yamlContent || ''
    const lineCount = content.split('\n').length
    const lineNumbers = lineNumbersRef.current
    if (lineNumbers) {
      lineNumbers.innerHTML = Array.from({ length: lineCount }, (_, i) =>
        `<div class="yaml-editor-line-number">${i + 1}</div>`
      ).join('')
    }
  }, [yamlContent])

  const validateYAML = (content) => {
    if (!content || !content.trim()) {
      return { valid: false, error: 'Please paste a workflow YAML file' }
    }
    try {
      const lines = (content || '').split('\n')
      for (let i = 0; i < lines.length; i++) {
        const line = lines[i]
        const trimmed = line.trim()
        if (!trimmed || trimmed.startsWith('#')) continue
        if (line.includes('\t')) {
          return { valid: false, error: `Line ${i + 1}: Mixed tabs and spaces. Use only spaces.` }
        }
      }
      return { valid: true, error: null }
    } catch (e) {
      return { valid: false, error: `YAML validation error: ${e.message}` }
    }
  }

  const handleSecure = async () => {
    setError(null)
    setValidationError(null)
    setFixes([])
    setIssues([])
    setAppliedFixes(new Set())

    const validation = validateYAML(yamlContent)
    if (!validation.valid) {
      setValidationError(validation.error)
      setError(`YAML validation failed: ${validation.error}`)
      return
    }

    setFixing(true)
    try {
      const response = await fetch('/api/audit/fix', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          yaml_content: yamlContent,
          github_token: githubToken || undefined,
        }),
      })
      if (!response.ok) {
        let errorData
        try { errorData = await response.json() } catch { errorData = { detail: `HTTP ${response.status}` } }
        throw new Error(errorData.detail || 'Failed to analyze workflow')
      }
      const result = await response.json()
      setIssues(result.issues || [])
      setFixes(result.fixes || [])
      setRateLimited(result.rate_limited || false)
    } catch (err) {
      setError(err.message || 'Failed to analyze workflow')
    } finally {
      setFixing(false)
    }
  }

  const applyFix = (index) => {
    const fix = fixes[index]
    if (!fix || appliedFixes.has(index)) return
    setYamlContent(prev => prev.replace(fix.original, fix.replacement))
    setAppliedFixes(prev => new Set([...prev, index]))
  }

  const applyAllFixes = () => {
    let content = yamlContent
    const newApplied = new Set(appliedFixes)
    fixes.forEach((fix, i) => {
      if (newApplied.has(i)) return
      if (content.includes(fix.original)) {
        content = content.replace(fix.original, fix.replacement)
        newApplied.add(i)
      }
    })
    setYamlContent(content)
    setAppliedFixes(newApplied)
  }

  const handleAnalyzeAndClose = async () => {
    setError(null)
    setValidationError(null)
    const validation = validateYAML(yamlContent)
    if (!validation.valid) {
      setValidationError(validation.error)
      setError(`YAML validation failed: ${validation.error}`)
      return
    }
    try {
      await onAnalyze(yamlContent, githubToken)
    } catch (err) {
      setError(err.message || 'Failed to analyze workflow')
    }
  }

  const unappliedCount = fixes.filter((_, i) => !appliedFixes.has(i)).length
  const hasFixes = fixes.length > 0
  const hasIssues = issues.length > 0

  return (
    <>
      <div className="yaml-editor-backdrop" onClick={onClose} />
      <div className="yaml-editor-panel">
        <div className="yaml-editor-header">
          <div>
            <h2>Secure Workflow Creator</h2>
            <p>Paste a GitHub Actions workflow to detect and fix security issues</p>
          </div>
          <button className="yaml-editor-close" onClick={onClose} aria-label="Close">
            &times;
          </button>
        </div>

        <div className="yaml-editor-content">
          {validationError && (
            <div className="yaml-editor-validation-error">
              <strong>YAML Validation Error:</strong> {validationError}
            </div>
          )}
          {error && !validationError && (
            <div className="yaml-editor-error">
              <strong>Error:</strong> {error}
            </div>
          )}

          <div className={`yaml-editor-split ${hasFixes || hasIssues ? 'has-results' : ''}`}>
            <div className="yaml-editor-left">
              <div className="yaml-editor-code-container">
                <div className="yaml-editor-line-numbers" ref={lineNumbersRef} />
                <textarea
                  ref={textareaRef}
                  className="yaml-editor-textarea"
                  value={yamlContent || ''}
                  onChange={(e) => {
                    setYamlContent(e.target.value || '')
                    setError(null)
                    setValidationError(null)
                  }}
                  placeholder={"Paste your workflow YAML here...\n\nExample:\nname: CI\non: [push]\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/checkout@v4"}
                  spellCheck={false}
                />
              </div>
            </div>

            {(hasFixes || hasIssues) && (
              <div className="yaml-editor-right">
                <div className="yaml-editor-fixes-header">
                  <h3>
                    Security Analysis
                    {hasIssues && <span className="yaml-fixes-count">{issues.length} issue{issues.length !== 1 ? 's' : ''}</span>}
                  </h3>
                  {rateLimited && (
                    <div className="yaml-fix-rate-warning">Provide a GitHub token for SHA auto-resolve</div>
                  )}
                  {hasFixes && unappliedCount > 0 && (
                    <button className="yaml-fix-apply-all" onClick={applyAllFixes}>
                      Apply All Fixes ({unappliedCount})
                    </button>
                  )}
                </div>
                <div className="yaml-editor-fixes-list">
                  {fixes.map((fix, i) => {
                    const applied = appliedFixes.has(i)
                    return (
                      <div key={i} className={`yaml-fix-card ${applied ? 'yaml-fix-applied' : ''}`}>
                        <div className="yaml-fix-card-header">
                          <span className="yaml-fix-severity" style={{ backgroundColor: SEVERITY_COLORS[fix.severity] || '#6b7280' }}>
                            {fix.severity}
                          </span>
                          <span className="yaml-fix-type">{fix.issue_type}</span>
                          {fix.line && <span className="yaml-fix-line">L{fix.line}</span>}
                        </div>
                        <p className="yaml-fix-description">{fix.description}</p>
                        <div className="yaml-fix-diff">
                          <div className="yaml-fix-diff-old">- {fix.original}</div>
                          <div className="yaml-fix-diff-new">+ {fix.replacement}</div>
                        </div>
                        {!applied ? (
                          <button className="yaml-fix-apply" onClick={() => applyFix(i)}>Apply Fix</button>
                        ) : (
                          <div className="yaml-fix-applied-label">
                            <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round"><polyline points="20 6 9 17 4 12" /></svg>
                            Applied
                          </div>
                        )}
                      </div>
                    )
                  })}
                  {issues.filter(iss => !fixes.some(f => f.issue_type === iss.type)).slice(0, 20).map((iss, i) => (
                    <div key={`iss-${i}`} className="yaml-fix-card yaml-issue-only">
                      <div className="yaml-fix-card-header">
                        <span className="yaml-fix-severity" style={{ backgroundColor: SEVERITY_COLORS[iss.severity] || '#6b7280' }}>
                          {iss.severity}
                        </span>
                        <span className="yaml-fix-type">{iss.type}</span>
                        {iss.line_number && <span className="yaml-fix-line">L{iss.line_number}</span>}
                      </div>
                      <p className="yaml-fix-description">{iss.message}</p>
                    </div>
                  ))}
                </div>
              </div>
            )}
          </div>

          <div className="yaml-editor-footer">
            <div className="yaml-editor-footer-buttons">
              <button
                className="yaml-editor-secure-button"
                onClick={handleSecure}
                disabled={fixing || loading || !yamlContent || !yamlContent.trim()}
              >
                {fixing ? (
                  <span className="loading-container">
                    <span className="loading-dots"><span></span><span></span><span></span></span>
                    <span className="loading-text">Analyzing</span>
                  </span>
                ) : (
                  'Secure Workflow'
                )}
              </button>
              <button
                className="yaml-editor-analyze-button"
                onClick={handleAnalyzeAndClose}
                disabled={fixing || loading || !yamlContent || !yamlContent.trim()}
              >
                {loading ? (
                  <span className="loading-container">
                    <span className="loading-dots"><span></span><span></span><span></span></span>
                    <span className="loading-text">Analyzing</span>
                  </span>
                ) : (
                  'Analyze & View Graph'
                )}
              </button>
            </div>
            <p className="yaml-editor-hint">
              "Secure Workflow" detects issues and suggests fixes. "Analyze & View Graph" creates the full dependency graph.
            </p>
          </div>
        </div>
      </div>
    </>
  )
}

export default YAMLEditorPanel
