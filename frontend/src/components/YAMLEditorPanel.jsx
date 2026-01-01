import React, { useState, useRef, useEffect } from 'react'
import './YAMLEditorPanel.css'

function YAMLEditorPanel({ onClose, onAnalyze, githubToken, loading, initialContent }) {
  const [yamlContent, setYamlContent] = useState(initialContent || '')
  const [error, setError] = useState(null)
  const [validationError, setValidationError] = useState(null)
  const textareaRef = useRef(null)
  const lineNumbersRef = useRef(null)

  // Update content when initialContent changes
  useEffect(() => {
    if (initialContent !== undefined) {
      setYamlContent(initialContent || '')
    }
  }, [initialContent])

  // Sync scroll between textarea and line numbers
  useEffect(() => {
    const textarea = textareaRef.current
    const lineNumbers = lineNumbersRef.current
    
    if (!textarea || !lineNumbers) return

    const handleScroll = () => {
      lineNumbers.scrollTop = textarea.scrollTop
    }

    textarea.addEventListener('scroll', handleScroll)
    return () => textarea.removeEventListener('scroll', handleScroll)
  }, [])

  // Update line numbers when content changes
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

  // Validate YAML syntax
  const validateYAML = (content) => {
    if (!content || !content.trim()) {
      return { valid: false, error: 'Please paste a workflow YAML file' }
    }

    try {
      // Basic YAML structure check
      const lines = (content || '').split('\n')
      
      for (let i = 0; i < lines.length; i++) {
        const line = lines[i]
        const trimmed = line.trim()
        
        // Skip empty lines and comments
        if (!trimmed || trimmed.startsWith('#')) {
          continue
        }
        
        // Check for mixed indentation (tabs vs spaces)
        if (line.includes('\t')) {
          return { 
            valid: false, 
            error: `Line ${i + 1}: Mixed tabs and spaces in indentation. Use only spaces.` 
          }
        }
        
        // Check for unclosed quotes
        const singleQuotes = (line.match(/'/g) || []).length
        const doubleQuotes = (line.match(/"/g) || []).length
        if (singleQuotes % 2 !== 0 || doubleQuotes % 2 !== 0) {
          return { 
            valid: false, 
            error: `Line ${i + 1}: Unclosed quotes detected.` 
          }
        }
      }
      
      return { valid: true, error: null }
    } catch (e) {
      return { 
        valid: false, 
        error: `YAML validation error: ${e.message}` 
      }
    }
  }

  const handleAnalyze = async () => {
    setError(null)
    setValidationError(null)

    // Validate YAML before analysis
    const validation = validateYAML(yamlContent)
    if (!validation.valid) {
      const errorMsg = `YAML validation failed: ${validation.error}`
      setValidationError(validation.error)
      setError(errorMsg)
      return
    }

    // Only proceed if validation passes
    try {
      await onAnalyze(yamlContent, githubToken)
    } catch (err) {
      // Display error from backend analysis
      setError(err.message || 'Failed to analyze workflow')
      setValidationError(null) // Clear validation error if we have a backend error
    }
  }

  return (
    <>
      <div className="yaml-editor-backdrop" onClick={onClose} />
      <div className="yaml-editor-panel">
        <div className="yaml-editor-header">
          <div>
            <h2>Workflow Editor</h2>
            <p>Paste your GitHub Actions workflow YAML to analyze it</p>
          </div>
          <button className="yaml-editor-close" onClick={onClose} aria-label="Close">
            ×
          </button>
        </div>

        <div className="yaml-editor-content">
          {validationError && (
            <div className="yaml-editor-validation-error">
              <strong>YAML Validation Error:</strong> {validationError}
            </div>
          )}
          
          {error && (
            <div className="yaml-editor-error">
              <strong>Error:</strong> {error}
            </div>
          )}

          <div className="yaml-editor-code-container">
            <div className="yaml-editor-line-numbers" ref={lineNumbersRef}>
              {/* Line numbers populated by useEffect */}
            </div>
            <textarea
              ref={textareaRef}
              className="yaml-editor-textarea"
              value={yamlContent || ''}
              onChange={(e) => {
                setYamlContent(e.target.value || '')
                setError(null)
                setValidationError(null)
              }}
              placeholder="Paste your workflow YAML here...&#10;&#10;Example:&#10;name: CI&#10;on: [push]&#10;jobs:&#10;  build:&#10;    runs-on: ubuntu-latest&#10;    steps:&#10;      - uses: actions/checkout@v3"
              spellCheck={false}
            />
          </div>

          <div className="yaml-editor-footer">
            <button
              className="yaml-editor-analyze-button"
              onClick={handleAnalyze}
              disabled={loading || !yamlContent || !yamlContent.trim() || !!validationError}
            >
              {loading ? (
                <span className="loading-container">
                  <span className="loading-dots">
                    <span></span>
                    <span></span>
                    <span></span>
                  </span>
                  <span className="loading-text">Analyzing</span>
                </span>
              ) : (
                <>
                  <svg width="16" height="16" viewBox="0 0 16 16" fill="none" xmlns="http://www.w3.org/2000/svg">
                    <path d="M8 0a8 8 0 1 1 0 16A8 8 0 0 1 8 0ZM1.5 8a6.5 6.5 0 1 0 13 0 6.5 6.5 0 0 0-13 0Z" fill="currentColor"/>
                    <path d="M7.25 4.75v3.5l3 1.75.75-1.3L8.75 8V4.75h-1.5Z" fill="currentColor"/>
                  </svg>
                  Analyze Workflow
                </>
              )}
            </button>
            <p className="yaml-editor-hint">
              The analysis will create a graph showing security issues and dependencies, just like analyzing a repository.
            </p>
          </div>
        </div>
      </div>
    </>
  )
}

export default YAMLEditorPanel
