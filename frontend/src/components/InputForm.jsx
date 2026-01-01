import React, { useState, useImperativeHandle, forwardRef } from 'react'
import './InputForm.css'

const InputForm = forwardRef(({ onAudit, loading, onOpenYAMLEditor }, ref) => {
  const [input, setInput] = useState('')
  const [githubToken, setGithubToken] = useState('')
  const [useClone, setUseClone] = useState(false)

  // Detect if input is an action or repository
  const detectInputType = (value) => {
    if (!value || !value.trim()) {
      return 'repository' // Default to repository
    }
    
    const trimmed = value.trim()
    
    // Check if it's an action reference (has @ symbol and owner/repo@ref format)
    if (trimmed.includes('@')) {
      const parts = trimmed.split('@')
      if (parts.length === 2 && parts[0].includes('/')) {
        // Check if it's not a GitHub URL
        if (!trimmed.startsWith('http://') && !trimmed.startsWith('https://')) {
          return 'action'
        }
      }
    }
    
    // Default to repository
    return 'repository'
  }

  // Expose setRepository function and getToken to parent via ref
  useImperativeHandle(ref, () => ({
    setRepository: (value) => {
      setInput(value)
    },
    getToken: () => githubToken
  }))

  const handleSubmit = (e) => {
    e.preventDefault()
    
    if (!input.trim()) {
      alert('Please enter a repository or action reference')
      return
    }
    
    const inputType = detectInputType(input)
    const trimmedInput = input.trim()
    
    const data = {
      github_token: githubToken || undefined,
      use_clone: useClone && inputType === 'repository', // Only allow clone for repositories
    }
    
    if (inputType === 'repository') {
      data.repository = trimmedInput
    } else {
      data.action = trimmedInput
    }
    
    onAudit(data)
  }

  const inputType = detectInputType(input)
  const placeholder = inputType === 'action' 
    ? 'owner/repo@v1 or owner/repo@main' 
    : 'owner/repo or https://github.com/owner/repo'
  const example = inputType === 'action'
    ? 'Example: actions/checkout@v3'
    : 'Example: actions/checkout or microsoft/vscode'

  return (
    <form className="input-form" onSubmit={handleSubmit}>
      <div className="form-group">
        <label htmlFor="input">Repository or Action</label>
        <input
          id="input"
          type="text"
          placeholder={placeholder}
          value={input}
          onChange={(e) => setInput(e.target.value)}
          disabled={loading}
        />
        <small>{example}</small>
      </div>

      <div className="form-group">
        <label htmlFor="token">GitHub Token (Recommended)</label>
        <input
          id="token"
          type="password"
          placeholder="ghp_..."
          value={githubToken}
          onChange={(e) => setGithubToken(e.target.value)}
          disabled={loading}
        />
        <small>
          Increases rate limit from 60/hour to 5000/hour. 
          <a href="https://github.com/settings/tokens" target="_blank" rel="noopener noreferrer" style={{marginLeft: '4px'}}>
            Create token
          </a>
        </small>
      </div>

      {inputType === 'repository' && (
        <div className="form-group">
          <label style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', cursor: 'pointer' }}>
            <input
              type="checkbox"
              checked={useClone}
              onChange={(e) => setUseClone(e.target.checked)}
              disabled={loading}
            />
            <span>Clone repository (for private repos or to avoid rate limits)</span>
          </label>
          <small>Clones the repository locally for analysis. Requires git to be installed.</small>
        </div>
      )}

          <button type="submit" disabled={loading} className="submit-button">
            {loading ? (
              <span className="loading-container">
                <span className="loading-dots">
                  <span></span>
                  <span></span>
                  <span></span>
                </span>
                <span className="loading-text">Auditing</span>
              </span>
            ) : (
              'Audit'
            )}
          </button>
          
          <div className="form-divider">
            <span>or</span>
          </div>
          
          <button 
            type="button" 
            className="yaml-editor-button"
            onClick={onOpenYAMLEditor}
            disabled={loading}
          >
            <svg width="16" height="16" viewBox="0 0 16 16" fill="none" xmlns="http://www.w3.org/2000/svg">
              <path d="M11.013 1.427a1.75 1.75 0 012.474 0l1.086 1.086a1.75 1.75 0 010 2.474l-8.61 8.61c-.21.21-.47.364-.756.445l-3.251.93a.75.75 0 01-.927-.928l.929-3.25c.081-.286.235-.547.445-.758l8.61-8.61zm1.414 1.06a.25.25 0 00-.354 0L10.811 3.75l1.439 1.44 1.263-1.263a.25.25 0 000-.354l-1.086-1.086zM11.189 6.25L9.75 4.81l-6.286 6.287a.25.25 0 00-.064.108l-.558 1.953 1.953-.558a.249.249 0 00.108-.064l6.286-6.286z" fill="currentColor"/>
            </svg>
            Edit Workflow YAML
          </button>
    </form>
  )
})

InputForm.displayName = 'InputForm'

export default InputForm

