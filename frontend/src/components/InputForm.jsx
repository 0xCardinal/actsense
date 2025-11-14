import React, { useState, useImperativeHandle, forwardRef } from 'react'
import './InputForm.css'

const InputForm = forwardRef(({ onAudit, loading }, ref) => {
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

  // Expose setRepository function to parent via ref
  useImperativeHandle(ref, () => ({
    setRepository: (value) => {
      setInput(value)
    }
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
    </form>
  )
})

InputForm.displayName = 'InputForm'

export default InputForm

