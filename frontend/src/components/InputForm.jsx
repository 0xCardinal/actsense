import React, { useState } from 'react'
import './InputForm.css'

function InputForm({ onAudit, loading }) {
  const [repository, setRepository] = useState('')
  const [action, setAction] = useState('')
  const [githubToken, setGithubToken] = useState('')
  const [inputType, setInputType] = useState('repository')
  const [useClone, setUseClone] = useState(false)

  const handleSubmit = (e) => {
    e.preventDefault()
    
    const data = {
      github_token: githubToken || undefined,
      use_clone: useClone && inputType === 'repository', // Only allow clone for repositories
    }
    
    if (inputType === 'repository') {
      if (!repository.trim()) {
        alert('Please enter a repository')
        return
      }
      data.repository = repository.trim()
    } else {
      if (!action.trim()) {
        alert('Please enter an action reference')
        return
      }
      data.action = action.trim()
    }
    
    onAudit(data)
  }

  return (
    <form className="input-form" onSubmit={handleSubmit}>
      <div className="form-group">
        <label>Input Type</label>
        <div className="radio-group">
          <label>
            <input
              type="radio"
              value="repository"
              checked={inputType === 'repository'}
              onChange={(e) => setInputType(e.target.value)}
            />
            Repository
          </label>
          <label>
            <input
              type="radio"
              value="action"
              checked={inputType === 'action'}
              onChange={(e) => setInputType(e.target.value)}
            />
            Action
          </label>
        </div>
      </div>

      {inputType === 'repository' ? (
        <div className="form-group">
          <label htmlFor="repository">Repository</label>
          <input
            id="repository"
            type="text"
            placeholder="owner/repo or https://github.com/owner/repo"
            value={repository}
            onChange={(e) => setRepository(e.target.value)}
            disabled={loading}
          />
          <small>Example: actions/checkout or microsoft/vscode</small>
        </div>
      ) : (
        <div className="form-group">
          <label htmlFor="action">Action Reference</label>
          <input
            id="action"
            type="text"
            placeholder="owner/repo@v1 or owner/repo@main"
            value={action}
            onChange={(e) => setAction(e.target.value)}
            disabled={loading}
          />
          <small>Example: actions/checkout@v3</small>
        </div>
      )}

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
}

export default InputForm

