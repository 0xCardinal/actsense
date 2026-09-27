import React, { useState, useEffect, useImperativeHandle, forwardRef } from 'react'
import './InputForm.css'

// The form is mounted in two places (home hero and workspace sidebar). The
// parent keeps the values in `defaults` and receives every change through
// `onValuesChange`, so switching layouts never loses what was typed.
const InputForm = forwardRef(({ onAudit, loading, onOpenYAMLEditor, variant = 'sidebar', defaults = {}, onValuesChange }, ref) => {
  const [input, setInput] = useState(defaults.input || '')
  const [githubToken, setGithubToken] = useState(defaults.token || '')
  const [useClone, setUseClone] = useState(Boolean(defaults.useClone))
  const [fieldError, setFieldError] = useState('')
  const [optionsOpen, setOptionsOpen] = useState(false)

  useEffect(() => {
    onValuesChange && onValuesChange({ input, token: githubToken, useClone })
  }, [input, githubToken, useClone, onValuesChange])

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
      setFieldError('')
    },
    getToken: () => githubToken
  }))

  const handleSubmit = (e) => {
    e.preventDefault()
    
    const inputType = detectInputType(input)
    const trimmedInput = input.trim()

    if (!trimmedInput) {
      setFieldError('Enter a repository or an action reference.')
      return
    }
    if (inputType === 'repository' && !/^https?:\/\//.test(trimmedInput) && !/^[\w.-]+\/[\w.-]+$/.test(trimmedInput)) {
      setFieldError('Use owner/repo, a github.com URL, or owner/repo@ref for a single action.')
      return
    }
    setFieldError('')
    
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

  return (
    <form className={`input-form input-form--${variant}`} onSubmit={handleSubmit} role={variant === 'hero' ? 'search' : undefined}>
      <div className="form-group">
        <label htmlFor="input" className={variant === 'hero' ? 'visually-hidden' : ''}>
          Repository or action
          {input.trim() && (
            <span className={`input-kind ${inputType}`}>{inputType === 'action' ? 'Action' : 'Repo'}</span>
          )}
        </label>
        <input
          id="input"
          type="text"
          placeholder={placeholder}
          value={input}
          onChange={(e) => { setInput(e.target.value); if (fieldError) setFieldError('') }}
          disabled={loading}
          spellCheck={false}
          autoComplete="off"
          aria-invalid={Boolean(fieldError)}
          aria-describedby={fieldError ? 'input-help' : undefined}
          className={`audit-input ${fieldError ? 'has-error' : ''}`}
          autoFocus={variant === 'hero'}
        />
        {variant === 'hero' && (
          <button type="submit" disabled={loading} className="submit-button hero-submit">
            Audit
          </button>
        )}
        {fieldError && <small id="input-help" className="field-error">{fieldError}</small>}
      </div>

      <details className="form-options" open={optionsOpen} onToggle={(e) => setOptionsOpen(e.currentTarget.open)}>
        <summary>
          Options
          {githubToken && <span className="options-dot" title="Token set" />}
        </summary>
        <div className="form-options-body">
          <div className="form-group">
            <label htmlFor="token">
              GitHub token
              <a
                className="label-link"
                href="https://github.com/settings/tokens"
                target="_blank"
                rel="noopener noreferrer"
              >
                Create
              </a>
            </label>
            <input
              id="token"
              type="password"
              placeholder="ghp_…"
              value={githubToken}
              onChange={(e) => setGithubToken(e.target.value)}
              disabled={loading}
            />
            <small>60 → 5,000 API requests/hour. Needed for deep graphs.</small>
          </div>

          {inputType === 'repository' && (
            <label className="toggle-row" title="For private repositories. Actions are still resolved through the API.">
              <input
                type="checkbox"
                role="switch"
                checked={useClone}
                onChange={(e) => setUseClone(e.target.checked)}
                disabled={loading}
              />
              <span className="toggle-track" aria-hidden="true"><span className="toggle-thumb" /></span>
              <span>Read workflows from a git clone</span>
            </label>
          )}
        </div>
      </details>

      {variant !== 'hero' && <button type="submit" disabled={loading} className="submit-button">
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
          'Run audit'
        )}
      </button>}

      <button
        type="button"
        className="yaml-editor-button"
        onClick={onOpenYAMLEditor}
        disabled={loading}
      >
        or create a secure workflow
      </button>
    </form>
  )
})

InputForm.displayName = 'InputForm'

export default InputForm

