import React, { useState, useEffect, useImperativeHandle, forwardRef } from 'react'
import './InputForm.css'

// The form is mounted in two places (home hero and workspace sidebar). The
// parent keeps the values in `defaults` and receives every change through
// `onValuesChange`, so switching layouts never loses what was typed.
const OWNER_RE = /^[A-Za-z0-9](?:[A-Za-z0-9-]{0,38})$/

// 'acme', '@acme' or a github.com/acme URL name a whole organization (or user).
export function orgFromInput(value) {
  let v = (value || '').trim().replace(/\/+$/, '')
  const url = v.match(/^(?:https?:\/\/)?(?:www\.)?github\.com\/(.+)$/i)
  if (url) v = url[1]
  v = v.replace(/^@/, '')
  return OWNER_RE.test(v) ? v : null
}

const InputForm = forwardRef(({ onAudit, loading, onOpenYAMLEditor, variant = 'sidebar', defaults = {}, onValuesChange }, ref) => {
  const [input, setInput] = useState(defaults.input || '')
  const [githubToken, setGithubToken] = useState(defaults.token || '')
  const [useClone, setUseClone] = useState(Boolean(defaults.useClone))
  const [fieldError, setFieldError] = useState('')
  const [tokenOpen, setTokenOpen] = useState(false)
  const [showToken, setShowToken] = useState(false)

  useEffect(() => {
    onValuesChange && onValuesChange({ input, token: githubToken, useClone })
  }, [input, githubToken, useClone, onValuesChange])

  // Detect if input is an action, a repository or an organization
  const detectInputType = (value) => {
    if (!value || !value.trim()) {
      return 'repository' // Default to repository
    }
    
    const trimmed = value.trim()

    if (orgFromInput(trimmed)) {
      return 'org'
    }
    
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
      setFieldError('Enter an organization, a repository or an action reference.')
      return
    }
    if (inputType === 'repository' && !/^https?:\/\//.test(trimmedInput) && !/^[\w.-]+\/[\w.-]+$/.test(trimmedInput)) {
      setFieldError('Use an organization name, owner/repo, a github.com URL, or owner/repo@ref for a single action.')
      return
    }
    setFieldError('')

    if (inputType === 'org') {
      onAudit({ org: orgFromInput(trimmedInput), github_token: githubToken || undefined, use_clone: useClone })
      return
    }
    
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
    : 'org, owner/repo or https://github.com/owner/repo'

  const isHero = variant === 'hero'
  const isAction = inputType === 'action'
  const isOrg = inputType === 'org'
  const kindLabel = input.trim() ? (isAction ? 'Action' : isOrg ? 'Org' : 'Repo') : null

  const submitLabel = loading ? (
    <span className="loading-container">
      <span className="loading-dots">
        <span></span>
        <span></span>
        <span></span>
      </span>
      <span className="loading-text">Auditing</span>
    </span>
  ) : isOrg ? (isHero ? 'Find repos' : 'Choose repositories') : (isHero ? 'Audit' : 'Run audit')

  const createWorkflowButton = (
    <button
      type="button"
      className="yaml-editor-button"
      onClick={onOpenYAMLEditor}
      disabled={loading}
    >
      <svg width="14" height="14" viewBox="0 0 16 16" fill="none" aria-hidden="true">
        <path d="M8 1.5 2.75 3.5v4c0 3.1 2.2 5.6 5.25 7 3.05-1.4 5.25-3.9 5.25-7v-4L8 1.5Z" stroke="currentColor" strokeWidth="1.4" strokeLinejoin="round" />
        <path d="M8 5.5v4M6 7.5h4" stroke="currentColor" strokeWidth="1.4" strokeLinecap="round" />
      </svg>
      <span>{isHero ? 'Secure workflow' : 'Create a secure workflow'}</span>
    </button>
  )

  return (
    <form className={`input-form input-form--${variant}`} onSubmit={handleSubmit} role={isHero ? 'search' : undefined}>
      <div className="form-group">
        <label htmlFor="input" className={isHero ? 'visually-hidden' : ''}>
          Organization, repository or action
          {!isHero && kindLabel && (
            <span className={`input-kind ${inputType}`}>{kindLabel}</span>
          )}
        </label>
        <div className="audit-field">
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
            className={`audit-input ${fieldError ? 'has-error' : ''} ${isHero && kindLabel ? 'has-kind' : ''} ${isHero && isOrg ? 'is-org' : ''}`}
            autoFocus={isHero}
          />
          {isHero && kindLabel && (
            <span className={`input-kind input-kind--inline ${inputType}`} aria-live="polite">{kindLabel}</span>
          )}
          {isHero && (
            <button type="submit" disabled={loading} className="submit-button hero-submit">
              {submitLabel}
            </button>
          )}
        </div>
        {fieldError && <small id="input-help" className="field-error">{fieldError}</small>}
      </div>

      {tokenOpen && (
        <div className="token-panel" id="token-panel">
          <div className="token-panel-head">
            <label htmlFor="token">GitHub token</label>
            <a
              className="label-link"
              href="https://github.com/settings/tokens/new?description=actsense"
              target="_blank"
              rel="noopener noreferrer"
            >
              Create token ↗
            </a>
          </div>
          <div className="token-field">
            <input
              id="token"
              type={showToken ? 'text' : 'password'}
              placeholder="ghp_… or github_pat_…"
              value={githubToken}
              onChange={(e) => setGithubToken(e.target.value)}
              disabled={loading}
              spellCheck={false}
              autoComplete="off"
              aria-describedby="token-help"
            />
            {githubToken && (
              <button
                type="button"
                className="token-field-action"
                onClick={() => setShowToken(v => !v)}
                aria-label={showToken ? 'Hide token' : 'Show token'}
                aria-pressed={showToken}
              >
                {showToken ? 'Hide' : 'Show'}
              </button>
            )}
            {githubToken && (
              <button
                type="button"
                className="token-field-action"
                onClick={() => { setGithubToken(''); setShowToken(false) }}
                aria-label="Clear token"
              >
                Clear
              </button>
            )}
          </div>
          <small id="token-help">
            Raises the API limit from 60 to 5,000 requests/hour, which deep graphs need. A token with no scopes works for public repositories. It is sent with the audit only and never saved.
          </small>
        </div>
      )}

      <div className="form-toolbar">
        <button
          type="button"
          className={`tool-chip ${githubToken ? 'is-set' : ''}`}
          onClick={() => setTokenOpen(v => !v)}
          aria-expanded={tokenOpen}
          aria-controls="token-panel"
          disabled={loading}
        >
          <svg width="14" height="14" viewBox="0 0 16 16" fill="none" aria-hidden="true">
            <circle cx="5.5" cy="10.5" r="3" stroke="currentColor" strokeWidth="1.4" />
            <path d="m7.7 8.3 5.8-5.8M11.5 4.5l1.75 1.75M9.75 6.25 11 7.5" stroke="currentColor" strokeWidth="1.4" strokeLinecap="round" />
          </svg>
          <span>{githubToken ? 'Token set' : 'Add token'}</span>
          {githubToken && <span className="tool-chip-dot" aria-hidden="true" />}
        </button>

        <label
          className={`tool-chip tool-chip--switch ${useClone && !isAction ? 'is-on' : ''} ${isAction ? 'is-disabled' : ''}`}
          title={isAction
            ? 'Cloning applies to repositories, not single actions.'
            : 'Read workflows from a git clone instead of the API. Useful for private repositories.'}
        >
          <input
            type="checkbox"
            role="switch"
            checked={useClone && !isAction}
            onChange={(e) => setUseClone(e.target.checked)}
            disabled={loading || isAction}
          />
          <svg width="14" height="14" viewBox="0 0 16 16" fill="none" aria-hidden="true">
            <circle cx="4.5" cy="3.5" r="1.75" stroke="currentColor" strokeWidth="1.4" />
            <circle cx="4.5" cy="12.5" r="1.75" stroke="currentColor" strokeWidth="1.4" />
            <circle cx="11.5" cy="5.5" r="1.75" stroke="currentColor" strokeWidth="1.4" />
            <path d="M4.5 5.25v5.5M11.5 7.25c0 2.5-3 2.25-6.5 3.75" stroke="currentColor" strokeWidth="1.4" strokeLinecap="round" />
          </svg>
          <span>Clone repo</span>
          <span className="toggle-track" aria-hidden="true"><span className="toggle-thumb" /></span>
        </label>

        {isHero && <span className="form-toolbar-spacer" aria-hidden="true" />}
        {isHero && createWorkflowButton}
      </div>

      {!isHero && (
        <button type="submit" disabled={loading} className="submit-button">
          {submitLabel}
        </button>
      )}

      {!isHero && createWorkflowButton}
    </form>
  )
})

InputForm.displayName = 'InputForm'

export default InputForm

