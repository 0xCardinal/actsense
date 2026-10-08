import React, { useEffect, useMemo, useState } from 'react'
import './OrgWorkspace.css'

const SEVERITIES = ['critical', 'high', 'medium', 'low']
const SEVERITY_SHORT = { critical: 'Crit', high: 'High', medium: 'Med', low: 'Low' }
const SEVERITY_RANK = { critical: 0, high: 1, medium: 2, low: 3 }
const GROUP_PAGE = 50

const STATUS_LABELS = {
  pending: 'Queued',
  running: 'Scanning',
  ok: 'Scanned',
  no_workflows: 'No workflows',
  error: 'Failed',
  skipped: 'Skipped',
}

/* ------------------------------------------------------------------ */
/* Small helpers                                                       */
/* ------------------------------------------------------------------ */

function relativeTime(iso) {
  if (!iso) return ''
  const days = Math.floor((Date.now() - new Date(iso).getTime()) / 86400000)
  if (days < 1) return 'today'
  if (days < 30) return `${days}d ago`
  if (days < 365) return `${Math.floor(days / 30)}mo ago`
  return `${Math.floor(days / 365)}y ago`
}

const repoName = (fullName) => fullName.split('/').slice(1).join('/') || fullName

const ACRONYMS = {
  github: 'GitHub', aws: 'AWS', gcp: 'GCP', oidc: 'OIDC', npm: 'NPM', sha: 'SHA', pr: 'PR',
  prs: 'PRs', id: 'ID', api: 'API', ci: 'CI', url: 'URL', yaml: 'YAML', js: 'JS',
}

const ruleTitle = (type) => (type || 'unknown')
  .split('_')
  .map((w, i) => ACRONYMS[w] || (i === 0 ? w.charAt(0).toUpperCase() + w.slice(1) : w))
  .join(' ')

const plural = (n, one, many = `${one}s`) => `${n} ${n === 1 ? one : many}`

// One line for the table; the full message stays available on hover.
function summarizeError(error) {
  if (!error) return ''
  const failed = error.match(/^(\d+) workflow\(s\) could not be processed/)
  const suffix = failed ? ` · ${plural(Number(failed[1]), 'workflow')}` : ''
  if (/rate limit/i.test(error)) return `Rate limit reached${suffix}`
  if (/deleted/i.test(error)) return 'Stored analysis deleted'
  if (failed) return `${plural(Number(failed[1]), 'workflow')} failed to load`
  if (/inaccessible|private|permission|403/i.test(error)) return 'No access'
  return error.length > 60 ? `${error.slice(0, 57)}…` : error
}

function defaultSelection(repositories, max) {
  return new Set(
    repositories.filter(r => !r.archived && !r.fork).slice(0, max).map(r => r.full_name)
  )
}

// Stagger list entrances, capped so long lists never wait on animation.
const stagger = (i) => ({ '--i': Math.min(i, 12) })

/* ------------------------------------------------------------------ */
/* Icons (inline, 1.5 stroke)                                          */
/* ------------------------------------------------------------------ */

const Icon = {
  External: () => (
    <svg className="org-icon" width="12" height="12" viewBox="0 0 16 16" fill="none" aria-hidden="true">
      <path d="M6.5 3.5h-3v9h9v-3M9.5 2.5h4v4M13.5 2.5 7.5 8.5" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round" />
    </svg>
  ),
  Chevron: ({ open }) => (
    <svg className={`org-icon org-chevron ${open ? 'is-open' : ''}`} width="12" height="12" viewBox="0 0 16 16" fill="none" aria-hidden="true">
      <path d="m6 3.5 4.5 4.5L6 12.5" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round" />
    </svg>
  ),
  Arrow: () => (
    <svg className="org-icon" width="12" height="12" viewBox="0 0 16 16" fill="none" aria-hidden="true">
      <path d="M3 8h10M9 4l4 4-4 4" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round" />
    </svg>
  ),
  Search: () => (
    <svg className="org-icon" width="14" height="14" viewBox="0 0 16 16" fill="none" aria-hidden="true">
      <circle cx="7" cy="7" r="4.5" stroke="currentColor" strokeWidth="1.5" />
      <path d="m10.5 10.5 3 3" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" />
    </svg>
  ),
  File: () => (
    <svg className="org-icon" width="12" height="12" viewBox="0 0 16 16" fill="none" aria-hidden="true">
      <path d="M4 1.75h5.5L12.5 4.75v9.5H4z" stroke="currentColor" strokeWidth="1.5" strokeLinejoin="round" />
      <path d="M9.25 1.75v3.25h3.25" stroke="currentColor" strokeWidth="1.5" strokeLinejoin="round" />
    </svg>
  ),
  Book: () => (
    <svg className="org-icon" width="12" height="12" viewBox="0 0 16 16" fill="none" aria-hidden="true">
      <path d="M8 4c0-.83-.67-1.5-1.5-1.5H2.5v10h4c.83 0 1.5.67 1.5 1.5M8 4c0-.83.67-1.5 1.5-1.5h4v10h-4c-.83 0-1.5.67-1.5 1.5M8 4v10" stroke="currentColor" strokeWidth="1.5" strokeLinejoin="round" />
    </svg>
  ),
  Graph: () => (
    <svg className="org-icon" width="12" height="12" viewBox="0 0 16 16" fill="none" aria-hidden="true">
      <circle cx="3.5" cy="8" r="1.75" stroke="currentColor" strokeWidth="1.5" />
      <circle cx="12.5" cy="3.5" r="1.75" stroke="currentColor" strokeWidth="1.5" />
      <circle cx="12.5" cy="12.5" r="1.75" stroke="currentColor" strokeWidth="1.5" />
      <path d="M5.1 7.2 10.9 4.3M5.1 8.8l5.8 2.9" stroke="currentColor" strokeWidth="1.5" />
    </svg>
  ),
  Warning: () => (
    <svg className="org-icon" width="16" height="16" viewBox="0 0 16 16" fill="none" aria-hidden="true">
      <path d="M8 2.25 1.75 13.25h12.5z" stroke="currentColor" strokeWidth="1.5" strokeLinejoin="round" />
      <path d="M8 6.5v3M8 11.5h.01" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" />
    </svg>
  ),
  Check: () => (
    <svg className="org-icon" width="20" height="20" viewBox="0 0 16 16" fill="none" aria-hidden="true">
      <circle cx="8" cy="8" r="6.25" stroke="currentColor" strokeWidth="1.5" />
      <path d="m5.25 8.25 1.9 1.9 3.6-3.9" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round" />
    </svg>
  ),
}

function OrgAvatar({ org }) {
  const [failed, setFailed] = useState(false)
  if (failed) return <span className="org-avatar org-avatar--fallback" aria-hidden="true">{org.slice(0, 1).toUpperCase()}</span>
  return (
    <img
      className="org-avatar"
      src={`https://github.com/${encodeURIComponent(org)}.png?size=88`}
      alt=""
      width="44"
      height="44"
      onError={() => setFailed(true)}
    />
  )
}

function SkeletonRows({ rows = 6 }) {
  return (
    <div className="org-skeleton" aria-hidden="true">
      {Array.from({ length: rows }, (_, i) => (
        <div key={i} className="org-skeleton-row">
          <span className="org-skeleton-bar" style={{ width: `${38 + ((i * 17) % 34)}%` }} />
          <span className="org-skeleton-bar org-skeleton-bar--short" />
        </div>
      ))}
    </div>
  )
}

function EmptyState({ title, children, action, tone = 'neutral' }) {
  return (
    <div className={`org-empty org-empty--${tone}`}>
      {tone === 'good' && <span className="org-empty-icon"><Icon.Check /></span>}
      <p className="org-empty-title">{title}</p>
      {children && <p className="org-empty-body">{children}</p>}
      {action}
    </div>
  )
}

function ExtLink({ href, children, className = '', title }) {
  if (!href) return <span className={className}>{children}</span>
  return (
    <a className={`org-ext ${className}`} href={href} target="_blank" rel="noopener noreferrer" title={title} onClick={(e) => e.stopPropagation()}>
      {children}
      <Icon.External />
    </a>
  )
}

function SevDot({ severity }) {
  return <span className={`org-sev-dot org-sev--${severity}`} aria-hidden="true" />
}

function SevPill({ severity }) {
  return (
    <span className={`org-sev-pill org-sev--${severity}`}>
      <SevDot severity={severity} />
      {severity}
    </span>
  )
}

/* ------------------------------------------------------------------ */
/* Repository picker                                                   */
/* ------------------------------------------------------------------ */

function OrgRepoPicker({ picker, onScan, disabled }) {
  const { org, repositories = [], maxSelectable = 200 } = picker
  const [query, setQuery] = useState('')
  const [showArchived, setShowArchived] = useState(false)
  const [showForks, setShowForks] = useState(false)
  const [selected, setSelected] = useState(() => defaultSelection(repositories, maxSelectable))

  const visible = useMemo(() => {
    const q = query.trim().toLowerCase()
    return repositories.filter(r =>
      (showArchived || !r.archived) &&
      (showForks || !r.fork) &&
      (!q || r.name.toLowerCase().includes(q) || (r.description || '').toLowerCase().includes(q))
    )
  }, [repositories, query, showArchived, showForks])

  const hiddenSelected = [...selected].filter(n => !visible.some(r => r.full_name === n)).length
  const allVisibleSelected = visible.length > 0 && visible.every(r => selected.has(r.full_name))
  const overLimit = selected.size > maxSelectable

  const toggle = (name) => setSelected(prev => {
    const next = new Set(prev)
    if (next.has(name)) next.delete(name)
    else next.add(name)
    return next
  })

  const toggleVisible = () => setSelected(prev => {
    const next = new Set(prev)
    visible.forEach(r => (allVisibleSelected ? next.delete(r.full_name) : next.add(r.full_name)))
    return next
  })

  const archivedCount = repositories.filter(r => r.archived).length
  const forkCount = repositories.filter(r => r.fork).length

  return (
    <section className="org-panel">
      <header className="org-hero">
        <OrgAvatar org={org} />
        <div className="org-hero-text">
          <p className="org-eyebrow">Choose repositories</p>
          <h2 className="org-title">{org}</h2>
          <p className="org-sub">
            {plural(repositories.length, 'repository', 'repositories')}. Each one you pick is audited on its own and rolled up here.
          </p>
        </div>
        <div className="org-hero-actions">
          <button
            type="button"
            className="org-btn org-btn--primary"
            disabled={disabled || selected.size === 0 || overLimit}
            onClick={() => onScan([...selected])}
          >
            Scan {plural(selected.size, 'repository', 'repositories')}
            <Icon.Arrow />
          </button>
        </div>
      </header>

      <div className="org-toolbar">
        <label className="org-search">
          <Icon.Search />
          <input
            type="search"
            placeholder="Filter by name or description"
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            aria-label="Filter repositories"
          />
        </label>
        <div className="org-toggle-group" role="group" aria-label="Include">
          <button type="button" className={`org-chip ${showForks ? 'is-on' : ''}`} aria-pressed={showForks} onClick={() => setShowForks(v => !v)}>
            Forks <span className="org-chip-count">{forkCount}</span>
          </button>
          <button type="button" className={`org-chip ${showArchived ? 'is-on' : ''}`} aria-pressed={showArchived} onClick={() => setShowArchived(v => !v)}>
            Archived <span className="org-chip-count">{archivedCount}</span>
          </button>
        </div>
        <span className="org-toolbar-spacer" />
        <button type="button" className="org-link" onClick={toggleVisible} disabled={visible.length === 0}>
          {allVisibleSelected ? 'Deselect shown' : 'Select shown'}
        </button>
        <button type="button" className="org-link" onClick={() => setSelected(new Set())} disabled={selected.size === 0}>
          Clear
        </button>
      </div>

      {(overLimit || hiddenSelected > 0) && (
        <p className={`org-callout ${overLimit ? 'is-error' : ''}`} role={overLimit ? 'alert' : undefined}>
          {overLimit
            ? `Select at most ${maxSelectable} repositories per scan (${selected.size} selected).`
            : `${plural(hiddenSelected, 'selected repository is', 'selected repositories are')} hidden by the filters and will still be scanned.`}
        </p>
      )}

      {visible.length === 0 ? (
        <EmptyState title="No repositories match">
          Try another name, or include forks and archived repositories.
        </EmptyState>
      ) : (
        <ul className="org-repo-list" aria-label="Repositories">
          {visible.map((repo, i) => (
            <li key={repo.full_name} className="org-enter" style={stagger(i)}>
              <label className={`org-repo ${selected.has(repo.full_name) ? 'is-selected' : ''}`}>
                <input
                  type="checkbox"
                  className="org-checkbox"
                  checked={selected.has(repo.full_name)}
                  onChange={() => toggle(repo.full_name)}
                />
                <span className="org-repo-main">
                  <span className="org-repo-name">
                    {repo.name}
                    {repo.private && <span className="org-tag">Private</span>}
                    {repo.fork && <span className="org-tag">Fork</span>}
                    {repo.archived && <span className="org-tag is-warn">Archived</span>}
                  </span>
                  {repo.description && <span className="org-repo-desc">{repo.description}</span>}
                </span>
                <span className="org-repo-meta">
                  {repo.language && <span>{repo.language}</span>}
                  <span className="org-num">{relativeTime(repo.pushed_at)}</span>
                </span>
              </label>
            </li>
          ))}
        </ul>
      )}
    </section>
  )
}

/* ------------------------------------------------------------------ */
/* Summary                                                             */
/* ------------------------------------------------------------------ */

function SeverityBar({ counts = {} }) {
  const present = SEVERITIES.filter(sev => counts[sev])
  if (present.length === 0) {
    return (
      <span className="org-sev org-sev--none">
        <span className="org-sev-dot" aria-hidden="true" />
        <span className="org-sev-label">No findings</span>
      </span>
    )
  }
  return (
    <div className="org-sevbar-wrap">
      {/* A bar only says something when it shows a split. */}
      {present.length > 1 && (
        <div className="org-sevbar" aria-hidden="true">
          {present.map(sev => (
            <span key={sev} className={`org-sevbar-seg org-sev--${sev}`} style={{ flexGrow: counts[sev] }} />
          ))}
        </div>
      )}
      <div className="org-sevbar-legend">
        {present.map(sev => (
          <span key={sev} className={`org-sev org-sev--${sev}`}>
            <SevDot severity={sev} />
            <span className="org-sev-num">{counts[sev]}</span>
            <span className="org-sev-label">{sev}</span>
          </span>
        ))}
      </div>
    </div>
  )
}

function MetricStrip({ stats, repoCount, actionCount }) {
  const failed = (stats.failed_repositories ?? 0) + (stats.skipped_repositories ?? 0)
  return (
    <div className="org-metrics">
      <div className="org-metric org-metric--lead">
        <span className="org-metric-label">Findings</span>
        <span className="org-metric-value">{stats.total_issues ?? 0}</span>
        <SeverityBar counts={stats.severity_counts} />
        {stats.dismissed_issues ? <span className="org-metric-note">{stats.dismissed_issues} dismissed</span> : null}
      </div>
      <div className="org-metric">
        <span className="org-metric-label">Repos with findings</span>
        <span className="org-metric-value">
          {stats.repositories_with_issues ?? 0}
          <span className="org-metric-of">/{stats.total_repositories ?? repoCount}</span>
        </span>
      </div>
      <div className="org-metric">
        <span className="org-metric-label">Distinct actions</span>
        <span className="org-metric-value">{actionCount}</span>
      </div>
      <div className={`org-metric ${failed > 0 ? 'is-warn' : ''}`}>
        <span className="org-metric-label">Failed or skipped</span>
        <span className="org-metric-value">{failed}</span>
      </div>
    </div>
  )
}

/* ------------------------------------------------------------------ */
/* Repositories tab                                                    */
/* ------------------------------------------------------------------ */

function riskKey(result) {
  const c = result.statistics?.severity_counts || {}
  return [c.critical || 0, c.high || 0, c.medium || 0, c.low || 0]
}

function compareRisk(a, b) {
  const ka = riskKey(a)
  const kb = riskKey(b)
  for (let i = 0; i < ka.length; i += 1) {
    if (ka[i] !== kb[i]) return kb[i] - ka[i]
  }
  return a.repository.localeCompare(b.repository)
}

function RepositoriesTab({ repos, onOpenRepository, onShowFindings }) {
  return (
    <div className="org-table-wrap">
      <table className="org-table org-table--repos">
        <colgroup>
          <col />
          <col className="org-col-status" />
          <col className="org-col-num org-cell-wf" />
          {SEVERITIES.map(sev => <col key={sev} className="org-col-sev" />)}
          <col className="org-col-action" />
        </colgroup>
        <thead>
          <tr>
            <th>Repository</th>
            <th>Status</th>
            <th className="num org-cell-wf">Workflows</th>
            {SEVERITIES.map(sev => (
              <th key={sev} className="num" title={sev}>
                <SevDot severity={sev} />
                <span className="org-th-sev">{SEVERITY_SHORT[sev]}</span>
              </th>
            ))}
            <th><span className="visually-hidden">Open</span></th>
          </tr>
        </thead>
        <tbody>
          {repos.map((r, i) => {
            const openable = r.status === 'ok' && r.analysis_id
            const counts = r.statistics?.severity_counts || {}
            const scanned = r.status === 'ok' || r.status === 'no_workflows'
            return (
              <tr
                key={r.repository}
                className={`org-enter ${openable ? 'is-openable' : ''}`}
                style={stagger(i)}
                onClick={openable ? () => onOpenRepository(r) : undefined}
              >
                <td className="org-cell-repo" title={r.repository}>
                  <span className="org-mono org-truncate">{repoName(r.repository)}</span>
                </td>
                <td className="org-cell-status">
                  <span className={`org-status org-status--${r.status}`}>
                    {(r.status === 'pending' || r.status === 'running') && (
                      <span className={`org-status-icon org-status-icon--${r.status}`} aria-hidden="true" />
                    )}
                    {STATUS_LABELS[r.status] || r.status}
                  </span>
                  {r.error && (
                    <span className="org-error-text org-truncate" title={r.error}>
                      {summarizeError(r.error)}
                    </span>
                  )}
                </td>
                <td className="num org-num org-cell-wf">{r.status === 'pending' || r.status === 'running' ? '' : r.workflows}</td>
                {SEVERITIES.map(sev => (
                  <td key={sev} className={`num org-num org-sev-cell ${counts[sev] ? `has-${sev}` : ''}`}>
                    {scanned ? (counts[sev] || <span className="org-zero">–</span>) : ''}
                  </td>
                ))}
                <td className="org-row-action">
                  {openable && (
                    <span className="org-row-actions">
                      {onShowFindings && (r.statistics?.total_issues ?? 0) > 0 && (
                        <button
                          type="button"
                          className="org-link org-link--quiet"
                          onClick={(e) => { e.stopPropagation(); onShowFindings({ repository: r.repository, mode: 'rule' }) }}
                        >
                          Findings
                        </button>
                      )}
                      <button
                        type="button"
                        className="org-link"
                        onClick={(e) => { e.stopPropagation(); onOpenRepository(r) }}
                        aria-label={`Open graph for ${r.repository}`}
                      >
                        <span className="org-link-text">Graph</span>
                        <Icon.Arrow />
                      </button>
                    </span>
                  )}
                </td>
              </tr>
            )
          })}
        </tbody>
      </table>
    </div>
  )
}

/* ------------------------------------------------------------------ */
/* Findings tab                                                        */
/* ------------------------------------------------------------------ */

function worstSeverity(items) {
  return items.reduce((worst, f) => (SEVERITY_RANK[f.severity] < SEVERITY_RANK[worst] ? f.severity : worst), 'low')
}

function FindingRow({ finding, showRepository, showRule, onOpen, active }) {
  const { location, target } = finding
  return (
    <li
      className={`org-finding ${finding.dismissed ? 'is-dismissed' : ''} ${onOpen ? 'is-openable' : ''} ${active ? 'is-active' : ''}`}
      onClick={onOpen ? () => onOpen(finding) : undefined}
    >
      <SevPill severity={finding.severity} />
      <div className="org-finding-body">
        {showRule && <p className="org-finding-rule">{ruleTitle(finding.type)}</p>}
        {onOpen ? (
          <button
            type="button"
            className="org-finding-message org-finding-open"
            onClick={(e) => { e.stopPropagation(); onOpen(finding) }}
            title="Open details"
          >
            {finding.message}
          </button>
        ) : (
          <p className="org-finding-message">{finding.message}</p>
        )}
        <div className="org-finding-refs">
          {showRepository && <span className="org-ref org-ref--repo">{repoName(finding.repository)}</span>}
          {location?.url && (
            <ExtLink href={location.url} className="org-ref org-ref--file" title="Open on GitHub">
              <Icon.File />
              <span className="org-mono">{location.path || location.label}{location.line ? `:${location.line}` : ''}</span>
            </ExtLink>
          )}
          {target && (
            <ExtLink href={target.url} className="org-ref org-ref--target" title={target.url ? 'Open the action at this ref' : undefined}>
              <span className="org-ref-prefix">via</span>
              <span className="org-mono org-truncate">{target.label}</span>
            </ExtLink>
          )}
          {finding.job && <span className="org-ref">job <span className="org-mono">{finding.job}</span></span>}
          {finding.dismissed && <span className="org-tag">Dismissed</span>}
        </div>
      </div>
      <span className="org-finding-actions">
        {onOpen && (
          <button
            type="button"
            className="org-docs"
            onClick={(e) => { e.stopPropagation(); onOpen(finding, { inGraph: true }) }}
            title={`Open ${repoName(finding.repository)} graph at this finding`}
          >
            <Icon.Graph />
            <span className="org-link-text">Graph</span>
          </button>
        )}
        {finding.docs_url && showRule && (
          <a className="org-docs" href={finding.docs_url} target="_blank" rel="noopener noreferrer" title="How to fix this on actsense.dev" onClick={(e) => e.stopPropagation()}>
            <Icon.Book />
            <span className="org-link-text">Fix</span>
          </a>
        )}
      </span>
    </li>
  )
}

function FindingGroup({ group, mode, index, defaultOpen, onOpenFinding, activeFingerprint }) {
  const [open, setOpen] = useState(defaultOpen)
  const [limit, setLimit] = useState(GROUP_PAGE)
  const repoCount = new Set(group.items.map(f => f.repository)).size
  const ruleCount = new Set(group.items.map(f => f.type)).size
  const docs = mode === 'rule' ? group.items[0]?.docs_url : null
  const counts = group.items.reduce((acc, f) => ({ ...acc, [f.severity]: (acc[f.severity] || 0) + 1 }), {})

  return (
    <li className="org-group org-enter" style={stagger(index)}>
      <div className="org-group-head">
        <button type="button" className="org-group-toggle" aria-expanded={open} onClick={() => setOpen(v => !v)}>
          <Icon.Chevron open={open} />
          <SevDot severity={worstSeverity(group.items)} />
          <span className="org-group-title">{mode === 'rule' ? ruleTitle(group.key) : repoName(group.key)}</span>
          <span className="org-group-meta">
            {mode === 'rule' ? plural(repoCount, 'repo') : plural(ruleCount, 'rule')}
          </span>
        </button>
        <span className="org-group-counts">
          {SEVERITIES.filter(s => counts[s]).map(s => (
            <span key={s} className={`org-group-count org-sev--${s}`} title={`${counts[s]} ${s}`}>
              <SevDot severity={s} />
              <span className="org-num">{counts[s]}</span>
            </span>
          ))}
        </span>
        {docs && (
          <a className="org-docs" href={docs} target="_blank" rel="noopener noreferrer" title="Read about this rule on actsense.dev">
            <Icon.Book />
            <span className="org-link-text">Docs</span>
          </a>
        )}
      </div>
      {open && (
        <ul className="org-findings">
          {group.items.slice(0, limit).map((f, i) => (
            <FindingRow
              key={`${f.repository}:${f.fingerprint || i}`}
              finding={f}
              showRepository={mode === 'rule'}
              showRule={mode !== 'rule'}
              onOpen={onOpenFinding}
              active={Boolean(activeFingerprint) && f.fingerprint === activeFingerprint}
            />
          ))}
          {group.items.length > limit && (
            <li className="org-more">
              <button type="button" className="org-link" onClick={() => setLimit(l => l + GROUP_PAGE)}>
                Show {Math.min(GROUP_PAGE, group.items.length - limit)} more of {group.items.length - limit}
              </button>
            </li>
          )}
        </ul>
      )}
    </li>
  )
}

function FindingsTab({ state, filter, onFilterChange, onRetry, onOpenFinding, activeFingerprint }) {
  const { findings, loading, error } = state
  const { query, severities, mode, showDismissed, repository, action } = filter
  const onAction = (f) => !action || (f.node?.type === 'action' && f.node.id.startsWith(`${action}@`))

  const dismissedCount = useMemo(() => (findings || []).filter(f => f.dismissed).length, [findings])

  const filtered = useMemo(() => {
    const q = query.trim().toLowerCase()
    return (findings || []).filter(f =>
      (showDismissed || !f.dismissed) &&
      (severities.size === 0 || severities.has(f.severity)) &&
      (!repository || f.repository === repository) &&
      onAction(f) &&
      (!q || [f.message, f.type, ruleTitle(f.type), f.repository, f.location?.path, f.target?.label, f.node?.label]
        .some(v => v && String(v).toLowerCase().includes(q)))
    )
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [findings, query, severities, showDismissed, repository, action])

  const severityCounts = useMemo(() => {
    const counts = {}
    ;(findings || []).forEach(f => {
      if ((showDismissed || !f.dismissed) && (!repository || f.repository === repository) && onAction(f)) {
        counts[f.severity] = (counts[f.severity] || 0) + 1
      }
    })
    return counts
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [findings, showDismissed, repository, action])

  const groups = useMemo(() => {
    const map = new Map()
    filtered.forEach(f => {
      const key = mode === 'rule' ? f.type : f.repository
      if (!map.has(key)) map.set(key, [])
      map.get(key).push(f)
    })
    return [...map.entries()]
      .map(([key, items]) => ({
        key,
        items: items.sort((a, b) => SEVERITY_RANK[a.severity] - SEVERITY_RANK[b.severity] || a.repository.localeCompare(b.repository)),
      }))
      .sort((a, b) => SEVERITY_RANK[worstSeverity(a.items)] - SEVERITY_RANK[worstSeverity(b.items)] || b.items.length - a.items.length)
  }, [filtered, mode])

  const set = (patch) => onFilterChange({ ...filter, ...patch })
  const clear = () => set({ query: '', severities: new Set(), repository: null, action: null })
  const toggleSeverity = (sev) => {
    const next = new Set(severities)
    if (next.has(sev)) next.delete(sev)
    else next.add(sev)
    set({ severities: next })
  }
  const hasFilters = Boolean(query || severities.size > 0 || repository || action)

  if (loading) return <SkeletonRows rows={7} />
  if (error) {
    return (
      <EmptyState title="Could not load findings" tone="error" action={<button type="button" className="org-btn" onClick={onRetry}>Try again</button>}>
        {error}
      </EmptyState>
    )
  }
  if (!findings) return null
  if (findings.length === 0) {
    return (
      <EmptyState title="No findings across this organization" tone="good">
        Every scanned workflow passed. Repositories that failed or were skipped are not included.
      </EmptyState>
    )
  }

  return (
    <div className="org-findings-tab">
      <div className="org-toolbar">
        <label className="org-search">
          <Icon.Search />
          <input
            type="search"
            placeholder="Search message, rule, repo, file or action"
            value={query}
            onChange={(e) => set({ query: e.target.value })}
            aria-label="Search findings"
          />
        </label>
        <div className="org-toggle-group" role="group" aria-label="Severity">
          {SEVERITIES.filter(s => severityCounts[s]).map(s => (
            <button
              key={s}
              type="button"
              className={`org-chip ${severities.has(s) ? 'is-on' : ''}`}
              aria-pressed={severities.has(s)}
              onClick={() => toggleSeverity(s)}
            >
              <SevDot severity={s} />
              {SEVERITY_SHORT[s]}
              <span className="org-chip-count">{severityCounts[s]}</span>
            </button>
          ))}
        </div>
        <span className="org-toolbar-spacer" />
        <div className="org-segmented" role="radiogroup" aria-label="Group by">
          {[['rule', 'By rule'], ['repository', 'By repo']].map(([value, label]) => (
            <button
              key={value}
              type="button"
              role="radio"
              aria-checked={mode === value}
              className={`org-segment ${mode === value ? 'is-active' : ''}`}
              onClick={() => set({ mode: value })}
            >
              {label}
            </button>
          ))}
        </div>
      </div>

      <div className="org-filter-line">
        <span><span className="org-num org-strong">{filtered.length}</span> <span className="org-dim">{filtered.length === 1 ? 'finding' : 'findings'} in {plural(groups.length, mode === 'rule' ? 'rule' : 'repository', mode === 'rule' ? 'rules' : 'repositories')}</span></span>
        {action && (
          <button type="button" className="org-filter-pill" onClick={() => set({ action: null })}>
            <span className="org-dim-inherit">Action</span>
            <span className="org-mono">{action}</span>
            <span aria-hidden="true">×</span>
            <span className="visually-hidden">Remove action filter</span>
          </button>
        )}
        {repository && (
          <button type="button" className="org-filter-pill" onClick={() => set({ repository: null })}>
            <span className="org-mono">{repoName(repository)}</span>
            <span aria-hidden="true">×</span>
            <span className="visually-hidden">Remove repository filter</span>
          </button>
        )}
        <span className="org-toolbar-spacer" />
        {dismissedCount > 0 && (
          <label className="org-check">
            <input type="checkbox" className="org-checkbox" checked={showDismissed} onChange={(e) => set({ showDismissed: e.target.checked })} />
            Show {dismissedCount} dismissed
          </label>
        )}
        {hasFilters && <button type="button" className="org-link" onClick={clear}>Clear filters</button>}
      </div>

      {groups.length === 0 ? (
        <EmptyState
          title="No findings match these filters"
          action={<button type="button" className="org-btn" onClick={clear}>Clear filters</button>}
        />
      ) : (
        <ul className="org-groups" key={`${mode}:${repository || ''}:${action || ''}`}>
          {groups.map((g, i) => (
            <FindingGroup
              key={g.key}
              group={g}
              mode={mode}
              index={i}
              defaultOpen={i === 0 || Boolean(query) || groups.length <= 3}
              onOpenFinding={onOpenFinding}
              activeFingerprint={activeFingerprint}
            />
          ))}
        </ul>
      )}
    </div>
  )
}

/* ------------------------------------------------------------------ */
/* Action inventory tab                                                */
/* ------------------------------------------------------------------ */

const INVENTORY_FILTERS = [
  ['third', 'Third party', a => !a.trusted],
  ['unpinned', 'Not SHA pinned', a => a.pinning !== 'sha'],
  ['inconsistent', 'Several refs', a => a.refs.length > 1],
]

function actionHomeUrl(action) {
  const [owner, repo] = action.split('/')
  return owner && repo ? `https://github.com/${owner}/${repo}` : null
}

function InventoryTab({ org, inventory: rawInventory, findings, onShowFindings }) {
  const inventory = useMemo(() => rawInventory.map(a => {
    const internal = a.internal ?? a.action.toLowerCase().startsWith(`${org.toLowerCase()}/`)
    return { ...a, internal, trusted: a.trusted || internal }
  }), [rawInventory, org])
  const [query, setQuery] = useState('')
  const [only, setOnly] = useState(new Set())
  const [expanded, setExpanded] = useState(null)

  const findingCounts = useMemo(() => {
    const counts = {}
    ;(findings || []).forEach(f => {
      if (f.dismissed || f.node?.type !== 'action' || !f.node.id.includes('@')) return
      const name = f.node.id.slice(0, f.node.id.lastIndexOf('@'))
      counts[name] = (counts[name] || 0) + 1
    })
    return counts
  }, [findings])

  const visible = useMemo(() => {
    const q = query.trim().toLowerCase()
    return inventory.filter(a =>
      (!q || a.action.toLowerCase().includes(q) || a.repositories.some(r => r.toLowerCase().includes(q))) &&
      INVENTORY_FILTERS.every(([key, , test]) => !only.has(key) || test(a))
    )
  }, [inventory, query, only])

  const toggle = (key) => setOnly(prev => {
    const next = new Set(prev)
    if (next.has(key)) next.delete(key)
    else next.add(key)
    return next
  })

  if (inventory.length === 0) {
    return (
      <EmptyState title="No actions found">
        None of the scanned workflows reference an action with <code>uses:</code>.
      </EmptyState>
    )
  }

  return (
    <div>
      <div className="org-toolbar">
        <label className="org-search">
          <Icon.Search />
          <input type="search" placeholder="Search actions or repositories" value={query} onChange={(e) => setQuery(e.target.value)} aria-label="Search actions" />
        </label>
        <div className="org-toggle-group" role="group" aria-label="Show only">
          {INVENTORY_FILTERS.map(([key, label, test]) => (
            <button key={key} type="button" className={`org-chip ${only.has(key) ? 'is-on' : ''}`} aria-pressed={only.has(key)} onClick={() => toggle(key)}>
              {label}
              <span className="org-chip-count">{inventory.filter(test).length}</span>
            </button>
          ))}
        </div>
      </div>

      {visible.length === 0 ? (
        <EmptyState title="No actions match" action={<button type="button" className="org-btn" onClick={() => { setQuery(''); setOnly(new Set()) }}>Clear filters</button>} />
      ) : (
        <ul className="org-groups">
          {visible.map((a, i) => {
            const isOpen = expanded === a.action
            const issues = findingCounts[a.action] || 0
            return (
              <li key={a.action} className="org-group org-enter" style={stagger(i)}>
                <div className="org-group-head">
                  <button type="button" className="org-group-toggle" aria-expanded={isOpen} onClick={() => setExpanded(isOpen ? null : a.action)}>
                    <Icon.Chevron open={isOpen} />
                    <span className="org-mono org-group-title org-truncate">{a.action}</span>
                  </button>
                  <span className="org-action-tags">
                    <span className={`org-tag ${a.trusted ? '' : 'is-warn'}`}>{a.internal ? 'Internal' : a.trusted ? 'Trusted' : 'Third party'}</span>
                    <span className={`org-tag ${a.pinning === 'sha' ? 'is-ok' : 'is-warn'}`}>
                      {a.pinning === 'sha' ? 'SHA pinned' : a.pinning === 'tag' ? 'Tag or branch' : 'Mixed pinning'}
                    </span>
                  </span>
                  <span className="org-action-stats">
                    <span className="org-num">{plural(a.repository_count, 'repo')}</span>
                    <span className={`org-num ${a.refs.length > 1 ? 'org-warn-text' : ''}`}>{plural(a.refs.length, 'ref')}</span>
                    {issues > 0 && (
                      <button type="button" className="org-link" onClick={() => onShowFindings({ action: a.action })}>
                        {plural(issues, 'finding')}
                      </button>
                    )}
                  </span>
                </div>
                {isOpen && (
                  <div className="org-action-body">
                    <ul className="org-refs">
                      {a.refs.map(ref => (
                        <li key={ref.ref} className="org-ref-block">
                          <div className="org-ref-head">
                            <code className="org-mono org-ref-name">@{ref.ref}</code>
                            <span className={`org-tag ${ref.pinning === 'sha' ? 'is-ok' : 'is-warn'}`}>{ref.pinning === 'sha' ? 'SHA' : 'Tag or branch'}</span>
                            <span className="org-dim org-num">{plural(ref.repositories.length, 'repo')}</span>
                          </div>
                          {ref.usages?.length ? (
                            <ul className="org-usages">
                              {ref.usages.map((u, j) => (
                                <li key={`${u.repository}:${u.path}:${u.line ?? j}`}>
                                  <span className="org-ref org-ref--repo">{repoName(u.repository)}</span>
                                  <ExtLink href={u.url} className="org-ref org-ref--file" title="Open on GitHub">
                                    <Icon.File />
                                    <span className="org-mono">{u.path}{u.line ? `:${u.line}` : ''}</span>
                                  </ExtLink>
                                </li>
                              ))}
                            </ul>
                          ) : (
                            <p className="org-usages-fallback">
                              {ref.repositories.map(repoName).join(', ')}
                              <span className="org-dim"> · scan again to see file and line references</span>
                            </p>
                          )}
                        </li>
                      ))}
                    </ul>
                    <ExtLink href={actionHomeUrl(a.action)} className="org-ref">View {a.action.split('/').slice(0, 2).join('/')} on GitHub</ExtLink>
                  </div>
                )}
              </li>
            )
          })}
        </ul>
      )}
    </div>
  )
}

/* ------------------------------------------------------------------ */
/* Scan results                                                        */
/* ------------------------------------------------------------------ */

const EMPTY_FILTER = { query: '', severities: new Set(), mode: 'rule', showDismissed: false, repository: null, action: null }

function useOrgFindings(scanId, enabled, refreshKey) {
  const [state, setState] = useState({ findings: null, loading: false, error: null })
  const [attempt, setAttempt] = useState(0)

  useEffect(() => {
    if (!scanId || !enabled) return undefined
    const controller = new AbortController()
    setState(s => ({ ...s, loading: s.findings === null, error: null }))
    fetch(`/api/org-scans/${encodeURIComponent(scanId)}/findings`, { signal: controller.signal })
      .then(r => (r.ok ? r.json() : r.json().then(b => Promise.reject(new Error(b.detail || 'Request failed')))))
      .then(body => setState({ findings: body.findings || [], loading: false, error: null }))
      .catch(err => {
        if (err.name !== 'AbortError') setState({ findings: null, loading: false, error: err.message })
      })
    return () => controller.abort()
  }, [scanId, enabled, attempt, refreshKey])

  return [state, () => setAttempt(a => a + 1)]
}

function OrgScanResults({ scan, running, progress, onOpenRepository, onCancel, onRescan, onOpenFinding, activeFingerprint, refreshKey }) {
  const [tab, setTab] = useState('repositories')
  const [copied, setCopied] = useState(false)
  const [filter, setFilter] = useState(EMPTY_FILTER)
  const stats = scan.statistics || {}
  const repos = useMemo(
    // Rows keep their place while results stream in, then sort by risk.
    () => (running ? scan.repositories || [] : [...(scan.repositories || [])].sort(compareRisk)),
    [scan.repositories, running],
  )
  const inventory = scan.action_inventory || []
  const completed = progress?.completed ?? repos.filter(r => r.status !== 'pending' && r.status !== 'running').length
  const total = progress?.total ?? repos.length
  // refreshKey changes when a finding is dismissed or restored in the side panel.
  const [findingsState, retryFindings] = useOrgFindings(scan.id, !running && tab !== 'repositories', refreshKey)

  const showFindings = (patch) => {
    setFilter({ ...EMPTY_FILTER, ...patch })
    setTab('findings')
  }

  const copyLink = async () => {
    const url = new URL(window.location.href)
    url.search = ''
    url.searchParams.set('org-scan', scan.id)
    try {
      await navigator.clipboard.writeText(url.toString())
      setCopied(true)
      setTimeout(() => setCopied(false), 1500)
    } catch {
      // clipboard unavailable; nothing to do
    }
  }

  const tabs = [
    ['repositories', 'Repositories', repos.length],
    ['findings', 'Findings', stats.total_issues ?? 0],
    ['actions', 'Action inventory', inventory.length],
  ]

  return (
    <section className="org-panel">
      <header className="org-hero">
        <OrgAvatar org={scan.org} />
        <div className="org-hero-text">
          <p className="org-eyebrow">Organization scan</p>
          <h2 className="org-title">{scan.org}</h2>
          <p className="org-sub">
            {running
              ? <>Scanning <span className="org-num">{completed}</span> of <span className="org-num">{total}</span> repositories</>
              : <>
                  <span className="org-num">{stats.scanned_repositories ?? 0}</span> of <span className="org-num">{stats.total_repositories ?? repos.length}</span> repositories scanned
                  {scan.timestamp && <span className="org-dim"> · {new Date(scan.timestamp).toLocaleString()}</span>}
                </>}
          </p>
        </div>
        <div className="org-hero-actions">
          {running ? (
            <button type="button" className="org-btn" onClick={onCancel}>Cancel</button>
          ) : (
            <>
              {scan.id && (
                <button type="button" className="org-btn" onClick={copyLink} aria-live="polite">
                  {copied ? 'Link copied' : 'Copy link'}
                </button>
              )}
              {onRescan && <button type="button" className="org-btn" onClick={onRescan}>Choose repositories</button>}
            </>
          )}
        </div>
      </header>

      {running && (
        <div className="org-progress" role="progressbar" aria-valuemin={0} aria-valuemax={total} aria-valuenow={completed}>
          <div className="org-progress-fill" style={{ transform: `scaleX(${total ? completed / total : 0})` }} />
        </div>
      )}

      {scan.error && (
        <p className="org-callout is-error" role="alert"><Icon.Warning /><span>{scan.error}</span></p>
      )}
      {scan.rate_limited && (
        <p className="org-callout is-warn" role="alert">
          <Icon.Warning />
          <span>
            <strong>GitHub rate limit reached.</strong> Repositories after that point were skipped. Add a token and choose them again to finish the scan.
          </span>
        </p>
      )}

      {!running && <MetricStrip stats={stats} repoCount={repos.length} actionCount={inventory.length} />}

      <div className="org-tabs" role="tablist" aria-label="Scan views">
        {tabs.map(([key, label, count]) => (
          <button
            key={key}
            type="button"
            role="tab"
            aria-selected={tab === key}
            className={`org-tab ${tab === key ? 'is-active' : ''}`}
            onClick={() => setTab(key)}
            disabled={running && key !== 'repositories'}
          >
            {label}
            <span className="org-count org-num">{count}</span>
          </button>
        ))}
      </div>

      <div className="org-tabpanel" role="tabpanel">
        {tab === 'repositories' && (
          <RepositoriesTab repos={repos} onOpenRepository={onOpenRepository} onShowFindings={scan.id && !running ? showFindings : null} />
        )}
        {tab === 'findings' && (
          <FindingsTab
            state={findingsState}
            filter={filter}
            onFilterChange={setFilter}
            onRetry={retryFindings}
            onOpenFinding={scan.id ? onOpenFinding : null}
            activeFingerprint={activeFingerprint}
          />
        )}
        {tab === 'actions' && (
          <InventoryTab org={scan.org} inventory={inventory} findings={findingsState.findings} onShowFindings={showFindings} />
        )}
      </div>
    </section>
  )
}

/* ------------------------------------------------------------------ */
/* Workspace                                                           */
/* ------------------------------------------------------------------ */

function OrgWorkspace({ picker, scan, running, progress, onScan, onOpenRepository, onCancel, onChooseRepositories, onOpenFinding, activeFingerprint, refreshKey }) {
  if (scan) {
    return (
      <div className="org-workspace">
        <OrgScanResults
          scan={scan}
          running={running}
          progress={progress}
          onOpenRepository={onOpenRepository}
          onCancel={onCancel}
          onRescan={onChooseRepositories}
          onOpenFinding={onOpenFinding}
          activeFingerprint={activeFingerprint}
          refreshKey={refreshKey}
        />
      </div>
    )
  }
  if (!picker) return null
  return (
    <div className="org-workspace">
      {picker.loading ? (
        <section className="org-panel" aria-busy="true">
          <header className="org-hero">
            <span className="org-avatar org-skeleton-bar" />
            <div className="org-hero-text">
              <p className="org-eyebrow">Loading repositories</p>
              <h2 className="org-title">{picker.org}</h2>
            </div>
          </header>
          <SkeletonRows rows={8} />
        </section>
      ) : picker.error ? (
        <section className="org-panel">
          <EmptyState title={`Could not load ${picker.org}`} tone="error">{picker.error}</EmptyState>
        </section>
      ) : (
        <OrgRepoPicker key={picker.org} picker={picker} onScan={onScan} disabled={running} />
      )}
    </div>
  )
}

export default OrgWorkspace
