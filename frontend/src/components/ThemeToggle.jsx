import React from 'react'
import { getThemePreference, setThemePreference, useThemePreference } from '../theme'
import './ThemeToggle.css'

// Cycles System → Light → Dark. The icon shows the current choice.
const ORDER = ['system', 'light', 'dark']
const LABELS = { system: 'System theme', light: 'Light theme', dark: 'Dark theme' }
const nextAfter = (preference) => ORDER[(ORDER.indexOf(preference) + 1) % ORDER.length]

const ICONS = {
  system: (
    <svg width="16" height="16" viewBox="0 0 16 16" fill="none" aria-hidden="true">
      <rect x="1.75" y="2.75" width="12.5" height="8.5" rx="1.5" stroke="currentColor" strokeWidth="1.4" />
      <path d="M5.5 14h5M8 11.25V14" stroke="currentColor" strokeWidth="1.4" strokeLinecap="round" />
    </svg>
  ),
  light: (
    <svg width="16" height="16" viewBox="0 0 16 16" fill="none" aria-hidden="true">
      <circle cx="8" cy="8" r="3" stroke="currentColor" strokeWidth="1.4" />
      <path d="M8 1.5v1.5M8 13v1.5M1.5 8H3M13 8h1.5M3.4 3.4l1.06 1.06M11.54 11.54l1.06 1.06M3.4 12.6l1.06-1.06M11.54 4.46l1.06-1.06" stroke="currentColor" strokeWidth="1.4" strokeLinecap="round" />
    </svg>
  ),
  dark: (
    <svg width="16" height="16" viewBox="0 0 16 16" fill="none" aria-hidden="true">
      <path d="M13.5 9.6A5.75 5.75 0 0 1 6.4 2.5a5.75 5.75 0 1 0 7.1 7.1Z" stroke="currentColor" strokeWidth="1.4" strokeLinejoin="round" />
    </svg>
  ),
}

function ThemeToggle({ className = '' }) {
  const preference = useThemePreference()
  const next = nextAfter(preference)

  return (
    <button
      type="button"
      className={`theme-toggle ${className}`}
      onClick={() => setThemePreference(nextAfter(getThemePreference()))}
      title={`${LABELS[preference]}. Switch to ${LABELS[next].toLowerCase()}.`}
      aria-label={`${LABELS[preference]}. Switch to ${LABELS[next].toLowerCase()}.`}
    >
      {ICONS[preference]}
    </button>
  )
}

export default ThemeToggle
