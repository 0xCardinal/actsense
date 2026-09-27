import { useSyncExternalStore } from 'react'

// The viewer's colour theme: 'light', 'dark' or 'system' (follow the OS).
// The preference is remembered per browser; the resolved theme is written to
// <html data-theme> so the CSS tokens in index.css switch over. index.html
// applies the same logic inline before the first paint to avoid a flash.

const STORAGE_KEY = 'actsense-theme'
const CHANGE_EVENT = 'actsense-theme-change'
const media = typeof window !== 'undefined' && window.matchMedia
  ? window.matchMedia('(prefers-color-scheme: dark)')
  : null

export function getThemePreference() {
  try {
    const saved = localStorage.getItem(STORAGE_KEY)
    if (saved === 'light' || saved === 'dark') return saved
  } catch {
    // Storage can be unavailable (private mode, blocked site data).
  }
  return 'system'
}

function resolve(preference) {
  if (preference === 'light' || preference === 'dark') return preference
  return media && media.matches ? 'dark' : 'light'
}

function apply() {
  document.documentElement.dataset.theme = resolve(getThemePreference())
  window.dispatchEvent(new Event(CHANGE_EVENT))
}

export function setThemePreference(preference) {
  try {
    if (preference === 'system') localStorage.removeItem(STORAGE_KEY)
    else localStorage.setItem(STORAGE_KEY, preference)
  } catch {
    // Still apply for this session even if it can't be saved.
  }
  apply()
}

// Follow OS changes while the preference is 'system'.
if (media) {
  media.addEventListener('change', () => {
    if (getThemePreference() === 'system') apply()
  })
}

function subscribe(callback) {
  window.addEventListener(CHANGE_EVENT, callback)
  return () => window.removeEventListener(CHANGE_EVENT, callback)
}

/** The theme actually in use: 'light' or 'dark'. */
export function useResolvedTheme() {
  return useSyncExternalStore(subscribe, () => document.documentElement.dataset.theme || 'light')
}

/** The saved preference: 'light', 'dark' or 'system'. */
export function useThemePreference() {
  return useSyncExternalStore(subscribe, getThemePreference)
}
