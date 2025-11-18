import React from 'react'
import './SearchButton.css'

function SearchButton({ onClick, disabled }) {
  const isMac = navigator.platform.toUpperCase().indexOf('MAC') >= 0
  const shortcutKey = isMac ? '⌘K' : 'Ctrl+K'

  return (
    <button
      className="search-button"
      onClick={onClick}
      disabled={disabled}
      title={`Search issues and assets (${shortcutKey})`}
      aria-label="Search issues and assets"
    >
      <svg 
        className="search-button-icon" 
        width="16" 
        height="16" 
        viewBox="0 0 16 16" 
        fill="none" 
        xmlns="http://www.w3.org/2000/svg"
      >
        <path 
          d="M11.5 10h-.79l-.28-.27C11.41 8.59 12 7.11 12 5.5 12 2.46 9.54 0 6.5 0S1 2.46 1 5.5 3.46 11 6.5 11c1.61 0 3.09-.59 4.23-1.57l.27.28v.79l5 4.99L16.49 15l-4.99-5zm-5 0C4.01 10 2 7.99 2 5.5S4.01 1 6.5 1 11 3.01 11 5.5 8.99 10 6.5 10z" 
          fill="currentColor"
        />
      </svg>
      <span className="search-button-text">Search</span>
      <kbd className="search-button-shortcut">{shortcutKey}</kbd>
    </button>
  )
}

export default SearchButton

