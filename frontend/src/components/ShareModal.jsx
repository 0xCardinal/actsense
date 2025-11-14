import React, { useState } from 'react'
import './ShareModal.css'

function ShareModal({ shareUrl, repository, onClose, onStartAnalysis }) {
  const [linkCopied, setLinkCopied] = useState(false)

  const handleCopyLink = () => {
    navigator.clipboard.writeText(shareUrl).then(() => {
      setLinkCopied(true)
      setTimeout(() => setLinkCopied(false), 2000)
    }).catch(err => {
      console.error('Failed to copy link:', err)
    })
  }

  return (
    <>
      <div className="share-modal-backdrop" onClick={onClose} />
      <div className="share-modal">
        <div className="share-modal-header">
          <h3>Share Node Details</h3>
          <button className="share-modal-close" onClick={onClose} aria-label="Close">
            ×
          </button>
        </div>
        
        <div className="share-modal-content">
          <div className="share-modal-section">
            <h4>Shareable Link</h4>
            <p className="share-modal-description">
              Copy this link to share this node's details with others.
            </p>
            <div className="share-link-container">
              <input
                type="text"
                value={shareUrl}
                readOnly
                className="share-link-input"
                onClick={(e) => e.target.select()}
              />
              <button
                onClick={handleCopyLink}
                className="share-copy-button"
                title="Copy link"
              >
                {linkCopied ? '✓ Copied' : 'Copy'}
              </button>
            </div>
          </div>
        </div>
      </div>
    </>
  )
}

export default ShareModal

