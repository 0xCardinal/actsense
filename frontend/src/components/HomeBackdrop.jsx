import React from 'react'
import './HomeBackdrop.css'

// Quiet, layered backdrop for the home page: a fine grid that fades out from
// the centre, one soft glow behind the search card, and a touch of grain.
function HomeBackdrop() {
  return (
    <div className="home-backdrop" aria-hidden="true">
      <div className="home-grid" />
      <div className="home-glow" />
      <div className="home-horizon" />
      <div className="home-grain" />
    </div>
  )
}

export default HomeBackdrop
