import React from 'react'
import './HomeBackdrop.css'

// Home page backdrop: the docs homepage's grainy horizon band, running
// behind the search card and fading out before the footer.
function HomeBackdrop() {
  return (
    <div className="home-backdrop" aria-hidden="true">
      <div className="home-horizon" />
      <div className="home-grain" />
    </div>
  )
}

export default HomeBackdrop
