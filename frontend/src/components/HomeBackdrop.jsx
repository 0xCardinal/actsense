import React from 'react'
import './HomeBackdrop.css'

// Home page backdrop: a grainy blue-to-orange bloom rising from the bottom
// edge, echoed by a faint wash of the same colours behind the brand.
function HomeBackdrop() {
  return (
    <div className="home-backdrop" aria-hidden="true">
      <div className="home-halo" />
      <div className="home-bloom" />
      <div className="home-bloom-grain" />
      <div className="home-grain" />
    </div>
  )
}

export default HomeBackdrop
