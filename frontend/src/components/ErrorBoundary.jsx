import React from 'react'

class ErrorBoundary extends React.Component {
  constructor(props) {
    super(props)
    this.state = { hasError: false, error: null }
  }

  static getDerivedStateFromError(error) {
    return { hasError: true, error }
  }

  componentDidCatch(error, errorInfo) {
    console.error('Error caught by boundary:', error, errorInfo)
  }

  render() {
    if (this.state.hasError) {
      return (
        <div style={{
          padding: '2rem',
          color: '#f85149',
          background: '#0d1117',
          minHeight: '100vh',
          display: 'flex',
          flexDirection: 'column',
          alignItems: 'center',
          justifyContent: 'center'
        }}>
          <h1>Something went wrong</h1>
          <pre style={{
            background: '#161b22',
            padding: '1rem',
            borderRadius: '6px',
            marginTop: '1rem',
            overflow: 'auto',
            maxWidth: '800px'
          }}>
            {this.state.error?.toString()}
            {this.state.error?.stack && (
              <div style={{ marginTop: '1rem', fontSize: '0.9rem' }}>
                {this.state.error.stack}
              </div>
            )}
          </pre>
          <button
            onClick={() => window.location.reload()}
            style={{
              marginTop: '1rem',
              padding: '0.75rem 1.5rem',
              background: '#238636',
              color: 'white',
              border: 'none',
              borderRadius: '6px',
              cursor: 'pointer'
            }}
          >
            Reload Page
          </button>
        </div>
      )
    }

    return this.props.children
  }
}

export default ErrorBoundary

