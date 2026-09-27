import { createContext, useContext } from 'react'

// Dismiss / restore for the analysis on screen. `canDismiss` is false where
// there is nothing to remember a dismissal against (inline YAML audits, share
// links).
export const DismissalContext = createContext({
  canDismiss: false,
  dismiss: async () => {},
  restore: async () => {},
})

export const useDismissals = () => useContext(DismissalContext)

export const isDismissed = (issue) => Boolean(issue?.dismissed)

// The graph with dismissed findings taken out, for every view but the
// findings table (which can show them on request).
export function withoutDismissed(graphData) {
  if (!graphData?.nodes) return graphData
  const active = (issues) => (issues || []).filter(issue => !isDismissed(issue))
  return {
    ...graphData,
    nodes: graphData.nodes.map(node => ({ ...node, issues: active(node.issues) })),
    issues: Object.fromEntries(
      Object.entries(graphData.issues || {}).map(([nodeId, issues]) => [nodeId, active(issues)])
    ),
  }
}
