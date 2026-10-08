---
title: "Usage"
description: "A tour of the actsense app: start an audit, read the dependency graph, inspect findings, search, and fix a workflow."
---

<p class="as-usage-lede">
actsense audits a repository, a single action, a whole organization, or a workflow you paste in. It maps everything that workflow runs, audits each piece at the version it runs, and puts every finding on the node and line it came from. This page follows one audit from start to finish.
</p>

{{< demo-video >}}
The whole flow in 35 seconds: audit a repository, filter to critical findings, open one, and fix the workflow in the editor. The screenshots below come from an audit of the same repository, `step-security/github-actions-goat`, and follow your light or dark theme.
{{< /demo-video >}}

<nav class="as-tour" aria-label="On this page">
  <a href="#start-an-audit"><span>1</span>Start an audit</a>
  <a href="#read-the-results"><span>2</span>Read the results</a>
  <a href="#explore-the-graph"><span>3</span>Explore the graph</a>
  <a href="#inspect-a-node"><span>4</span>Inspect a node</a>
  <a href="#search-and-tables"><span>5</span>Search and tables</a>
  <a href="#fix-a-workflow"><span>6</span>Fix a workflow</a>
  <a href="#scan-an-organization"><span>7</span>Scan an organization</a>
</nav>

## Start an audit

Open actsense (`http://localhost:8000` with Docker, `http://localhost:5173` in development) and type what you want audited.

{{< shot name="home" alt="The actsense start screen with the audit input, token and clone options, and example audits" >}}
The start screen. The **Try** chips run example audits.
{{< /shot >}}

| You enter | actsense audits |
| --- | --- |
| `owner/repo`<br>`https://github.com/owner/repo` | Every workflow in `.github/workflows`, plus the actions, reusable workflows and images they use |
| `owner/repo@ref`<br>`actions/checkout@v4` | That one action at that ref, plus its own dependencies |
| `org`<br>`https://github.com/org` | The repositories you pick from that organization or user. See [Scan an organization](#scan-an-organization) |
| **Secure workflow** | A workflow you paste in. See [Fix a workflow](#fix-a-workflow) |

The two options below the input:

<div class="as-ui-list">
  <div>
    <strong>Add token</strong>
    <p>Raises the GitHub API limit from 60 to 5,000 requests an hour, which deep graphs need. A token with no scopes is enough for public repositories. It is sent with the audit and never saved.</p>
  </div>
  <div>
    <strong>Clone repo</strong>
    <p>Reads workflows from a git clone instead of the API. Use it for private repositories or to spend fewer API calls. Available for repositories, not single actions.</p>
  </div>
</div>

Each audit is saved. Open **Previous analyses** at the bottom of the screen and choose **Load** to reopen one without running it again.

## Read the results

When the audit finishes, the sidebar shows a summary. Every part of it is also a filter.

<div class="as-split">
  <div class="as-split-media">

{{< shot name="stats" alt="The results panel: node, edge and finding counts, a graph/table toggle and a severity breakdown" width="290" height="340" size="small" >}}{{< /shot >}}

  </div>
  <div class="as-split-copy">
    <dl class="as-defs">
      <dt>Nodes</dt>
      <dd>The full graph. Select it to clear any other filter.</dd>
      <dt>Edges</dt>
      <dd>Every dependency path from the repository, as a table.</dd>
      <dt>Findings</dt>
      <dd>Every finding, sorted by severity, as a table.</dd>
      <dt>Graph / Table</dt>
      <dd>Switches the current view between the graph and a list of nodes.</dd>
      <dt>By severity</dt>
      <dd>Select a row to show only nodes with findings at that severity. Select it again, or <strong>Clear filter</strong>, to go back.</dd>
      <dt>Levels</dt>
      <dd>How deep the graph goes. Resolution stops at 10 levels, the same nesting limit GitHub puts on reusable workflows.</dd>
    </dl>
  </div>
</div>

Severities tell you what to fix first:

| Severity | Meaning |
| --- | --- |
| <span class="as-sev as-sev-critical">Critical</span> | Exploitable now, for example a `pull_request_target` workflow that runs a fork's code with your secrets. |
| <span class="as-sev as-sev-high">High</span> | A serious weakness an attacker can build on, such as a write-all token or an unpinned third-party action. |
| <span class="as-sev as-sev-medium">Medium</span> | Hardening you should schedule, such as tag pins instead of commit SHAs. |
| <span class="as-sev as-sev-low">Low</span> | Best practice and hygiene. |

## Explore the graph

The graph reads left to right: the repository, its workflows, then the actions, reusable workflows and container images each one uses, down to their own dependencies. An edge means the left node directly references the right one, at the ref the workflow pins.

{{< shot name="graph" alt="The dependency graph zoomed in, with the path through actions/checkout@v4 highlighted in blue" >}}
Hovering `actions/checkout@v4` highlights every workflow that uses it.
{{< /shot >}}

- **Nodes** show their type, name and finding count. The badge colour is the node's highest severity. A green check means no findings.
- **Hover** a node to highlight its lineage: everything it depends on and everything that depends on it.
- **The legend** at the top names the node types and severity colours. **Map** turns the minimap on or off.
- **Zoom** with the controls at the bottom left. The last control fits the whole graph back on screen.

{{< shot name="dependency-map" alt="The full dependency graph of the goat repository fitted on screen, with the minimap in the corner" >}}
The same audit fitted to the screen. Workflows form the long column and shared actions sit to their right.
{{< /shot >}}

## Inspect a node

Click a node to open its details panel.

{{< shot name="node-details" alt="The node details panel for PRTargetWorkflow.yml showing its type, ID, GitHub link and dependency chain" >}}
Details for `PRTargetWorkflow.yml`.
{{< /shot >}}

The panel shows:

- **Name, type and node ID**, plus the repository that was scanned.
- **Open on GitHub**, linking to the file at the audited ref.
- **Dependency chain**: what depends on this node, and what this node depends on. Click any chip to jump to that node.
- **Security issues**: every finding on this node. Click one to open it.

### Finding details

{{< shot name="issue-details" alt="The details of a dangerous_event finding: description, mitigation, the triggering event as evidence, and a link to the docs" >}}
A `dangerous_event` finding with the event that triggered it.
{{< /shot >}}

Each finding explains the risk, gives a mitigation, and shows the **evidence** it was raised on: the event, step, line or value in the workflow. The link at the bottom opens that check's page in the [check reference](/vulnerabilities/).

### Dismiss a finding

If a finding is a false positive or a risk you accept, click **Dismiss finding** at the bottom of its details and, optionally, note why. A dismissed finding leaves the graph, the counts and search, and stays dismissed when you audit the same repository or action again. It comes back if the finding itself changes, for example when the step it points at is edited.

{{< shot name="dismiss-finding" alt="A dangerous_event finding's details with the dismiss form open: a reason typed in, and Cancel and Dismiss buttons" >}}
Dismissing a `dangerous_event` finding, with a reason for whoever reviews it later.
{{< /shot >}}

To review dismissals, open the **Findings** table and tick **Show dismissed**. Open a dismissed finding to see when it was dismissed and why, and click **Restore** to bring it back.

Dismissals are stored with your saved analyses in the container's `data` directory. Findings from a pasted workflow (**Create a secure workflow**) can't be dismissed, since there is no repository to remember them against.

### Share a node

**Share** in the panel header creates a link to that node and its findings.

{{< shot name="share" alt="The Share Node Details dialog with a shareable link and a Copy button" >}}{{< /shot >}}

The node and its findings are encoded in the link itself, so nothing is stored on a server. Whoever opens it sees the same panel and can run the full audit from there.

## Search and tables

### Search

Press <kbd>⌘</kbd> <kbd>K</kbd> (<kbd>Ctrl</kbd> <kbd>K</kbd> on Windows and Linux), or click the search box above the graph. Search matches finding types, messages, node names, owners and paths.

{{< shot name="search" alt="The search overlay with results for 'secret', each showing severity, finding type, message and node" >}}
Searching for `secret`. Press <kbd>Enter</kbd> to open the top result.
{{< /shot >}}

When there are more than eight matches, **View all** opens a results page grouped by severity. From there, **View Details** opens the finding and **Go to Node** shows it in the graph.

{{< shot name="search-result-page" alt="The search results page listing 37 results for 'secret', grouped by severity" >}}{{< /shot >}}

### Findings table

Select **Findings** in the sidebar to list every finding across the audit, critical first, with its node and message. Click a row to open the finding.

{{< shot name="security-issue-table" alt="The security issues table with severity, type, node, message and action columns" >}}{{< /shot >}}

### Dependency paths

Select **Edges** to list every path from the repository to each dependency, with its depth and the number of findings along it. Expand a row to see each step of the chain.

{{< shot name="dependencies-table" alt="The transitive dependencies table listing paths from the repository to alpine:3.10, tj-actions/glob and actions/checkout" >}}{{< /shot >}}

### Nodes table

Switch to **Table** to list every node with its type, finding count and highest severity.

{{< shot name="table-view-nodes" alt="The nodes table listing the repository, workflows and actions with their finding counts and severities" >}}{{< /shot >}}

## Fix a workflow

The secure workflow editor audits YAML you paste in, suggests line-level fixes, and applies them for you. Open it with **Secure workflow** on the start screen or **Create a secure workflow** in the sidebar.

{{< shot name="secure-workflow-editor" alt="The Secure Workflow Creator with a pasted workflow on the left and suggested fixes with diffs on the right" >}}
Findings on a `pull_request_target` workflow, each with a fix you can apply.
{{< /shot >}}

<ol class="as-steps as-steps--stack">
  <li>
    <span class="as-step-num">1</span>
    <h3>Paste a workflow</h3>
    <p>The YAML is validated first. Syntax errors and mixed tabs and spaces are reported with a line number.</p>
  </li>
  <li>
    <span class="as-step-num">2</span>
    <h3>Secure Workflow</h3>
    <p>Lists every finding with its line and, where one exists, a fix shown as a diff.</p>
  </li>
  <li>
    <span class="as-step-num">3</span>
    <h3>Apply fixes</h3>
    <p><strong>Apply Fix</strong> changes one line. <strong>Apply All Fixes</strong> applies every automatic fix at once. Then run Secure Workflow again to check the result.</p>
  </li>
  <li>
    <span class="as-step-num">4</span>
    <h3>Analyze &amp; View Graph</h3>
    <p>Runs the full audit on the edited workflow and opens its dependency graph.</p>
  </li>
</ol>

Pinning fixes replace tags with commit SHAs and image tags with digests. They are resolved through [pin.](https://pin.actsense.dev), with the GitHub API as a fallback, so pinning works without a token. When a pin can't be resolved, the fix is marked **manual** and contains a `<SHA>` or `<digest>` placeholder for you to fill in. **Apply All Fixes** skips these.

## Scan an organization

Type an organization or user name on its own (`my-org`, `@my-org` or `https://github.com/my-org`). The input is marked **Org** and the button reads **Find repos**.

<ol class="as-steps as-steps--stack">
  <li>
    <span class="as-step-num">1</span>
    <h3>Choose repositories</h3>
    <p>actsense lists the organization's repositories, most recently pushed first. Everything except forks and archived repositories starts selected. Filter by name, include forks or archived repositories, and scan up to 200 at a time.</p>
  </li>
  <li>
    <span class="as-step-num">2</span>
    <h3>Scan</h3>
    <p>Four repositories are audited at a time, each exactly as a single repository audit would be. Each row shows <strong>Queued</strong>, <strong>Scanning</strong> and then its result. A repository that fails is reported and the scan carries on.</p>
  </li>
  <li>
    <span class="as-step-num">3</span>
    <h3>Review the organization</h3>
    <p>The summary counts findings across every repository. Three tabs break it down:</p>
  </li>
</ol>

<div class="as-ui-list">
  <div>
    <strong>Repositories</strong>
    <p>Every scanned repository, riskiest first, with its findings by severity. Click a row to open its dependency graph; <strong>Back to scan</strong> in the sidebar returns here.</p>
  </div>
  <div>
    <strong>Findings</strong>
    <p>Every finding across the organization, grouped by rule or by repository, with search and severity filters. Each one links to the workflow file and line on GitHub, the action it comes through, and how to fix it. Click a finding to open it in the same side panel as the graph, where you can dismiss it, or use <strong>Graph</strong> to jump to it in the repository's graph.</p>
  </div>
  <div>
    <strong>Action inventory</strong>
    <p>Every action the organization's workflows use, flagging third-party actions, actions not pinned to a commit SHA, and actions used at several refs. Expand one to see each ref and every file and line that uses it.</p>
  </div>
</div>

Each repository is saved as an ordinary analysis, so dismissals and history work as they do for a single repository. **Copy link** shares the organization view. Scanning many repositories needs a [GitHub token](#start-an-audit): without one, GitHub's limit of 60 requests an hour runs out after a few repositories, and the rest are marked **Skipped** so you can scan them again.

## Good to know

<div class="as-ui-list">
  <div>
    <strong>Light and dark</strong>
    <p>The button next to <strong>Docs</strong> cycles between system, light and dark themes. Your choice is remembered in the browser.</p>
  </div>
  <div>
    <strong>Your data stays local</strong>
    <p>actsense runs as one self-hosted container. Saved analyses live in its <code>data</code> directory, and tokens are never written to disk.</p>
  </div>
  <div>
    <strong>Automate it</strong>
    <p>Everything the app does goes through the HTTP API. See the <a href="/api-reference/">API reference</a> to run audits from scripts or CI.</p>
  </div>
  <div>
    <strong>Every check is documented</strong>
    <p>Each finding type has a page explaining the risk, a vulnerable example and a fix. <a href="/vulnerabilities/">Browse the checks</a>.</p>
  </div>
</div>

{{< callout type="info" >}}
**Haven't installed actsense yet?** The [Getting Started guide](/getting-started/) takes you from `docker run` to your first audit.
{{< /callout >}}
