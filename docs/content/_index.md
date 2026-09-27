---
title: ""
description: "Open-source security auditor for GitHub Actions: maps every action, reusable workflow and image your CI runs, at the version it runs, and explains what each one exposes."
toc: false
---

<div class="index-page-wrapper as-home">

<section class="actsense-hero as-hero">
  <p class="as-eyebrow">Open-source Workflow Security Auditor</p>
  <h1>actsense</h1>
  <p class="as-lede">
    See every dependency your CI workflows actually run, at the exact version they run,
    and what each one exposes. Then fix it.
  </p>
  <div class="as-hero-actions">
    <a href="/getting-started/" class="as-btn as-btn-primary">Get started</a>
    <a href="/vulnerabilities/" class="as-btn as-btn-secondary">Browse the 79 checks</a>
  </div>
  <a class="as-platform-badge" href="#supported-platforms"><svg width="14" height="14" viewBox="0 0 16 16" fill="currentColor" aria-hidden="true"><path d="M8 0C3.58 0 0 3.58 0 8c0 3.54 2.29 6.53 5.47 7.59.4.07.55-.17.55-.38 0-.19-.01-.82-.01-1.49-2.01.37-2.53-.49-2.69-.94-.09-.23-.48-.94-.82-1.13-.28-.15-.68-.52-.01-.53.63-.01 1.08.58 1.23.82.72 1.21 1.87.87 2.33.66.07-.52.28-.87.51-1.07-1.78-.2-3.64-.89-3.64-3.95 0-.87.31-1.59.82-2.15-.08-.2-.36-1.02.08-2.12 0 0 .67-.21 2.2.82.64-.18 1.32-.27 2-.27.68 0 1.36.09 2 .27 1.53-1.04 2.2-.82 2.2-.82.44 1.1.16 1.92.08 2.12.51.56.82 1.27.82 2.15 0 3.07-1.87 3.75-3.65 3.95.29.25.54.73.54 1.48 0 1.07-.01 1.93-.01 2.2 0 .21.15.46.55.38A8.013 8.013 0 0016 8c0-4.42-3.58-8-8-8z"/></svg><span>Works with <strong>GitHub Actions</strong></span></a>
  <div class="hero-command-wrap">
    <div class="hero-command-card" id="hero-command-card" role="button" tabindex="0" aria-label="Copy the docker run command">
      <span class="hero-command-label">Quickstart</span>
      <code class="hero-command-text" id="hero-docker-command">docker run --rm -p 8000:8000 ghcr.io/0xcardinal/actsense:latest</code>
      <span class="hero-command-icon" aria-hidden="true">
        <svg class="icon-copy" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="9" y="9" width="13" height="13" rx="2"/><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"/></svg>
        <svg class="icon-check" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"/></svg>
      </span>
      <span class="visually-hidden" id="hero-command-status" aria-live="polite"></span>
    </div>
  </div>
</section>

<ul class="as-proof" aria-label="At a glance">
  <li><strong>79</strong><span>documented checks, each with a fix</span></li>
  <li><strong>Every layer</strong><span>composite actions, reusable workflows, images</span></li>
  <li><strong>Pinned refs</strong><span>audited at the version that runs, not <code>main</code></span></li>
  <li><strong>1 container</strong><span>self-hosted; your workflows stay with you</span></li>
</ul>

<div class="platform-image-container as-shot">
  <img id="platform-image" src="/images/platform.png" alt="actsense dependency graph of a repository's workflows and actions, with findings on each node" class="platform-tilt-image" />
</div>

<section class="as-section">
  <div class="as-section-head">
    <h2>The attacks it catches</h2>
    <p>The patterns behind real CI/CD compromises, found in your workflows and in every dependency they pull in. Shown here for GitHub Actions.</p>
  </div>
  <div class="as-threats">
    <a class="as-threat" href="/vulnerabilities/insecure_pull_request_target/">
      <span class="as-sev as-sev-critical">Critical</span>
      <h3>Pwn requests</h3>
      <p><code>pull_request_target</code> workflows that check out and run a fork's code with your secrets and a write token.</p>
    </a>
    <a class="as-threat" href="/vulnerabilities/risky_context_usage/">
      <span class="as-sev as-sev-critical">Critical</span>
      <h3>Script injection</h3>
      <p>PR titles, branch names and comments interpolated straight into <code>run:</code>, where they execute as shell.</p>
    </a>
    <a class="as-threat" href="/vulnerabilities/github_env_injection/">
      <span class="as-sev as-sev-critical">Critical</span>
      <h3>Environment poisoning</h3>
      <p>Untrusted text written to <code>$GITHUB_ENV</code> or <code>$GITHUB_PATH</code>, hijacking every later step.</p>
    </a>
    <a class="as-threat" href="/vulnerabilities/self_hosted_runner_pr_exposure/">
      <span class="as-sev as-sev-critical">Critical</span>
      <h3>Runner takeover</h3>
      <p>Self-hosted runners that pull requests from forks can reach, in a public repository.</p>
    </a>
    <a class="as-threat" href="/vulnerabilities/potential_hardcoded_secret/">
      <span class="as-sev as-sev-critical">Critical</span>
      <h3>Leaked credentials</h3>
      <p>Hardcoded keys and tokens, verified with TruffleHog, plus static cloud keys where OIDC should be.</p>
    </a>
    <a class="as-threat" href="/vulnerabilities/no_hash_pinning/">
      <span class="as-sev as-sev-medium">Supply chain</span>
      <h3>Mutable dependencies</h3>
      <p>Actions pinned to movable tags, unpinned images and packages, typosquats and archived actions.</p>
    </a>
  </div>
</section>

<section class="as-section">
  <div class="as-section-head">
    <h2>How it works</h2>
  </div>
  <ol class="as-steps">
    <li>
      <span class="as-step-num">1</span>
      <h3>Point it at a repository</h3>
      <p>An <code>owner/repo</code>, a single <code>owner/repo@ref</code> action, or a workflow file you paste in.</p>
    </li>
    <li>
      <span class="as-step-num">2</span>
      <h3>It maps the whole supply chain</h3>
      <p>Workflows, local and remote actions, nested reusable workflows, Docker base images and installed packages, each fetched at the ref your workflow pins.</p>
    </li>
    <li>
      <span class="as-step-num">3</span>
      <h3>Every node is audited</h3>
      <p>Findings land on the exact node and line, ranked by severity, each linked to a page explaining the risk and the fix.</p>
    </li>
  </ol>
</section>

<section class="as-section as-fix">
  <div class="as-fix-copy">
    <h2>Fix, not just flag</h2>
    <p>
      The workflow editor turns findings into line-level fixes you can apply in one click.
      Tags are resolved to commit SHAs and image digests through
      <a href="https://pin.actsense.dev">pin.</a>, so pinning works without a GitHub token.
    </p>
    <pre class="as-diff"><code><span class="as-del">-      - uses: actions/checkout@v4</span>
<span class="as-add">+      - uses: actions/checkout@11d5960a326750d5838078e36cf38b85af677262 # v4</span>
<span class="as-del">-    container: nginx:1.27</span>
<span class="as-add">+    container: nginx@sha256:6784fb08…c05f7d # 1.27</span></code></pre>
  </div>
</section>

<section class="as-section" id="supported-platforms">
  <div class="as-section-head">
    <h2>Supported platforms</h2>
    <p>actsense is a workflow security auditor. GitHub Actions is fully supported today; the engine is built so other workflow platforms can be added.</p>
  </div>
  <div class="as-platform-grid">
    <div class="as-platform-card is-supported">
      <span class="as-platform-logo"><svg width="22" height="22" viewBox="0 0 16 16" fill="currentColor" aria-hidden="true"><path d="M8 0C3.58 0 0 3.58 0 8c0 3.54 2.29 6.53 5.47 7.59.4.07.55-.17.55-.38 0-.19-.01-.82-.01-1.49-2.01.37-2.53-.49-2.69-.94-.09-.23-.48-.94-.82-1.13-.28-.15-.68-.52-.01-.53.63-.01 1.08.58 1.23.82.72 1.21 1.87.87 2.33.66.07-.52.28-.87.51-1.07-1.78-.2-3.64-.89-3.64-3.95 0-.87.31-1.59.82-2.15-.08-.2-.36-1.02.08-2.12 0 0 .67-.21 2.2.82.64-.18 1.32-.27 2-.27.68 0 1.36.09 2 .27 1.53-1.04 2.2-.82 2.2-.82.44 1.1.16 1.92.08 2.12.51.56.82 1.27.82 2.15 0 3.07-1.87 3.75-3.65 3.95.29.25.54.73.54 1.48 0 1.07-.01 1.93-.01 2.2 0 .21.15.46.55.38A8.013 8.013 0 0016 8c0-4.42-3.58-8-8-8z"/></svg></span>
      <div>
        <h3>GitHub Actions</h3>
        <p>Workflows, composite and JavaScript actions, reusable workflows, Docker actions and job containers.</p>
      </div>
      <span class="as-platform-status">Supported</span>
    </div>
    <div class="as-platform-card is-planned">
      <span class="as-platform-logo"><svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><circle cx="6" cy="6" r="2.5"/><circle cx="18" cy="6" r="2.5"/><circle cx="12" cy="18" r="2.5"/><path d="M8 7.5l3 8M16 7.5l-3 8M8.5 6h7"/></svg></span>
      <div>
        <h3>More workflow platforms</h3>
        <p>Other CI/CD workflow systems are planned. <a href="https://github.com/0xCardinal/actsense/issues">Tell us which one you need.</a></p>
      </div>
      <span class="as-platform-status">Planned</span>
    </div>
  </div>
</section>

<section class="as-section">
  <div class="as-section-head">
    <h2>What's covered</h2>
  </div>
  <div class="as-categories">
    <a href="/vulnerabilities/#workflow-security"><strong>Workflow security</strong><span>15 checks</span></a>
    <a href="/vulnerabilities/#supply-chain-security"><strong>Supply chain</strong><span>14 checks</span></a>
    <a href="/vulnerabilities/#secrets--credentials"><strong>Secrets &amp; credentials</strong><span>13 checks</span></a>
    <a href="/vulnerabilities/#self-hosted-runners"><strong>Self-hosted runners</strong><span>9 checks</span></a>
    <a href="/vulnerabilities/#action-pinning--immutability"><strong>Action pinning</strong><span>8 checks</span></a>
    <a href="/vulnerabilities/#permissions--access-control"><strong>Permissions</strong><span>7 checks</span></a>
    <a href="/vulnerabilities/#best-practices"><strong>Best practices</strong><span>7 checks</span></a>
    <a href="/vulnerabilities/#advanced-threats"><strong>Advanced threats</strong><span>6 checks</span></a>
  </div>
</section>

<section class="as-final">
  <h2>Audit your first repository in a minute</h2>
  <div class="as-hero-actions">
    <a href="/getting-started/" class="as-btn as-btn-primary">Get started</a>
    <a href="https://github.com/0xCardinal/actsense" class="as-btn as-btn-secondary">View on GitHub</a>
  </div>
</section>

</div>
