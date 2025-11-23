---
title: ""
description: "Comprehensive security documentation and vulnerability detection for GitHub Actions workflows"
toc: false
---

<div class="index-page-wrapper">
<div class="actsense-hero">
  <h1>actsense</h1>
  <p>
    Comprehensive security auditing for GitHub Actions workflows. Detect vulnerabilities, analyze dependencies, and secure your CI/CD pipelines.
  </p>
  <div style="display: flex; gap: 1rem; justify-content: center; flex-wrap: wrap;">
    <a href="https://github.com/0xCardinal/actsense" class="actsense-cta" target="_blank" rel="noopener noreferrer">
      <svg style="display: inline-block; width: 1.25rem; height: 1.25rem; margin-right: 0.5rem; vertical-align: middle;" fill="currentColor" viewBox="0 0 24 24">
        <path d="M12 0c-6.626 0-12 5.373-12 12 0 5.302 3.438 9.8 8.207 11.387.599.111.793-.261.793-.577v-2.234c-3.338.726-4.033-1.416-4.033-1.416-.546-1.387-1.333-1.756-1.333-1.756-1.089-.745.083-.729.083-.729 1.205.084 1.839 1.237 1.839 1.237 1.07 1.834 2.807 1.304 3.492.997.107-.775.418-1.305.762-1.604-2.665-.305-5.467-1.334-5.467-5.931 0-1.311.469-2.381 1.236-3.221-.124-.303-.535-1.524.117-3.176 0 0 1.008-.322 3.301 1.23.957-.266 1.983-.399 3.003-.404 1.02.005 2.047.138 3.006.404 2.291-1.552 3.297-1.23 3.297-1.23.653 1.653.242 2.874.118 3.176.77.84 1.235 1.911 1.235 3.221 0 4.609-2.807 5.624-5.479 5.921.43.372.823 1.102.823 2.222v3.293c0 .319.192.694.801.576 4.765-1.589 8.199-6.086 8.199-11.386 0-6.627-5.373-12-12-12z"/>
      </svg>
      View on GitHub
      <svg style="display: inline-block; width: 1rem; height: 1rem; margin-left: 0.5rem; vertical-align: middle;" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" viewBox="0 0 24 24">
        <path d="M5 12h14M12 5l7 7-7 7"/>
      </svg>
    </a>
  </div>
</div>

<div class="platform-image-container" style="text-align: center; margin: 0rem 0 2rem; perspective: 1000px;">
  <img id="platform-image" src="/images/platform.png" alt="actsense platform" class="platform-tilt-image" style="max-width: 100%; height: auto; border-radius: 0.5rem; box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.1), 0 2px 4px -1px rgba(0, 0, 0, 0.06); transition: transform 0.3s ease-out; display: inline-block; position: relative; z-index: 1;" />
</div>

{{< cards cols="3" >}}
  {{< card link="/vulnerabilities/" title="50+ Security Checks" icon="shield-check" >}}
  {{< card link="/usage/" title="Interactive Analysis" icon="chart-bar" >}}
  {{< card link="/getting-started/" title="Self Hosting" icon="document-text" >}}
{{< /cards >}}

## Why actsense?

GitHub Actions workflows can introduce serious security vulnerabilities. actsense helps you:

- **Detect 50+ vulnerability types** across workflows and dependencies
- **Analyze action dependencies** with interactive visual graphs  
- **Identify supply chain risks** from untrusted or outdated actions
- **Prevent credential exposure** and permission escalation

{{< callout type="info" >}}
**Ready to secure your workflows?** Explore our comprehensive [vulnerability documentation](/vulnerabilities/) with detailed explanations, evidence, and step-by-step mitigation strategies.
{{< /callout >}}

## Vulnerability Categories

{{< tabs items="Action Security,Access Control,Secrets & Credentials,Workflow Security,Runner Security" >}}
  {{< tab "Action Security" >}}
- Version pinning and immutability
- Dependency management  
- Supply chain security
- Unpinnable actions (Docker, composite, JavaScript)
  {{< /tab >}}
  {{< tab "Access Control" >}}
- Permission management
- Token security
- Branch protection
- Permission escalation risks
  {{< /tab >}}
  {{< tab "Secrets & Credentials" >}}
- Hardcoded secrets detection
- Environment security
- Long-term credential risks
- Secret exposure prevention
  {{< /tab >}}
  {{< tab "Workflow Security" >}}
- Dangerous event handling
- Input validation
- Code injection prevention
- Script execution security
  {{< /tab >}}
  {{< tab "Runner Security" >}}
- Self-hosted runner risks
- Network isolation
- Code execution security
- Exposure prevention
  {{< /tab >}}
{{< /tabs >}}

<div style="text-align: center; margin: 2rem 0;">
  <a href="/vulnerabilities/" class="actsense-cta">
    View All Vulnerabilities →
  </a>
</div>
