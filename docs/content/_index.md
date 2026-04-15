---
title: ""
description: "Comprehensive security documentation and vulnerability and exposure detection for GitHub Actions workflows"
toc: false
---

<div class="index-page-wrapper">
<div class="actsense-hero">
  <h1>actsense</h1>
  <p>
    Comprehensive security auditing for GitHub Actions workflows. Detect vulnerabilities and exposures, analyze dependencies, and secure your CI/CD pipelines.
  </p>
  <div class="hero-command-wrap">
    <div id="hero-command-card" class="hero-command-card" role="button" tabindex="0" aria-label="Copy docker run command">
      <div class="hero-command-label">Quick start</div>
      <code id="hero-docker-command" class="hero-command-text">docker run -p 8000:8000 0xcardinal/actsense:latest</code>
      <span id="hero-command-hint" class="hero-command-hint" aria-live="polite">Click to copy</span>
    </div>
  </div>
</div>

<div class="platform-image-container" style="text-align: center; margin: 0rem 0 2rem; perspective: 1000px;">
  <img id="platform-image" src="/images/platform.png" alt="actsense platform" class="platform-tilt-image" style="max-width: 100%; height: auto; border-radius: 0.5rem; box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.1), 0 2px 4px -1px rgba(0, 0, 0, 0.06); transition: transform 0.3s ease-out; display: inline-block; position: relative; z-index: 1;" />
</div>

{{< cards cols="3" >}}
  {{< card link="/vulnerabilities/" title="~70 Security Checks" icon="shield-check" >}}
  {{< card link="/usage/" title="Interactive Analysis" icon="chart-bar" >}}
  {{< card link="/getting-started/" title="Self Hosting" icon="document-text" >}}
{{< /cards >}}

## Why actsense?

GitHub Actions workflows can introduce serious security vulnerabilities and exposures. actsense helps you:

- **Detect ~70 vulnerability and exposure patterns** across workflows and dependencies
- **Analyze action dependencies** with interactive visual graphs  
- **Identify supply chain risks and exposures** from untrusted or outdated actions
- **Prevent credential exposure** and permission escalation

{{< callout type="info" >}}
**Ready to secure your workflows?** Explore our comprehensive [vulnerability documentation](/vulnerabilities/) with detailed explanations, evidence, and step-by-step mitigation strategies.
{{< /callout >}}

## Vulnerability and Exposure Categories

{{< tabs items="Action Security,Access Control,Secrets & Credentials,Workflow Security,Runner Security" >}}
  {{< tab "Action Security" >}}
- Unpinned or weak pinning checks (`unpinned_version`, `no_hash_pinning`, `short_hash_pinning`)
- Outdated or inconsistent versions (`older_action_version`, `inconsistent_action_version`)
- Untrusted and typosquatting exposure checks (`untrusted_action_source`, `typosquatting_action`)
- Unpinnable supply chain exposures (Docker/composite/JavaScript resource checks)
  {{< /tab >}}
  {{< tab "Access Control" >}}
- Overly permissive token and job permissions (`overly_permissive`, `github_token_write_all`)
- Excessive write scope and escalation paths (`excessive_write_permissions`, `token_permission_escalation`)
- Cross-repository and branch protection bypass exposure checks
- Environment protection and deployment policy bypass risks
  {{< /tab >}}
  {{< tab "Secrets & Credentials" >}}
- Hardcoded secret and cloud credential detection (`potential_hardcoded_secret`, cloud credential checks)
- Secret exposure in environment and workflow runtime (`secret_in_environment`, `environment_with_secrets`)
- Optional secret input and insecure secret-handling exposures
- Long-term cloud credential exposures vs OIDC best practices
  {{< /tab >}}
  {{< tab "Workflow Security" >}}
- Dangerous trigger and event exposure checks (`dangerous_event`, `insecure_pull_request_target`)
- Input and context injection checks (`unvalidated_workflow_input`, `code_injection_via_input`)
- Shell/script execution risks (`shell_injection`, `script_injection`, `risky_context_usage`)
- Malicious command patterns and obfuscation (`malicious_curl_pipe_bash`, `malicious_base64_decode`, `obfuscation_detection`)
  {{< /tab >}}
  {{< tab "Runner Security" >}}
- Public self-hosted runner exposure checks (`self_hosted_runner_pr_exposure`, issue exposure)
- Secrets and write-all risk on self-hosted runners
- Runner label confusion and workload hijacking risks
- Network exposure and lateral movement risk detection
  {{< /tab >}}
{{< /tabs >}}

<div style="text-align: center; margin: 2rem 0;">
  <a href="/vulnerabilities/" class="actsense-cta">
    View All Vulnerabilities →
  </a>
</div>
