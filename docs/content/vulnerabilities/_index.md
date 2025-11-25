---
title: "Security Vulnerabilities"
description: "Comprehensive documentation for all security vulnerabilities detected by actsense"
---

This section documents all security vulnerabilities detected by actsense. Each vulnerability includes a detailed description, evidence, and mitigation strategies.

## Vulnerability Categories

### Action Pinning & Immutability
- [Unpinned Version](/vulnerabilities/unpinned_version/)
- [No Hash Pinning](/vulnerabilities/no_hash_pinning/)
- [Short Hash Pinning](/vulnerabilities/short_hash_pinning/)
- [Older Action Version](/vulnerabilities/older_action_version/)
- [Inconsistent Action Version](/vulnerabilities/inconsistent_action_version/)
- [Unpinnable Docker Image](/vulnerabilities/unpinnable_docker_image/)
- [Unpinnable Composite Subaction](/vulnerabilities/unpinnable_composite_subaction/)
- [Unpinnable JavaScript Action](/vulnerabilities/unpinned_javascript_resources/)

### Permissions & Access Control
- [Overly Permissive](/vulnerabilities/overly_permissive/)
- [GitHub Token Write All](/vulnerabilities/github_token_write_all/)
- [GitHub Token Write Permissions](/vulnerabilities/github_token_write_permissions/)
- [Excessive Write Permissions](/vulnerabilities/excessive_write_permissions/)
- [Branch Protection Bypass](/vulnerabilities/branch_protection_bypass/)
- [Token Permission Escalation](/vulnerabilities/token_permission_escalation/)

### Secrets & Credentials
- [Potential Hardcoded Secret](/vulnerabilities/potential_hardcoded_secret/)
- [Potential Hardcoded Cloud Credentials](/vulnerabilities/potential_hardcoded_cloud_credentials/)
- [Long Term Cloud Credentials](/vulnerabilities/long_term_cloud_credentials/)
- [Secret in Environment](/vulnerabilities/secret_in_environment/)
- [Secrets Access Untrusted](/vulnerabilities/secrets_access_untrusted/)
- [Secrets in Matrix](/vulnerabilities/secrets_in_matrix/)
- [Environment with Secrets](/vulnerabilities/environment_with_secrets/)

### Workflow Security
- [Dangerous Event](/vulnerabilities/dangerous_event/)
- [Insecure Pull Request Target](/vulnerabilities/insecure_pull_request_target/)
- [Unsafe Checkout](/vulnerabilities/unsafe_checkout/)
- [Unsafe Checkout Ref](/vulnerabilities/unsafe_checkout_ref/)
- [Checkout Full History](/vulnerabilities/checkout_full_history/)
- [Script Injection](/vulnerabilities/script_injection/)
- [Shell Injection](/vulnerabilities/shell_injection/)
- [Code Injection via Input](/vulnerabilities/code_injection_via_input/)
- [Unvalidated Workflow Input](/vulnerabilities/unvalidated_workflow_input/)
- [Unsafe Shell](/vulnerabilities/unsafe_shell/)

### Supply Chain Security
- [Untrusted Action Source](/vulnerabilities/untrusted_action_source/)
- [Untrusted Action Unpinned](/vulnerabilities/untrusted_action_unpinned/)
- [Typosquatting Action](/vulnerabilities/typosquatting_action/)
- [Deprecated Action](/vulnerabilities/deprecated_action/)
- [Missing Action Repository](/vulnerabilities/missing_action_repository/)
- [Unpinned Dockerfile Dependencies](/vulnerabilities/unpinned_dockerfile_dependencies/)
- [Unpinned Dockerfile Resources](/vulnerabilities/unpinned_dockerfile_resources/)
- [Unpinned External Resources](/vulnerabilities/unpinned_external_resources/)
- [Unpinned JavaScript Resources](/vulnerabilities/unpinned_javascript_resources/)
- [Unpinned NPM Packages](/vulnerabilities/unpinned_npm_packages/)
- [Unpinned Python Packages](/vulnerabilities/unpinned_python_packages/)
- [Unfiltered Network Traffic](/vulnerabilities/unfiltered_network_traffic/)
- [No File Tampering Protection](/vulnerabilities/no_file_tampering_protection/)

### Self-Hosted Runners
- [Self Hosted Runner](/vulnerabilities/self_hosted_runner/)
- [Self Hosted Runner PR Exposure](/vulnerabilities/self_hosted_runner_pr_exposure/)
- [Self Hosted Runner Issue Exposure](/vulnerabilities/self_hosted_runner_issue_exposure/)
- [Self Hosted Runner Write All](/vulnerabilities/self_hosted_runner_write_all/)
- [Self Hosted Runner Secrets in Run](/vulnerabilities/self_hosted_runner_secrets_in_run/)
- [Self Hosted Runner Network Risk](/vulnerabilities/self_hosted_runner_network_risk/)
- [Runner Label Confusion](/vulnerabilities/runner_label_confusion/)
- [Public Repo Self Hosted Secrets](/vulnerabilities/public_repo_self_hosted_secrets/)
- [Public Repo Self Hosted Environment](/vulnerabilities/public_repo_self_hosted_environment/)

### Best Practices
- [Continue on Error Critical Job](/vulnerabilities/continue_on_error_critical_job/)
- [Artifact Retention](/vulnerabilities/long_artifact_retention/)
- [Large Matrix](/vulnerabilities/large_matrix/)
- [Insufficient Audit Logging](/vulnerabilities/insufficient_audit_logging/)
- [Environment Bypass Risk](/vulnerabilities/environment_bypass_risk/)
- [Cross Repository Access](/vulnerabilities/cross_repository_access/)
- [Cross Repository Access Command](/vulnerabilities/cross_repository_access_command/)

### Advanced Threats
- [Malicious Curl Pipe Bash](/vulnerabilities/malicious_curl_pipe_bash/)
- [Malicious Base64 Decode](/vulnerabilities/malicious_base64_decode/)
- [Obfuscation Detection](/vulnerabilities/obfuscation_detection/)
- [Artipacked Vulnerability](/vulnerabilities/artipacked_vulnerability/)

