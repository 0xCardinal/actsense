import React from 'react'
import './IssueDetailsModal.css'

function IssueDetailsModal({ issue, otherInstances, onClose }) {
  if (!issue) return null

  const getIssueDescription = (issueType) => {
    const descriptions = {
      'unpinned_version': {
        description: 'This action is not pinned to a specific version, tag, or commit SHA. Using unpinned actions means your workflows could break or be compromised if the action is updated with malicious code.',
        mitigation: 'Pin actions to a specific version tag (e.g., @v3) or better yet, use the full commit SHA (40 characters) for maximum security. Example: actions/checkout@8f4b7f84884ec3e152e95e913f196d7a537752ca'
      },
      'no_hash_pinning': {
        description: 'This action uses a version tag instead of a commit SHA hash. Tags can be moved or overwritten, making them less secure than immutable commit SHAs.',
        mitigation: 'Replace the tag with the full 40-character commit SHA. You can find the SHA by visiting the action repository and copying the commit hash from the releases page.'
      },
      'short_hash_pinning': {
        description: 'This action uses a short commit SHA (7+ characters) instead of the full 40-character SHA. Short SHAs can potentially collide with other commits.',
        mitigation: 'Use the full 40-character commit SHA instead of a short SHA for maximum security and immutability.'
      },
      'unpinnable_docker_image': {
        description: 'This Docker action uses a mutable tag (like "latest" or "v1") instead of an immutable Docker image digest. Tags can be updated to point to different images, creating a security risk.',
        mitigation: 'Use Docker image digests (sha256:...) instead of tags. You can get the digest by running: docker pull <image>:<tag> && docker inspect <image>:<tag> | grep RepoDigests'
      },
      'unpinnable_composite_subaction': {
        description: 'This composite action uses sub-actions that are not pinned to full commit SHAs. This creates a transitive dependency risk.',
        mitigation: 'Update the composite action to pin all sub-actions to full 40-character commit SHAs instead of tags or branches.'
      },
      'unpinnable_javascript_resources': {
        description: 'This JavaScript action downloads external resources without checksum verification, making it vulnerable to supply chain attacks.',
        mitigation: 'Add checksum verification for all downloaded resources using SHA256 or SHA512 hashes before executing them.'
      },
      'overly_permissive': {
        description: 'This workflow has overly permissive permissions, allowing write access to repository contents. This increases the attack surface if the workflow is compromised.',
        mitigation: 'Use the principle of least privilege. Only grant the minimum permissions needed. Use read-only permissions when possible, and scope write permissions to specific areas.'
      },
      'github_token_write_all': {
        description: 'This workflow uses write-all permissions for GITHUB_TOKEN, giving it full access to the repository. This is a significant security risk.',
        mitigation: 'Replace write-all with specific, scoped permissions. Only grant write access to the specific areas needed (e.g., contents: write, packages: write).'
      },
      'github_token_write_permissions': {
        description: 'This workflow grants write permissions to GITHUB_TOKEN for specific scopes. While better than write-all, it still poses a risk if compromised.',
        mitigation: 'Review if write permissions are truly necessary. Consider using read-only permissions and only grant write access when absolutely required for the workflow to function.'
      },
      'self_hosted_runner': {
        description: 'This workflow uses self-hosted runners, which can be compromised and used to attack your repository or infrastructure.',
        mitigation: 'Use GitHub-hosted runners when possible. If self-hosted runners are necessary, implement strict security controls, network isolation, and regular security audits.'
      },
      'dangerous_event': {
        description: 'This workflow uses dangerous trigger events like pull_request_target or workflow_run, which can be exploited by attackers from forks or through workflow chaining.',
        mitigation: 'Avoid using pull_request_target when possible. If necessary, validate all inputs and never trust code from pull requests. For workflow_run, ensure proper authentication and validation.'
      },
      'unsafe_checkout': {
        description: 'This workflow uses checkout with persist-credentials=true, which can expose credentials to subsequent steps.',
        mitigation: 'Remove persist-credentials or set it to false. Use GITHUB_TOKEN with appropriate permissions instead of persisting credentials.'
      },
      'unsafe_checkout_ref': {
        description: 'This workflow uses checkout with a potentially unsafe ref that could be manipulated.',
        mitigation: 'Validate and sanitize ref inputs before using them in checkout. Use fixed refs or validate against an allowlist.'
      },
      'potential_script_injection': {
        description: 'This workflow may be vulnerable to script injection through github.event variables used in shell commands.',
        mitigation: 'Sanitize all user inputs and github.event data before using them in shell commands. Use environment variables and proper escaping.'
      },
      'potential_hardcoded_secret': {
        description: 'This workflow may contain hardcoded secrets, passwords, or API keys, which is a critical security vulnerability.',
        mitigation: 'Remove all hardcoded secrets immediately. Use GitHub Secrets or environment secrets instead. Rotate any exposed credentials.'
      },
      'optional_secret_input': {
        description: 'This action has optional secret inputs, which could lead to security issues if secrets are not properly validated.',
        mitigation: 'Make secret inputs required when they are necessary for security, or implement proper default handling and validation.'
      },
      'long_term_aws_credentials': {
        description: 'This workflow uses long-term AWS credentials instead of OIDC, which is less secure and harder to rotate.',
        mitigation: 'Migrate to GitHub OIDC for AWS authentication. This provides temporary credentials and better security. See: https://docs.github.com/en/actions/deployment/security-hardening-your-deployments/configuring-openid-connect-in-amazon-web-services'
      },
      'long_term_azure_credentials': {
        description: 'This workflow uses long-term Azure credentials instead of OIDC.',
        mitigation: 'Migrate to GitHub OIDC for Azure authentication. See: https://docs.github.com/en/actions/deployment/security-hardening-your-deployments/configuring-openid-connect-in-azure'
      },
      'long_term_gcp_credentials': {
        description: 'This workflow uses long-term GCP credentials instead of OIDC.',
        mitigation: 'Migrate to GitHub OIDC for GCP authentication. See: https://docs.github.com/en/actions/deployment/security-hardening-your-deployments/configuring-openid-connect-in-google-cloud-platform'
      },
      'untrusted_third_party_action': {
        description: 'This workflow uses a third-party action from an untrusted publisher. Third-party actions can contain malicious code.',
        mitigation: 'Only use actions from trusted publishers. Review the action source code, check for security advisories, and consider forking and maintaining your own copy of critical actions.'
      },
      'untrusted_action_unpinned': {
        description: 'This workflow uses an untrusted third-party action that is not pinned to a specific version, making it extremely vulnerable.',
        mitigation: 'Pin the action to a specific commit SHA and review the source code. Consider forking the action and maintaining your own version if it\'s critical.'
      },
      'secrets_in_matrix': {
        description: 'This workflow uses secrets in a matrix strategy, which exposes secrets to all matrix job combinations.',
        mitigation: 'Remove secrets from matrix definitions. Use environment variables or job-level secrets instead. Secrets in matrices are visible to all jobs.'
      },
      'unvalidated_workflow_input': {
        description: 'This workflow accepts inputs without proper validation, which could lead to injection attacks or unexpected behavior.',
        mitigation: 'Validate all workflow inputs before use. Check types, ranges, and formats. Sanitize inputs used in shell commands or file paths.'
      },
      'code_injection_via_input': {
        description: 'This workflow may be vulnerable to code injection through workflow_dispatch inputs used in shell commands.',
        mitigation: 'Validate and sanitize all workflow inputs. Never directly interpolate user inputs into shell commands. Use environment variables and proper escaping.'
      },
      'branch_protection_bypass': {
        description: 'This workflow may bypass branch protection rules by auto-approving or auto-merging pull requests.',
        mitigation: 'Remove auto-approval or auto-merge functionality from workflows. Let branch protection rules handle approvals and merges.'
      },
      'unfiltered_network_traffic': {
        description: 'This workflow performs network operations that could exfiltrate credentials or sensitive data.',
        mitigation: 'Implement network segmentation and traffic filtering. Monitor outbound connections and restrict access to only necessary endpoints.'
      },
      'no_file_tampering_protection': {
        description: 'This workflow modifies files during build without protection against tampering.',
        mitigation: 'Implement endpoint detection and response (EDR) tools to detect source code or artifact tampering during build processes.'
      },
      'insufficient_audit_logging': {
        description: 'This workflow performs sensitive operations without detailed audit logging.',
        mitigation: 'Enable detailed audit logging for all CI/CD activities. Log all sensitive operations, credential usage, and file modifications to enable forensic analysis.'
      },
      'checkout_full_history': {
        description: 'This workflow fetches the full git history, which may expose sensitive information from commit history.',
        mitigation: 'Use fetch-depth: 1 to only fetch the latest commit, unless full history is necessary for the workflow.'
      },
      'long_artifact_retention': {
        description: 'This workflow retains artifacts for more than 90 days, which may violate data retention policies.',
        mitigation: 'Set artifact retention to 90 days or less unless longer retention is required for compliance.'
      },
      'large_matrix': {
        description: 'This workflow has a large matrix with many combinations, which may impact performance and costs.',
        mitigation: 'Review if all matrix combinations are necessary. Consider splitting into separate workflows or reducing the matrix size.'
      },
      'environment_with_secrets': {
        description: 'This workflow uses environment secrets, which should be carefully managed.',
        mitigation: 'Ensure environment protection rules are configured. Limit access to environments with secrets and use approval workflows when appropriate.'
      },
      'unpinned_dockerfile_dependencies': {
        description: 'This Docker action installs Python packages without version pinning in the Dockerfile.',
        mitigation: 'Pin all package versions in Dockerfile using == syntax (e.g., pip install package==1.2.3). Use requirements.txt with pinned versions.'
      },
      'unpinned_dockerfile_resources': {
        description: 'This Docker action downloads external resources without checksum verification in the Dockerfile.',
        mitigation: 'Verify checksums for all downloaded external resources in the Dockerfile using SHA256 or SHA512.'
      },
      'unpinned_npm_packages': {
        description: 'This composite action installs NPM packages without version locking.',
        mitigation: 'Use package-lock.json or specify exact versions in package.json. Run npm ci instead of npm install in CI.'
      },
      'unpinned_python_packages': {
        description: 'This composite action installs Python packages without version pinning.',
        mitigation: 'Pin all Python package versions using == syntax (e.g., pip install package==1.2.3). Use requirements.txt with pinned versions.'
      },
      'unpinned_external_resources': {
        description: 'This composite action downloads external resources without checksum verification.',
        mitigation: 'Verify checksums for all downloaded external resources using SHA256 or SHA512 before using them.'
      },
      'unsafe_shell': {
        description: 'This workflow uses bash without the -e flag, which means errors may not be caught.',
        mitigation: 'Add -e flag to bash commands (set -e) or use set -euo pipefail for better error handling.'
      }
    }

    return descriptions[issueType] || {
      description: 'This is a security issue that requires attention.',
      mitigation: 'Review the issue and implement appropriate security controls.'
    }
  }

  const issueInfo = getIssueDescription(issue.type)

  return (
    <>
      <div className="issue-modal-backdrop" onClick={onClose} />
      <div className="issue-modal">
        <div className="issue-modal-header">
          <h3>{issue.type || 'Security Issue'}</h3>
          <button className="issue-modal-close" onClick={onClose} aria-label="Close">
            ×
          </button>
        </div>
        
        <div className="issue-modal-content">
          <div className="issue-modal-section">
            <h4>Description</h4>
            <p>{issueInfo.description}</p>
          </div>

          <div className="issue-modal-section">
            <h4>Mitigation Strategy</h4>
            <p>{issueInfo.mitigation}</p>
          </div>

          {otherInstances && otherInstances.length > 0 && (
            <div className="issue-modal-section">
              <h4>Other Instances ({otherInstances.length})</h4>
              <div className="other-instances-list">
                {otherInstances.map((instance, index) => (
                  <div key={index} className="instance-item">
                    <div className="instance-node">{instance.nodeLabel || instance.id}</div>
                    {instance.message && (
                      <div className="instance-message">{instance.message}</div>
                    )}
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>
      </div>
    </>
  )
}

export default IssueDetailsModal

