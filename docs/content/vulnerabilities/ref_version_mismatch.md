# Action Ref / Version Comment Mismatch

## Description

Pinning an action to a full commit SHA is the most secure way to reference it, and the common convention is to annotate the SHA with the human-readable version it corresponds to: `uses: actions/checkout@<sha>  # v4.1.1`. When the comment's tag does not actually resolve to the pinned SHA, the annotation is misleading — the workflow is not running the version it claims to. This can hide an accidental downgrade, a copy-paste error, or a deliberately swapped commit that reviewers wave through because the comment "looks right." [^gh_security_hardening] It undermines the review signal that SHA pinning is supposed to provide (see [No Hash Pinning](/vulnerabilities/no_hash_pinning/)).

## Vulnerable Instance

- An action is pinned to a commit SHA with a trailing version comment, but that tag resolves to a different commit.

```yaml
steps:
  # comment claims v4, but this SHA is actually the v3 commit
  - uses: actions/checkout@a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0  # v4
```

## Mitigation Strategies

1. **Make the SHA and comment agree.** Re-pin to the SHA the intended tag points to, or fix the comment to match the commit actually in use.
2. **Automate pinning.** Use a tool that pins actions to SHAs and keeps the version comment in sync, so the two cannot drift.
3. **Review the comment as data, not truth.** Treat the annotation as a convenience, and rely on the SHA for what actually runs.

### Secure Version

```diff
 steps:
-  - uses: actions/checkout@a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0  # v4
+  - uses: actions/checkout@<sha-of-v4>  # v4
```

## Impact

| Dimension | Severity | Notes |
| --- | --- | --- |
| Likelihood | ![Low](https://img.shields.io/badge/-Low-green?style=flat-square) | Usually an honest drift between the SHA and its comment, but occasionally a deliberate disguise. |
| Risk | ![Medium](https://img.shields.io/badge/-Medium-orange?style=flat-square) | The workflow runs a different version than reviewers believe, weakening the pinning review signal. |
| Blast radius | ![Moderate](https://img.shields.io/badge/-Moderate-yellow?style=flat-square) | Bounded by what the mismatched action version does. |

## References

- GitHub Docs, "Security hardening for GitHub Actions — Using third-party actions," https://docs.github.com/en/actions/security-guides/security-hardening-for-github-actions#using-third-party-actions [^gh_security_hardening]
- GitHub Docs, "Finding and customizing actions — Using SHAs," https://docs.github.com/en/actions/learn-github-actions/finding-and-customizing-actions#using-shas [^gh_shas]

---

[^gh_security_hardening]: GitHub Docs, "Security hardening for GitHub Actions," https://docs.github.com/en/actions/security-guides/security-hardening-for-github-actions#using-third-party-actions
[^gh_shas]: GitHub Docs, "Finding and customizing actions," https://docs.github.com/en/actions/learn-github-actions/finding-and-customizing-actions#using-shas
