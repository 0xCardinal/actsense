"""Repository cloning functionality."""
import subprocess
import tempfile
import shutil
import os
import logging
from typing import Optional, Tuple
from pathlib import Path
import re

logger = logging.getLogger(__name__)


class CloneError(Exception):
    """User-facing git clone failure (map to HTTP 400, not 500)."""

    def __init__(self, detail: str):
        self.detail = detail
        super().__init__(detail)


def _clone_failure_user_message(stderr: str, had_token: bool) -> str:
    err_l = (stderr or "").lower()
    if (
        "could not read username" in err_l
        or "terminal prompts disabled" in err_l
        or "authentication failed" in err_l
    ):
        if not had_token:
            return (
                "Git could not access this repository (it may be private or require authentication). "
                "Provide a token in the request, set the GITHUB_TOKEN environment variable, "
                "or turn off 'Use clone' and use the API for public repositories."
            )
        return (
            "Git rejected the credentials. Verify the token has access to this repository and "
            "appropriate scopes (e.g. repo for private repos)."
        )
    if "not found" in err_l or "does not exist" in err_l:
        return "Repository not found. Check the owner and repository name, or your access token."
    # Keep stderr short: avoid leaking host-specific paths; cap length
    line = (stderr or "").strip().splitlines()[-1] if (stderr or "").strip() else "unknown error"
    if len(line) > 400:
        line = line[:400] + "…"
    return f"Git clone failed: {line}"


class RepoCloner:
    """Handle cloning and cleanup of repositories."""

    def __init__(self, base_dir: Optional[str] = None):
        """Initialize with optional base directory for clones."""
        if base_dir:
            self.base_dir = Path(base_dir)
            self.base_dir.mkdir(parents=True, exist_ok=True)
        else:
            self.base_dir = Path(tempfile.gettempdir()) / "actsense-clones"
            self.base_dir.mkdir(parents=True, exist_ok=True)

    def clone_repository(
        self,
        owner: str,
        repo: str,
        token: Optional[str] = None,
        branch: Optional[str] = None
    ) -> Tuple[str, str]:
        """
        Clone a repository and return the path to the cloned directory.

        Returns:
            Tuple of (clone_path, cleanup_function_name)
        """
        safe_owner = RepoCloner._validated_repo_slug(owner, "owner")
        safe_repo = RepoCloner._validated_repo_slug(repo, "repository")
        safe_branch = RepoCloner._validated_branch_name(branch) if branch else None

        # Credential-less URL; auth is supplied via git config environment (not argv).
        repo_url = f"https://github.com/{safe_owner}/{safe_repo}.git"
        public_repo_url = repo_url  # alias used in sanitize step below

        # Explicit API token first, then GITHUB_TOKEN (e.g. container env) for private repos.
        raw = (token or "").strip() or (os.environ.get("GITHUB_TOKEN") or "").strip()
        safe_token: Optional[str] = None
        if raw:
            try:
                safe_token = RepoCloner._validated_github_token(raw)
            except ValueError as e:
                raise CloneError(
                    "Invalid github_token or GITHUB_TOKEN format. "
                    "Use a personal access token (ghp_... or github_pat_...)."
                ) from e

        clone_env = os.environ.copy()
        clone_env["GIT_TERMINAL_PROMPT"] = "0"
        if safe_token:
            # Pass http.extraHeader via env so the token never appears in subprocess argv.
            # See git(1) GIT_CONFIG_COUNT / GIT_CONFIG_KEY_* / GIT_CONFIG_VALUE_*.
            clone_env["GIT_CONFIG_COUNT"] = "1"
            clone_env["GIT_CONFIG_KEY_0"] = "http.extraheader"
            clone_env["GIT_CONFIG_VALUE_0"] = f"AUTHORIZATION: bearer {safe_token}"

        # Create unique directory for this clone (must stay under base_dir).
        base_resolved = self.base_dir.resolve()
        clone_dir = (self.base_dir / f"{safe_owner}_{safe_repo}_{os.getpid()}").resolve()
        try:
            clone_dir.relative_to(base_resolved)
        except ValueError:
            raise ValueError("Invalid clone directory path") from None
        clone_dir_str = str(clone_dir)

        try:
            # Clone with --no-checkout so no files are written yet.
            # --depth 1 + --filter=tree:0 skips all tree and blob objects
            # until we explicitly ask for them via sparse-checkout.
            # Use list args + -- separator + shell=False to avoid command injection sinks.
            clone_cmd = [
                "git", "clone",
                "--depth", "1",
                "--filter=tree:0",
                "--no-checkout",
            ]
            if safe_branch:
                clone_cmd.extend(["-b", safe_branch])
            clone_cmd.extend(["--", repo_url, clone_dir_str])

            result = subprocess.run(
                clone_cmd,
                capture_output=True,
                text=True,
                timeout=60,
                shell=False,
                env=clone_env,
            )

            if result.returncode != 0:
                # Sanitize stderr before surfacing it — the URL may contain the token.
                sanitized_stderr = (
                    result.stderr.replace(repo_url, public_repo_url) if safe_token else result.stderr
                )
                raise CloneError(
                    _clone_failure_user_message(sanitized_stderr, safe_token is not None)
                ) from None

            # Configure sparse-checkout before any checkout happens.
            subprocess.run(
                ["git", "-C", clone_dir_str, "sparse-checkout", "init", "--cone"],
                capture_output=True,
                text=True,
                timeout=15,
                check=False,
                shell=False,
                env=clone_env,
            )
            subprocess.run(
                ["git", "-C", clone_dir_str, "sparse-checkout", "set", ".github/workflows"],
                capture_output=True,
                text=True,
                timeout=15,
                check=False,
                shell=False,
                env=clone_env,
            )

            # Single checkout: only fetches blobs for .github/workflows.
            result = subprocess.run(
                ["git", "-C", clone_dir_str, "checkout"],
                capture_output=True,
                text=True,
                timeout=60,
                shell=False,
                env=clone_env,
            )

            if result.returncode != 0:
                # Fallback for older Git: non-cone sparse-checkout
                sparse_config = Path(clone_dir) / ".git" / "info" / "sparse-checkout"
                sparse_config.parent.mkdir(parents=True, exist_ok=True)
                with open(sparse_config, 'w') as f:
                    f.write(".github/workflows/*\n")
                subprocess.run(
                    ["git", "-C", clone_dir_str, "checkout"],
                    capture_output=True,
                    text=True,
                    timeout=60,
                    shell=False,
                    env=clone_env,
                )

                logger.warning(
                    "Sparse checkout fallback used for %s/%s",
                    safe_owner,
                    safe_repo,
                )

            return clone_dir_str, clone_dir_str

        except subprocess.TimeoutExpired as e:
            raise CloneError("Repository clone timed out. Try again, or use the API method instead of clone.") from e
        except CloneError:
            if clone_dir.exists():
                shutil.rmtree(clone_dir, ignore_errors=True)
            raise
        except Exception:
            # Cleanup on error
            if clone_dir.exists():
                shutil.rmtree(clone_dir, ignore_errors=True)
            raise

    @staticmethod
    def _validated_repo_slug(value: str, field_name: str) -> str:
        """Return owner/repo slug after strict validation (allowlisted characters only)."""
        if not isinstance(value, str) or not value:
            raise ValueError(f"Invalid {field_name}")
        if "/" in value or value.startswith("-"):
            raise ValueError(f"Invalid {field_name}")
        m = re.fullmatch(r"[A-Za-z0-9_.-]{1,100}", value)
        if not m:
            raise ValueError(f"Invalid {field_name}")
        return m.group(0)

    @staticmethod
    def _validated_branch_name(branch: str) -> str:
        """Validate branch names to prevent command/option injection; return the branch string."""
        if not isinstance(branch, str) or not branch:
            raise ValueError("Invalid branch name")
        if branch.startswith("-") or ".." in branch or "@{" in branch or branch.endswith("."):
            raise ValueError("Invalid branch name")
        if "\\" in branch or " " in branch or "//" in branch or branch.endswith("/"):
            raise ValueError("Invalid branch name")
        m = re.fullmatch(r"[A-Za-z0-9._/\-]{1,200}", branch)
        if not m:
            raise ValueError("Invalid branch name")
        return m.group(0)

    @staticmethod
    def _validated_github_token(token: str) -> str:
        """Validate GitHub token format and return the token string."""
        if not (re.fullmatch(r"^ghp_[A-Za-z0-9]{36}$", token) or
                re.fullmatch(r"^github_pat_[A-Za-z0-9_\-]{20,}$", token) or
                re.fullmatch(r"^[A-Za-z0-9_\-]{20,100}$", token)):
            raise ValueError("Invalid GitHub token format")
        if any(c in token for c in "@:/\\ \n\r\t'\""):
            raise ValueError("Token contains forbidden characters")
        return token

    def get_file_content(self, clone_path: str, file_path: str) -> str:
        """Read file content from cloned repository."""
        full_path = Path(clone_path) / file_path
        if not full_path.exists():
            raise FileNotFoundError(f"File not found: {file_path}")

        with open(full_path, 'r', encoding='utf-8') as f:
            return f.read()

    def get_workflow_files(self, clone_path: str) -> list:
        """Get all workflow files from cloned repository."""
        workflows_dir = Path(clone_path) / ".github" / "workflows"
        workflows = []

        if not workflows_dir.exists():
            return workflows

        for file_path in workflows_dir.glob("*.yml"):
            workflows.append({
                "name": file_path.name,
                "path": str(file_path.relative_to(clone_path))
            })

        for file_path in workflows_dir.glob("*.yaml"):
            workflows.append({
                "name": file_path.name,
                "path": str(file_path.relative_to(clone_path))
            })

        return workflows

    def cleanup(self, clone_path: str):
        """Remove cloned repository directory."""
        path = Path(clone_path)
        if path.exists():
            shutil.rmtree(path, ignore_errors=True)
