"""Repository cloning functionality."""
import subprocess
import tempfile
import shutil
import os
from typing import Optional, Tuple
from pathlib import Path
import re
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

        clone_env: Optional[dict] = None
        if token:
            safe_token = RepoCloner._validated_github_token(token)
            clone_env = os.environ.copy()
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
                raise Exception(f"Git clone failed: {result.stderr}")
            
            # Configure sparse-checkout before any checkout happens.
            subprocess.run(
                ["git", "-C", clone_dir_str, "sparse-checkout", "init", "--cone"],
                capture_output=True,
                text=True,
                timeout=15,
                check=False,
                shell=False,
            )
            subprocess.run(
                ["git", "-C", clone_dir_str, "sparse-checkout", "set", ".github/workflows"],
                capture_output=True,
                text=True,
                timeout=15,
                check=False,
                shell=False,
            )

            # Single checkout: only fetches blobs for .github/workflows.
            result = subprocess.run(
                ["git", "-C", clone_dir_str, "checkout"],
                capture_output=True,
                text=True,
                timeout=60,
                shell=False,
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
                )

            return clone_dir_str, clone_dir_str
        
        except subprocess.TimeoutExpired:
            raise Exception("Repository clone timed out")
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

