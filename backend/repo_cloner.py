"""Repository cloning functionality."""
import subprocess
import tempfile
import shutil
import os
from typing import Optional, Tuple
from pathlib import Path
import re
from urllib.parse import quote

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
        self._validate_repo_identifier(owner, "owner")
        self._validate_repo_identifier(repo, "repository")
        if branch:
            self._validate_branch_name(branch)

        repo_url = f"https://github.com/{owner}/{repo}.git"
        
        # Use token in URL if provided (for private repos)
        if token:
            # Validate token: GitHub tokens can be:
            # - Classic tokens: ghp_ followed by 36 alphanumeric characters (40 total)
            # - Fine-grained tokens: github_pat_ followed by alphanumeric/underscore/dash (longer)
            # - Legacy tokens: alphanumeric/underscore/dash, 20-100 chars
            if not (re.fullmatch(r'^ghp_[A-Za-z0-9]{36}$', token) or
                    re.fullmatch(r'^github_pat_[A-Za-z0-9_\-]{20,}$', token) or
                    re.fullmatch(r'^[A-Za-z0-9_\-]{20,100}$', token)):
                raise ValueError("Invalid GitHub token format")
            # Additional check for forbidden characters in the token
            if any(c in token for c in '@:/\\ \n\r\t'):
                raise ValueError("Token contains forbidden characters")
            # For private repos, use token in URL. URL-encode the token to ensure safety.
            safe_token = quote(token, safe='')
            repo_url = f"https://{safe_token}@github.com/{owner}/{repo}.git"
        
        # Create unique directory for this clone
        clone_dir = self.base_dir / f"{owner}_{repo}_{os.getpid()}"
        
        try:
            # Clone with --no-checkout so no files are written yet.
            # --depth 1 + --filter=tree:0 skips all tree and blob objects
            # until we explicitly ask for them via sparse-checkout.
            clone_cmd = [
                "git", "clone",
                "--depth", "1",
                "--filter=tree:0",
                "--no-checkout",
                repo_url,
                str(clone_dir)
            ]
            if branch:
                clone_cmd.extend(["-b", branch])
            
            result = subprocess.run(
                clone_cmd,
                capture_output=True,
                text=True,
                timeout=60
            )
            
            if result.returncode != 0:
                raise Exception(f"Git clone failed: {result.stderr}")
            
            # Configure sparse-checkout before any checkout happens.
            subprocess.run(
                ["git", "-C", str(clone_dir), "sparse-checkout", "init", "--cone"],
                capture_output=True, text=True, timeout=15, check=False,
            )
            subprocess.run(
                ["git", "-C", str(clone_dir), "sparse-checkout", "set", ".github/workflows"],
                capture_output=True, text=True, timeout=15, check=False,
            )
            
            # Single checkout: only fetches blobs for .github/workflows.
            result = subprocess.run(
                ["git", "-C", str(clone_dir), "checkout"],
                capture_output=True, text=True, timeout=60,
            )
            
            if result.returncode != 0:
                # Fallback for older Git: non-cone sparse-checkout
                sparse_config = Path(clone_dir) / ".git" / "info" / "sparse-checkout"
                sparse_config.parent.mkdir(parents=True, exist_ok=True)
                with open(sparse_config, 'w') as f:
                    f.write(".github/workflows/*\n")
                subprocess.run(
                    ["git", "-C", str(clone_dir), "checkout"],
                    capture_output=True, text=True, timeout=60,
                )
            
            return str(clone_dir), str(clone_dir)
        
        except subprocess.TimeoutExpired:
            raise Exception("Repository clone timed out")
        except Exception as e:
            # Cleanup on error
            if clone_dir.exists():
                shutil.rmtree(clone_dir, ignore_errors=True)
            raise

    @staticmethod
    def _validate_repo_identifier(value: str, field_name: str) -> None:
        """Validate owner/repository identifiers before using them in git commands."""
        if not isinstance(value, str) or not value:
            raise ValueError(f"Invalid {field_name}")
        if "/" in value or value.startswith("-"):
            raise ValueError(f"Invalid {field_name}")
        if not re.fullmatch(r"[A-Za-z0-9_.-]{1,100}", value):
            raise ValueError(f"Invalid {field_name}")

    @staticmethod
    def _validate_branch_name(branch: str) -> None:
        """Validate branch names to prevent command/option injection."""
        if not isinstance(branch, str) or not branch:
            raise ValueError("Invalid branch name")
        if branch.startswith("-") or ".." in branch or "@{" in branch or branch.endswith("."):
            raise ValueError("Invalid branch name")
        if "\\" in branch or " " in branch or "//" in branch or branch.endswith("/"):
            raise ValueError("Invalid branch name")
        if not re.fullmatch(r"[A-Za-z0-9._/\-]{1,200}", branch):
            raise ValueError("Invalid branch name")
    
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

