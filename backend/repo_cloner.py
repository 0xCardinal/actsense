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
        repo_url = f"https://github.com/{owner}/{repo}.git"
        
        # Use token in URL if provided (for private repos)
        if token:
            # Validate token: only allow alphanumeric, underscore, and dash, typical of GitHub tokens (minimum 20, maximum 100 characters for sanity)
            if not re.fullmatch(r'^[A-Za-z0-9_\-]{20,100}$', token):
                raise ValueError("Invalid GitHub token format")
            # For private repos, use token in URL
            repo_url = f"https://{token}@github.com/{owner}/{repo}.git"
        
        # Create unique directory for this clone
        clone_dir = self.base_dir / f"{owner}_{repo}_{os.getpid()}"
        
        try:
            # Clone the repository
            clone_cmd = ["git", "clone", "--depth", "1", repo_url, str(clone_dir)]
            if branch:
                clone_cmd.extend(["-b", branch])
            
            result = subprocess.run(
                clone_cmd,
                capture_output=True,
                text=True,
                timeout=300  # 5 minute timeout
            )
            
            if result.returncode != 0:
                raise Exception(f"Git clone failed: {result.stderr}")
            
            return str(clone_dir), str(clone_dir)
        
        except subprocess.TimeoutExpired:
            raise Exception("Repository clone timed out")
        except Exception as e:
            # Cleanup on error
            if clone_dir.exists():
                shutil.rmtree(clone_dir, ignore_errors=True)
            raise
    
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

