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
            # For private repos, use token in URL
            repo_url = f"https://{token}@github.com/{owner}/{repo}.git"
        
        # Create unique directory for this clone
        clone_dir = self.base_dir / f"{owner}_{repo}_{os.getpid()}"
        
        try:
            # Clone the repository with sparse checkout to only get .github/workflows
            # This is much faster and uses less disk space
            clone_cmd = [
                "git", "clone",
                "--depth", "1",
                "--filter=blob:none",
                "--sparse",
                repo_url,
                str(clone_dir)
            ]
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
            
            # Initialize sparse checkout (if not already done by --sparse flag)
            # Then set it to only include .github/workflows
            sparse_init_cmd = [
                "git", "-C", str(clone_dir),
                "sparse-checkout", "init", "--cone"
            ]
            subprocess.run(
                sparse_init_cmd,
                capture_output=True,
                text=True,
                timeout=30,
                check=False  # Don't fail if already initialized
            )
            
            # Set sparse checkout to only .github/workflows
            sparse_set_cmd = [
                "git", "-C", str(clone_dir),
                "sparse-checkout", "set",
                ".github/workflows"
            ]
            
            result = subprocess.run(
                sparse_set_cmd,
                capture_output=True,
                text=True,
                timeout=30
            )
            
            if result.returncode != 0:
                # Fallback: try without --cone mode
                sparse_init_no_cone_cmd = [
                    "git", "-C", str(clone_dir),
                    "sparse-checkout", "init", "--no-cone"
                ]
                subprocess.run(sparse_init_no_cone_cmd, capture_output=True, text=True, timeout=30, check=False)
                
                # Write sparse checkout config manually
                sparse_config = Path(clone_dir) / ".git" / "info" / "sparse-checkout"
                sparse_config.parent.mkdir(parents=True, exist_ok=True)
                with open(sparse_config, 'w') as f:
                    f.write(".github/workflows/*\n")
            
            # Checkout the sparse files
            checkout_cmd = [
                "git", "-C", str(clone_dir),
                "checkout"
            ]
            
            result = subprocess.run(
                checkout_cmd,
                capture_output=True,
                text=True,
                timeout=60
            )
            
            if result.returncode != 0:
                # If sparse checkout fails completely, fall back to full clone
                print(f"Warning: Sparse checkout failed, falling back to full clone. Error: {result.stderr}")
                # The clone already happened, so we can still use it, just with all files
            
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

