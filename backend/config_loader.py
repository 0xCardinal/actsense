"""Configuration loader for trusted action publishers."""
import os
import yaml
from typing import List
from pathlib import Path


class ConfigLoader:
    """Load and manage application configuration."""
    
    def __init__(self, config_path: str = None):
        """Initialize config loader.
        
        Args:
            config_path: Optional path to config file. If not provided, looks for:
                        1. TRUSTED_PUBLISHERS_CONFIG environment variable
                        2. config.yaml in the backend directory
        """
        if config_path:
            self.config_path = Path(config_path)
        else:
            # Check environment variable first
            env_config = os.getenv("TRUSTED_PUBLISHERS_CONFIG")
            if env_config:
                self.config_path = Path(env_config)
            else:
                # Default to config.yaml in backend directory
                self.config_path = Path(__file__).parent / "config.yaml"
    
    def load_trusted_publishers(self) -> List[str]:
        """Load trusted publishers from config file.
        
        Returns:
            List of trusted publisher prefixes (e.g., ["actions/", "github/"])
            
        Raises:
            FileNotFoundError: If config file doesn't exist
            yaml.YAMLError: If config file is invalid YAML
        """
        if not self.config_path.exists():
            # Return default trusted publishers if config file doesn't exist
            return self._get_default_trusted_publishers()
        
        try:
            with open(self.config_path, 'r') as f:
                config = yaml.safe_load(f)
            
            if not config:
                return self._get_default_trusted_publishers()
            
            trusted_publishers = config.get("trusted_publishers", [])
            
            # Validate that it's a list
            if not isinstance(trusted_publishers, list):
                return self._get_default_trusted_publishers()
            
            # Filter out empty strings and validate format
            valid_publishers = []
            for publisher in trusted_publishers:
                if isinstance(publisher, str) and publisher.strip():
                    # Ensure it ends with / for prefix matching
                    publisher = publisher.strip()
                    if not publisher.endswith("/"):
                        publisher = publisher + "/"
                    valid_publishers.append(publisher)
            
            # If no valid publishers found, return defaults
            if not valid_publishers:
                return self._get_default_trusted_publishers()
            
            return valid_publishers
            
        except (yaml.YAMLError, Exception) as e:
            # If there's an error loading config, return defaults
            print(f"Warning: Failed to load config from {self.config_path}: {e}")
            print("Using default trusted publishers.")
            return self._get_default_trusted_publishers()
    
    def _get_default_trusted_publishers(self) -> List[str]:
        """Get default trusted publishers if config file is missing or invalid."""
        return [
            "actions/",
            "github/",
            "microsoft/",
            "azure/",
            "docker/",
            "hashicorp/",
            "google-github-actions/",
            "aws-actions/",
            "step-security/",
        ]
    
    def add_trusted_publisher(self, publisher: str) -> bool:
        """Add a trusted publisher to the config file.
        
        Args:
            publisher: Publisher prefix (e.g., "elgohr/" or "elgohr")
            
        Returns:
            True if successful, False otherwise
        """
        # Ensure publisher ends with /
        publisher = publisher.strip()
        if not publisher.endswith("/"):
            publisher = publisher + "/"
        
        # Load existing config
        if self.config_path.exists():
            try:
                with open(self.config_path, 'r') as f:
                    config = yaml.safe_load(f) or {}
            except Exception:
                config = {}
        else:
            config = {}
        
        # Get existing publishers
        trusted_publishers = config.get("trusted_publishers", [])
        if not isinstance(trusted_publishers, list):
            trusted_publishers = []
        
        # Add if not already present
        if publisher not in trusted_publishers:
            trusted_publishers.append(publisher)
            config["trusted_publishers"] = trusted_publishers
            
            # Ensure directory exists
            self.config_path.parent.mkdir(parents=True, exist_ok=True)
            
            # Write back to file
            try:
                with open(self.config_path, 'w') as f:
                    yaml.dump(config, f, default_flow_style=False, sort_keys=False)
                return True
            except Exception as e:
                print(f"Error writing config: {e}")
                return False
        
        return True  # Already exists


# Global config loader instance
_config_loader = None


def get_trusted_publishers() -> List[str]:
    """Get trusted publishers from config.
    
    This function caches the config loader and results for performance.
    To reload config, set _config_loader to None.
    
    Returns:
        List of trusted publisher prefixes
    """
    global _config_loader
    
    if _config_loader is None:
        _config_loader = ConfigLoader()
    
    return _config_loader.load_trusted_publishers()


def reload_config():
    """Reload configuration (useful for testing or after config changes)."""
    global _config_loader
    _config_loader = None

