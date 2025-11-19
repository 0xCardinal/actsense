"""Tests for config_loader.py"""
import pytest
import tempfile
import os
import yaml
from pathlib import Path
from config_loader import ConfigLoader, get_trusted_publishers, reload_config


class TestConfigLoader:
    """Test ConfigLoader class."""
    
    def test_init_with_custom_path(self):
        """Test initialization with custom config path."""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.yaml', delete=False) as f:
            f.write("trusted_publishers:\n  - actions/")
            config_path = f.name
        
        try:
            loader = ConfigLoader(config_path=config_path)
            assert loader.config_path == Path(config_path)
        finally:
            os.unlink(config_path)
    
    def test_init_with_env_var(self, monkeypatch):
        """Test initialization with environment variable."""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.yaml', delete=False) as f:
            f.write("trusted_publishers:\n  - actions/")
            env_path = f.name
        
        try:
            monkeypatch.setenv("TRUSTED_PUBLISHERS_CONFIG", env_path)
            loader = ConfigLoader()
            assert loader.config_path == Path(env_path)
        finally:
            os.unlink(env_path)
    
    def test_init_with_default_path(self):
        """Test initialization with default config path."""
        loader = ConfigLoader()
        expected = Path(__file__).parent.parent / "config.yaml"
        assert loader.config_path == expected
    
    def test_load_trusted_publishers_valid(self):
        """Test loading valid trusted publishers."""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.yaml', delete=False) as f:
            yaml.dump({
                "trusted_publishers": [
                    "actions/",
                    "github/",
                    "microsoft/"
                ]
            }, f)
            config_path = f.name
        
        try:
            loader = ConfigLoader(config_path=config_path)
            publishers = loader.load_trusted_publishers()
            assert "actions/" in publishers
            assert "github/" in publishers
            assert "microsoft/" in publishers
        finally:
            os.unlink(config_path)
    
    def test_load_trusted_publishers_missing_file(self):
        """Test loading when config file doesn't exist."""
        loader = ConfigLoader(config_path="/nonexistent/path/config.yaml")
        publishers = loader.load_trusted_publishers()
        # Should return defaults
        assert isinstance(publishers, list)
        assert len(publishers) > 0
        assert "actions/" in publishers
    
    def test_load_trusted_publishers_empty_file(self):
        """Test loading empty config file."""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.yaml', delete=False) as f:
            f.write("")
            config_path = f.name
        
        try:
            loader = ConfigLoader(config_path=config_path)
            publishers = loader.load_trusted_publishers()
            # Should return defaults
            assert isinstance(publishers, list)
            assert len(publishers) > 0
        finally:
            os.unlink(config_path)
    
    def test_load_trusted_publishers_none_value(self):
        """Test loading config with None value."""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.yaml', delete=False) as f:
            yaml.dump(None, f)
            config_path = f.name
        
        try:
            loader = ConfigLoader(config_path=config_path)
            publishers = loader.load_trusted_publishers()
            # Should return defaults
            assert isinstance(publishers, list)
            assert len(publishers) > 0
        finally:
            os.unlink(config_path)
    
    def test_load_trusted_publishers_not_list(self):
        """Test loading config where trusted_publishers is not a list."""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.yaml', delete=False) as f:
            yaml.dump({
                "trusted_publishers": "not a list"
            }, f)
            config_path = f.name
        
        try:
            loader = ConfigLoader(config_path=config_path)
            publishers = loader.load_trusted_publishers()
            # Should return defaults
            assert isinstance(publishers, list)
            assert len(publishers) > 0
        finally:
            os.unlink(config_path)
    
    def test_load_trusted_publishers_empty_list(self):
        """Test loading config with empty list."""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.yaml', delete=False) as f:
            yaml.dump({
                "trusted_publishers": []
            }, f)
            config_path = f.name
        
        try:
            loader = ConfigLoader(config_path=config_path)
            publishers = loader.load_trusted_publishers()
            # Should return defaults
            assert isinstance(publishers, list)
            assert len(publishers) > 0
        finally:
            os.unlink(config_path)
    
    def test_load_trusted_publishers_without_slash(self):
        """Test loading publishers without trailing slash."""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.yaml', delete=False) as f:
            yaml.dump({
                "trusted_publishers": [
                    "actions",
                    "github"
                ]
            }, f)
            config_path = f.name
        
        try:
            loader = ConfigLoader(config_path=config_path)
            publishers = loader.load_trusted_publishers()
            assert "actions/" in publishers
            assert "github/" in publishers
        finally:
            os.unlink(config_path)
    
    def test_load_trusted_publishers_filters_empty_strings(self):
        """Test that empty strings are filtered out."""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.yaml', delete=False) as f:
            yaml.dump({
                "trusted_publishers": [
                    "actions/",
                    "",
                    "  ",
                    "github/"
                ]
            }, f)
            config_path = f.name
        
        try:
            loader = ConfigLoader(config_path=config_path)
            publishers = loader.load_trusted_publishers()
            assert "actions/" in publishers
            assert "github/" in publishers
            assert "" not in publishers
            assert "  /" not in publishers
        finally:
            os.unlink(config_path)
    
    def test_load_trusted_publishers_invalid_yaml(self, capsys):
        """Test loading invalid YAML."""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.yaml', delete=False) as f:
            f.write("invalid: yaml: [")
            config_path = f.name
        
        try:
            loader = ConfigLoader(config_path=config_path)
            publishers = loader.load_trusted_publishers()
            # Should return defaults
            assert isinstance(publishers, list)
            assert len(publishers) > 0
            # Should print warning
            captured = capsys.readouterr()
            assert "Warning" in captured.out or "Warning" in captured.err
        finally:
            os.unlink(config_path)
    
    def test_get_default_trusted_publishers(self):
        """Test getting default trusted publishers."""
        loader = ConfigLoader(config_path="/nonexistent/path.yaml")
        publishers = loader._get_default_trusted_publishers()
        assert isinstance(publishers, list)
        assert "actions/" in publishers
        assert "github/" in publishers
        assert "microsoft/" in publishers
    
    def test_add_trusted_publisher_new(self):
        """Test adding a new trusted publisher."""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.yaml', delete=False) as f:
            yaml.dump({
                "trusted_publishers": ["actions/"]
            }, f)
            config_path = f.name
        
        try:
            loader = ConfigLoader(config_path=config_path)
            result = loader.add_trusted_publisher("github")
            assert result is True
            
            # Verify it was added
            publishers = loader.load_trusted_publishers()
            assert "actions/" in publishers
            assert "github/" in publishers
        finally:
            os.unlink(config_path)
    
    def test_add_trusted_publisher_existing(self):
        """Test adding an existing trusted publisher."""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.yaml', delete=False) as f:
            yaml.dump({
                "trusted_publishers": ["actions/"]
            }, f)
            config_path = f.name
        
        try:
            loader = ConfigLoader(config_path=config_path)
            result = loader.add_trusted_publisher("actions")
            assert result is True  # Should return True even if exists
            
            # Verify no duplicates
            publishers = loader.load_trusted_publishers()
            assert publishers.count("actions/") == 1
        finally:
            os.unlink(config_path)
    
    def test_add_trusted_publisher_to_new_file(self):
        """Test adding publisher when config file doesn't exist."""
        with tempfile.TemporaryDirectory() as tmpdir:
            config_path = os.path.join(tmpdir, "config.yaml")
            loader = ConfigLoader(config_path=config_path)
            
            result = loader.add_trusted_publisher("test-publisher")
            assert result is True
            
            # Verify file was created and publisher added
            assert os.path.exists(config_path)
            publishers = loader.load_trusted_publishers()
            assert "test-publisher/" in publishers
    
    def test_add_trusted_publisher_invalid_config(self):
        """Test adding publisher when config file has invalid YAML."""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.yaml', delete=False) as f:
            f.write("invalid: yaml: [")
            config_path = f.name
        
        try:
            loader = ConfigLoader(config_path=config_path)
            result = loader.add_trusted_publisher("test")
            assert result is True  # Should create new config
        finally:
            os.unlink(config_path)
    
    def test_add_trusted_publisher_write_error(self, monkeypatch):
        """Test handling write error when adding publisher."""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.yaml', delete=False) as f:
            config_path = f.name
        
        try:
            loader = ConfigLoader(config_path=config_path)
            
            # Mock open to raise exception
            def mock_open(*args, **kwargs):
                raise IOError("Permission denied")
            
            monkeypatch.setattr("builtins.open", mock_open)
            
            result = loader.add_trusted_publisher("test")
            assert result is False
        finally:
            os.unlink(config_path)


class TestGlobalFunctions:
    """Test global functions."""
    
    def test_get_trusted_publishers(self):
        """Test get_trusted_publishers function."""
        publishers = get_trusted_publishers()
        assert isinstance(publishers, list)
        assert len(publishers) > 0
    
    def test_get_trusted_publishers_caching(self):
        """Test that get_trusted_publishers caches results."""
        publishers1 = get_trusted_publishers()
        publishers2 = get_trusted_publishers()
        assert publishers1 == publishers2
    
    def test_reload_config(self):
        """Test reload_config function."""
        # Should not raise error
        reload_config()
        
        # After reload, should still work
        publishers = get_trusted_publishers()
        assert isinstance(publishers, list)

