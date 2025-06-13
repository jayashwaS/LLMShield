"""Test basic setup and imports."""

import pytest
from pathlib import Path


def test_imports():
    """Test that all core modules can be imported."""
    import llmshield
    from llmshield.core import ConfigManager, LLMShieldConfig
    from llmshield.core.logger import get_logger
    from llmshield.core.exceptions import LLMShieldError
    from llmshield.cli import main
    
    assert llmshield.__version__ == "0.1.0"


def test_config_manager():
    """Test configuration manager initialization."""
    from llmshield.core.config import ConfigManager
    
    config = ConfigManager()
    assert config.config is not None
    assert config.config.scanner.max_file_size == 5 * 1024 * 1024 * 1024
    assert config.config.log_level == "INFO"


def test_logger():
    """Test logger initialization."""
    from llmshield.core.logger import setup_logger
    
    logger = setup_logger(name="test", level="DEBUG")
    assert logger is not None
    assert logger.logger.name == "test"


def test_cli_commands():
    """Test CLI command registration."""
    from llmshield.cli.main import cli
    
    # Get all registered commands
    commands = cli.commands
    expected_commands = ['scan', 'pull', 'config', 'configure', 'version', 'list-parsers']
    
    for cmd in expected_commands:
        assert cmd in commands, f"Command '{cmd}' not registered"