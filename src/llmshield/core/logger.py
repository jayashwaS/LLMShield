"""Logging configuration for LLMShield."""

import logging
import sys
from datetime import datetime
from pathlib import Path
from typing import Optional

from rich.console import Console
from rich.logging import RichHandler
from rich.theme import Theme

# Custom theme for LLMShield
LLMSHIELD_THEME = Theme({
    "info": "cyan",
    "warning": "yellow",
    "error": "bold red",
    "critical": "bold white on red",
    "success": "bold green",
    "debug": "dim cyan",
    "scan": "bold blue",
    "vulnerability": "bold yellow",
    "safe": "green",
})

console = Console(theme=LLMSHIELD_THEME)


class LLMShieldLogger:
    """Custom logger for LLMShield with rich formatting."""
    
    def __init__(self, name: str = "llmshield", level: str = "INFO", log_file: Optional[str] = None):
        """Initialize logger with rich handler."""
        self.logger = logging.getLogger(name)
        self.logger.setLevel(getattr(logging, level.upper()))
        
        # Remove existing handlers
        self.logger.handlers.clear()
        
        # Console handler with rich formatting
        console_handler = RichHandler(
            console=console,
            show_time=True,
            show_path=False,
            markup=True,
            rich_tracebacks=True,
            tracebacks_show_locals=True,
        )
        console_handler.setLevel(getattr(logging, level.upper()))
        
        # Custom format
        console_format = logging.Formatter("%(message)s")
        console_handler.setFormatter(console_format)
        self.logger.addHandler(console_handler)
        
        # File handler if specified
        if log_file:
            self._add_file_handler(log_file)
    
    def _add_file_handler(self, log_file: str):
        """Add file handler for logging to file."""
        log_path = Path(log_file)
        log_path.parent.mkdir(parents=True, exist_ok=True)
        
        file_handler = logging.FileHandler(log_path)
        file_handler.setLevel(self.logger.level)
        
        # Detailed format for file logging
        file_format = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(filename)s:%(lineno)d - %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S'
        )
        file_handler.setFormatter(file_format)
        self.logger.addHandler(file_handler)
    
    def debug(self, message: str, *args, **kwargs):
        """Log debug message."""
        self.logger.debug(f"[debug]{message}[/debug]", *args, **kwargs)
    
    def info(self, message: str, *args, **kwargs):
        """Log info message."""
        self.logger.info(f"[info]{message}[/info]", *args, **kwargs)
    
    def warning(self, message: str, *args, **kwargs):
        """Log warning message."""
        self.logger.warning(f"[warning]{message}[/warning]", *args, **kwargs)
    
    def error(self, message: str, *args, **kwargs):
        """Log error message."""
        self.logger.error(f"[error]{message}[/error]", *args, **kwargs)
    
    def critical(self, message: str, *args, **kwargs):
        """Log critical message."""
        self.logger.critical(f"[critical]{message}[/critical]", *args, **kwargs)
    
    def success(self, message: str, *args, **kwargs):
        """Log success message."""
        self.logger.info(f"[success]{message}[/success]", *args, **kwargs)
    
    def scan(self, message: str, *args, **kwargs):
        """Log scan-related message."""
        self.logger.info(f"[scan]{message}[/scan]", *args, **kwargs)
    
    def vulnerability(self, message: str, severity: str = "medium", *args, **kwargs):
        """Log vulnerability finding."""
        severity_colors = {
            "low": "yellow",
            "medium": "bold yellow",
            "high": "bold red",
            "critical": "bold white on red"
        }
        color = severity_colors.get(severity.lower(), "bold yellow")
        self.logger.warning(f"[{color}]⚠️  {message}[/{color}]", *args, **kwargs)
    
    def safe(self, message: str, *args, **kwargs):
        """Log safe/clean finding."""
        self.logger.info(f"[safe]✅ {message}[/safe]", *args, **kwargs)
    
    def progress(self, message: str, *args, **kwargs):
        """Log progress message."""
        self.logger.info(f"[dim]⏳ {message}[/dim]", *args, **kwargs)


# Global logger instance
logger = LLMShieldLogger()


def setup_logger(name: str = "llmshield", level: str = "INFO", log_file: Optional[str] = None) -> LLMShieldLogger:
    """Setup and return a logger instance."""
    return LLMShieldLogger(name, level, log_file)


def get_logger(name: str = "llmshield") -> LLMShieldLogger:
    """Get logger instance."""
    return logger