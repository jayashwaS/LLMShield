"""Enhanced logging configuration for LLMShield with detailed failure tracking."""

import logging
import sys
import json
import traceback
from datetime import datetime
from pathlib import Path
from typing import Optional, Dict, Any, List
from contextlib import contextmanager
import time

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


class DetailedFileHandler(logging.FileHandler):
    """Custom file handler that writes detailed JSON logs."""
    
    def emit(self, record):
        """Emit a record with additional context."""
        try:
            # Create detailed log entry
            log_entry = {
                'timestamp': datetime.utcnow().isoformat(),
                'level': record.levelname,
                'logger': record.name,
                'message': record.getMessage(),
                'module': record.module,
                'function': record.funcName,
                'line': record.lineno,
                'file': record.filename,
                'path': record.pathname,
                'process': record.process,
                'thread': record.thread,
            }
            
            # Add extra fields if present
            if hasattr(record, 'component'):
                log_entry['component'] = record.component
            if hasattr(record, 'phase'):
                log_entry['phase'] = record.phase
            if hasattr(record, 'error_type'):
                log_entry['error_type'] = record.error_type
            if hasattr(record, 'details'):
                log_entry['details'] = record.details
            if hasattr(record, 'traceback'):
                log_entry['traceback'] = record.traceback
            if hasattr(record, 'duration'):
                log_entry['duration'] = record.duration
                
            # Write JSON log
            self.stream.write(json.dumps(log_entry) + '\n')
            self.flush()
        except Exception:
            self.handleError(record)


class LLMShieldLogger:
    """Enhanced logger for LLMShield with detailed failure tracking."""
    
    def __init__(self, name: str = "llmshield", level: str = "INFO", 
                 log_file: Optional[str] = None, detailed_log_file: Optional[str] = None):
        """Initialize logger with rich handler and detailed logging."""
        self.logger = logging.getLogger(name)
        self.logger.setLevel(getattr(logging, level.upper()))
        self.log_file = log_file
        self.detailed_log_file = detailed_log_file
        
        # Track current context
        self.current_component = None
        self.current_phase = None
        self.scan_context = {}
        
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
        
        # File handlers
        if log_file:
            self._add_file_handler(log_file)
        if detailed_log_file:
            self._add_detailed_handler(detailed_log_file)
    
    def _add_file_handler(self, log_file: str):
        """Add standard file handler for logging."""
        log_path = Path(log_file)
        log_path.parent.mkdir(parents=True, exist_ok=True)
        
        file_handler = logging.FileHandler(log_path)
        file_handler.setLevel(self.logger.level)
        
        # Custom formatter that handles missing attributes
        class SafeFormatter(logging.Formatter):
            def format(self, record):
                # Add default values for missing attributes
                if not hasattr(record, 'component'):
                    record.component = 'unknown'
                if not hasattr(record, 'phase'):
                    record.phase = 'unknown'
                return super().format(record)
        
        # Detailed format for file logging
        file_format = SafeFormatter(
            '%(asctime)s - %(name)s - %(levelname)s - [%(component)s:%(phase)s] - %(filename)s:%(lineno)d - %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S'
        )
        file_handler.setFormatter(file_format)
        self.logger.addHandler(file_handler)
    
    def _add_detailed_handler(self, detailed_log_file: str):
        """Add detailed JSON file handler."""
        log_path = Path(detailed_log_file)
        log_path.parent.mkdir(parents=True, exist_ok=True)
        
        detailed_handler = DetailedFileHandler(log_path)
        detailed_handler.setLevel(logging.DEBUG)  # Capture everything
        self.logger.addHandler(detailed_handler)
    
    @contextmanager
    def component_context(self, component: str):
        """Context manager for tracking component."""
        old_component = self.current_component
        self.current_component = component
        self.debug(f"Entering component: {component}")
        start_time = time.time()
        try:
            yield
        except Exception as e:
            self.error(f"Failed in component {component}: {str(e)}", 
                      exc_info=True, component=component)
            raise
        finally:
            duration = time.time() - start_time
            self.debug(f"Exiting component: {component} (duration: {duration:.3f}s)", 
                      duration=duration)
            self.current_component = old_component
    
    @contextmanager
    def phase_context(self, phase: str):
        """Context manager for tracking execution phase."""
        old_phase = self.current_phase
        self.current_phase = phase
        self.debug(f"Starting phase: {phase}")
        start_time = time.time()
        try:
            yield
        except Exception as e:
            self.error(f"Failed in phase {phase}: {str(e)}", 
                      exc_info=True, phase=phase)
            raise
        finally:
            duration = time.time() - start_time
            self.debug(f"Completed phase: {phase} (duration: {duration:.3f}s)", 
                      duration=duration)
            self.current_phase = old_phase
    
    def _add_context(self, kwargs: Dict[str, Any]) -> Dict[str, Any]:
        """Add current context to kwargs."""
        if self.current_component and 'component' not in kwargs:
            kwargs['component'] = self.current_component
        if self.current_phase and 'phase' not in kwargs:
            kwargs['phase'] = self.current_phase
        return kwargs
    
    def debug(self, message: str, *args, **kwargs):
        """Log debug message with context."""
        kwargs = self._add_context(kwargs)
        self.logger.debug(f"[debug]{message}[/debug]", *args, extra=kwargs)
    
    def info(self, message: str, *args, **kwargs):
        """Log info message with context."""
        kwargs = self._add_context(kwargs)
        self.logger.info(f"[info]{message}[/info]", *args, extra=kwargs)
    
    def warning(self, message: str, *args, **kwargs):
        """Log warning message with context."""
        kwargs = self._add_context(kwargs)
        self.logger.warning(f"[warning]{message}[/warning]", *args, extra=kwargs)
    
    def error(self, message: str, *args, exc_info=False, **kwargs):
        """Log error message with detailed context."""
        kwargs = self._add_context(kwargs)
        
        # Capture exception details if available
        if exc_info:
            kwargs['traceback'] = traceback.format_exc()
            kwargs['error_type'] = sys.exc_info()[0].__name__ if sys.exc_info()[0] else 'Unknown'
        
        self.logger.error(f"[error]{message}[/error]", *args, exc_info=exc_info, extra=kwargs)
    
    def critical(self, message: str, *args, **kwargs):
        """Log critical message with context."""
        kwargs = self._add_context(kwargs)
        kwargs['traceback'] = traceback.format_exc()
        self.logger.critical(f"[critical]{message}[/critical]", *args, extra=kwargs)
    
    def success(self, message: str, *args, **kwargs):
        """Log success message with context."""
        kwargs = self._add_context(kwargs)
        self.logger.info(f"[success]{message}[/success]", *args, extra=kwargs)
    
    def scan(self, message: str, *args, **kwargs):
        """Log scan-related message with context."""
        kwargs = self._add_context(kwargs)
        self.logger.info(f"[scan]{message}[/scan]", *args, extra=kwargs)
    
    def vulnerability(self, message: str, severity: str = "medium", *args, **kwargs):
        """Log vulnerability finding with context."""
        kwargs = self._add_context(kwargs)
        severity_colors = {
            "low": "yellow",
            "medium": "bold yellow",
            "high": "bold red",
            "critical": "bold white on red"
        }
        color = severity_colors.get(severity.lower(), "bold yellow")
        self.logger.warning(f"[{color}]⚠️  {message}[/{color}]", *args, extra=kwargs)
    
    def safe(self, message: str, *args, **kwargs):
        """Log safe/clean finding with context."""
        kwargs = self._add_context(kwargs)
        self.logger.info(f"[safe]✅ {message}[/safe]", *args, extra=kwargs)
    
    def progress(self, message: str, *args, **kwargs):
        """Log progress message with context."""
        kwargs = self._add_context(kwargs)
        self.logger.info(f"[dim]⏳ {message}[/dim]", *args, extra=kwargs)
    
    # Specific logging methods for different phases
    def log_parsing_start(self, file_path: str, parser_type: str):
        """Log start of file parsing."""
        self.debug(f"Starting to parse {file_path} with {parser_type}", 
                  component="parser", phase="parsing", 
                  details={'file_path': str(file_path), 'parser_type': parser_type})
    
    def log_parsing_success(self, file_path: str, metadata: Dict[str, Any]):
        """Log successful parsing."""
        self.success(f"Successfully parsed {file_path}", 
                    component="parser", phase="parsing",
                    details={'file_path': str(file_path), 'metadata': metadata})
    
    def log_parsing_failure(self, file_path: str, error: Exception):
        """Log parsing failure."""
        self.error(f"Failed to parse {file_path}: {str(error)}", 
                  component="parser", phase="parsing", exc_info=True,
                  details={'file_path': str(file_path), 'error': str(error)})
    
    def log_rule_loading_start(self, config_path: str):
        """Log start of rule loading."""
        self.debug(f"Loading rules from {config_path}", 
                  component="rule_loader", phase="initialization",
                  details={'config_path': str(config_path)})
    
    def log_rule_loading_success(self, rule_count: int, categories: List[str]):
        """Log successful rule loading."""
        self.success(f"Loaded {rule_count} rules from {len(categories)} categories", 
                    component="rule_loader", phase="initialization",
                    details={'rule_count': rule_count, 'categories': categories})
    
    def log_rule_loading_failure(self, config_path: str, error: Exception):
        """Log rule loading failure."""
        self.error(f"Failed to load rules from {config_path}: {str(error)}", 
                  component="rule_loader", phase="initialization", exc_info=True,
                  details={'config_path': str(config_path), 'error': str(error)})
    
    def log_scan_start(self, file_path: str, scanner_name: str):
        """Log start of scanning."""
        self.debug(f"Starting scan of {file_path} with {scanner_name}", 
                  component="scanner", phase="scanning",
                  details={'file_path': str(file_path), 'scanner': scanner_name})
    
    def log_scan_complete(self, file_path: str, scanner_name: str, vuln_count: int):
        """Log scan completion."""
        self.info(f"Completed scan of {file_path} with {scanner_name}: {vuln_count} issues found", 
                 component="scanner", phase="scanning",
                 details={'file_path': str(file_path), 'scanner': scanner_name, 'vuln_count': vuln_count})
    
    def log_scan_failure(self, file_path: str, scanner_name: str, error: Exception):
        """Log scan failure."""
        self.error(f"Scanner {scanner_name} failed on {file_path}: {str(error)}", 
                  component="scanner", phase="scanning", exc_info=True,
                  details={'file_path': str(file_path), 'scanner': scanner_name, 'error': str(error)})
    
    def log_report_generation_start(self, format: str, output_path: Optional[str]):
        """Log start of report generation."""
        self.debug(f"Generating {format} report", 
                  component="reporter", phase="reporting",
                  details={'format': format, 'output_path': str(output_path) if output_path else None})
    
    def log_report_generation_success(self, format: str, output_path: Optional[str]):
        """Log successful report generation."""
        self.success(f"Generated {format} report successfully", 
                    component="reporter", phase="reporting",
                    details={'format': format, 'output_path': str(output_path) if output_path else None})
    
    def log_report_generation_failure(self, format: str, error: Exception):
        """Log report generation failure."""
        self.error(f"Failed to generate {format} report: {str(error)}", 
                  component="reporter", phase="reporting", exc_info=True,
                  details={'format': format, 'error': str(error)})
    
    def create_scan_summary(self, scan_id: str, files_scanned: int, total_vulns: int, 
                           duration: float, errors: List[Dict[str, Any]]):
        """Create a detailed scan summary."""
        summary = {
            'scan_id': scan_id,
            'timestamp': datetime.utcnow().isoformat(),
            'files_scanned': files_scanned,
            'total_vulnerabilities': total_vulns,
            'duration_seconds': duration,
            'errors': errors,
            'status': 'completed_with_errors' if errors else 'completed'
        }
        
        self.info(f"Scan Summary - Files: {files_scanned}, Vulnerabilities: {total_vulns}, Errors: {len(errors)}", 
                 component="scan_summary", phase="complete",
                 details=summary)
        
        return summary


# Global logger instance
logger = LLMShieldLogger()


def setup_logger(name: str = "llmshield", level: str = "INFO", 
                log_file: Optional[str] = None, detailed_log_file: Optional[str] = None) -> LLMShieldLogger:
    """Setup and return a logger instance with detailed logging."""
    # Generate default log files with timestamp
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    
    if log_file is None:
        log_dir = Path.home() / ".llmshield" / "logs"
        log_dir.mkdir(parents=True, exist_ok=True)
        log_file = str(log_dir / f"llmshield_{timestamp}.log")
    
    if detailed_log_file is None:
        log_dir = Path.home() / ".llmshield" / "logs"
        log_dir.mkdir(parents=True, exist_ok=True)
        detailed_log_file = str(log_dir / f"llmshield_detailed_{timestamp}.json")
    
    global logger
    logger = LLMShieldLogger(name, level, log_file, detailed_log_file)
    return logger


def get_logger(name: str = "llmshield") -> LLMShieldLogger:
    """Get logger instance."""
    return logger