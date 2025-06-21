"""
Exclusion-aware scanner wrapper that properly handles file-based exclusions.
"""

import yaml
from pathlib import Path
from typing import Dict, Any, List, Optional
from fnmatch import fnmatch

from .base import BaseScanner, ScanResult, Vulnerability
from ..core.logger import get_logger

logger = get_logger(__name__)


class ExclusionAwareScanner:
    """Wrapper that applies exclusion rules before running scanners."""
    
    def __init__(self, scanner: BaseScanner, config_path: Optional[str] = None):
        self.scanner = scanner
        self.config_path = config_path or self._get_default_config_path()
        self.exclusions = self._load_exclusions()
        
    def _get_default_config_path(self) -> str:
        """Get the default detection rules config path."""
        return str(Path(__file__).parent.parent.parent.parent / "config" / "detection_rules.yaml")
        
    def _load_exclusions(self) -> Dict[str, Any]:
        """Load exclusion rules from config."""
        try:
            with open(self.config_path, 'r') as f:
                config = yaml.safe_load(f)
                return config.get('exclusions', {})
        except Exception as e:
            logger.warning(f"Could not load exclusions from {self.config_path}: {e}")
            return {}
    
    def should_skip_scanner(self, file_path: str) -> bool:
        """Check if this scanner should be skipped for this file."""
        filename = Path(file_path).name
        scanner_name = self.scanner.name
        
        # Check scanner-specific exclusions
        scanner_exclusions = self.exclusions.get('scanner_exclusions', {})
        
        for category, rules in scanner_exclusions.items():
            patterns = rules.get('patterns', [])
            
            # Check if file matches any pattern
            file_matches = False
            for pattern in patterns:
                if fnmatch(filename, pattern):
                    file_matches = True
                    break
                    
            if file_matches:
                # Check if this scanner should be skipped
                skip_scanners = rules.get('skip_scanners', [])
                
                # Map scanner names to rule categories
                scanner_category_map = {
                    'CodeScanner': 'code_execution',
                    'SecretScanner': 'secrets',
                    'PatternScanner': 'secrets',  # PatternScanner also detects secrets
                    'SignatureScanner': 'malware'
                }
                
                scanner_category = scanner_category_map.get(scanner_name, scanner_name.lower())
                
                if scanner_category in skip_scanners:
                    logger.debug(f"Skipping {scanner_name} for {filename} based on exclusion rules")
                    return True
                    
        return False
    
    def scan(self, file_path: str, parsed_data: Dict[str, Any]) -> ScanResult:
        """Scan with exclusion rules applied."""
        # Check if we should skip this scanner for this file
        if self.should_skip_scanner(file_path):
            return ScanResult(
                scanner_name=self.scanner.name,
                vulnerabilities=[],
                metadata={'skipped': True, 'reason': 'File excluded by rules'}
            )
            
        # Otherwise, run the scanner normally
        return self.scanner.scan(file_path, parsed_data)
    
    # Delegate other methods to the wrapped scanner
    def __getattr__(self, name):
        return getattr(self.scanner, name)