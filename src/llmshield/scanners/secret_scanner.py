"""
Secret Scanner - A specialized scanner for detecting secrets using YAML rules.
This is a wrapper around YamlRuleScanner focused on secret detection.
"""

from typing import Dict, Any, List
from pathlib import Path
from fnmatch import fnmatch

from .yaml_rule_scanner import YamlRuleScanner
from .base import ScanResult
from ..core.logger import get_logger

logger = get_logger(__name__)


class SecretScanner(YamlRuleScanner):
    """Scanner specifically for detecting hardcoded secrets and credentials."""
    
    def __init__(self, config: Dict[str, Any] = None):
        # Extract config_path from config if provided, otherwise use default
        config_path = config.get('rules_path', None) if config else None
        super().__init__(config_path)
        self._name = "SecretScanner"
        self._description = "Detects hardcoded secrets, API keys, passwords, and credentials"
        self._supported_formats = ["*"]  # Works with all formats
    
    @property
    def name(self) -> str:
        return self._name
    
    @property
    def description(self) -> str:
        return self._description
    
    @property
    def supported_formats(self) -> List[str]:
        return self._supported_formats
    
    def can_scan(self, file_path: Any, parsed_data: Dict[str, Any]) -> bool:
        """Can scan any parsed file."""
        return True
    
    def scan(self, file_path: str, parsed_data: Dict[str, Any]) -> ScanResult:
        """Scan for secrets using YAML-defined rules."""
        # Check if this file should be excluded for secrets scanning
        filename = Path(file_path).name
        exclusions = self.config.get('exclusions', {}).get('scanner_exclusions', {})
        
        # Check vocabulary files exclusion
        vocab_patterns = exclusions.get('vocabulary_files', {}).get('patterns', [])
        skip_scanners = exclusions.get('vocabulary_files', {}).get('skip_scanners', [])
        
        for pattern in vocab_patterns:
            # Handle ** patterns by removing the prefix
            if pattern.startswith('**/'):
                pattern = pattern[3:]
            if fnmatch(filename, pattern) and 'secrets' in skip_scanners:
                logger.debug(f"Skipping secrets scan for vocabulary file: {filename}")
                return ScanResult(
                    scanner_name=self.name,
                    vulnerabilities=[],
                    metadata={'skipped': True, 'reason': 'Vocabulary file excluded'}
                )
        
        # Use parent's scan method
        result = super().scan(file_path, parsed_data)
        
        # Filter to only include secret-related vulnerabilities
        secret_vulnerabilities = []
        for vuln in result.vulnerabilities:
            # Check evidence field (dict) instead of details (string)
            if (vuln.evidence.get('category') == 'secrets' or 
                vuln.category == 'secrets' or
                'SECRET' in str(vuln.evidence.get('rule_id', '')).upper() or
                'ENTROPY' in str(vuln.evidence.get('rule_id', '')).upper()):
                secret_vulnerabilities.append(vuln)
        
        return ScanResult(
            scanner_name=self.name,
            vulnerabilities=secret_vulnerabilities,
            metadata={
                **result.metadata,
                'scanner_type': 'secrets',
                'total_rules': len([r for r in self.rules if r.category == 'secrets'])
            }
        )