"""Configurable rule scanner that loads rules from separate YAML files."""

import re
import yaml
import os
from pathlib import Path
from typing import Dict, List, Any, Optional
from dataclasses import dataclass

from .base import BaseScanner, Vulnerability, Severity, ScanResult
from ..core.logger import get_logger

logger = get_logger(__name__)

@dataclass
class Rule:
    """Represents a single detection rule."""
    id: str
    enabled: bool
    name: str
    description: str
    patterns: List[str]
    severity: str
    tags: List[str]
    remediation: str
    exclude_patterns: List[str] = None
    exclude_files: List[str] = None
    context: Dict[str, Any] = None

class ConfigurableRuleScanner(BaseScanner):
    """Scanner that loads rules from configurable YAML files."""
    
    def __init__(self, rule_files: List[str] = None):
        """Initialize with specific rule files."""
        super().__init__()
        self._name = "ConfigurableRuleScanner"
        self._description = "Scans using configurable YAML rules"
        self._supported_formats = ["*"]  # Supports all formats
        
        # Default rule files - load all rule YAML files
        if rule_files is None:
            config_dir = Path(__file__).parent.parent.parent.parent / "config"
            rule_files = [
                config_dir / "secret_detection_rules.yaml",
                config_dir / "ml_security_rules.yaml",
                config_dir / "code_execution_rules.yaml",
                config_dir / "model_backdoor_rules.yaml"
            ]
        
        self.rule_files = rule_files
        self.rules = self._load_all_rules()
        
    def _load_all_rules(self) -> List[Rule]:
        """Load rules from all configured files."""
        all_rules = []
        
        for rule_file in self.rule_files:
            if Path(rule_file).exists():
                rules = self._load_rules_from_file(rule_file)
                all_rules.extend(rules)
                logger.info(f"Loaded {len(rules)} rules from {rule_file}")
            else:
                logger.warning(f"Rule file not found: {rule_file}")
        
        return all_rules
    
    def _load_rules_from_file(self, file_path: str) -> List[Rule]:
        """Load rules from a single YAML file."""
        rules = []
        
        try:
            with open(file_path, 'r') as f:
                config = yaml.safe_load(f)
            
            # Check if the entire file is enabled
            settings = config.get('settings', {})
            if not settings.get('enabled', True):
                logger.info(f"Rules in {file_path} are disabled")
                return rules
            
            # Load individual rules
            for rule_id, rule_data in config.get('rules', {}).items():
                # Skip if rule is disabled
                if not rule_data.get('enabled', True):
                    continue
                
                rule = Rule(
                    id=rule_id,
                    enabled=rule_data.get('enabled', True),
                    name=rule_data.get('name', rule_id),
                    description=rule_data.get('description', ''),
                    patterns=rule_data.get('patterns', []),
                    severity=rule_data.get('severity', settings.get('default_severity', 'MEDIUM')),
                    tags=rule_data.get('tags', []),
                    remediation=rule_data.get('remediation', ''),
                    exclude_patterns=rule_data.get('exclude_patterns', []),
                    exclude_files=rule_data.get('exclude_files', []),
                    context=rule_data.get('context', {})
                )
                rules.append(rule)
                
        except Exception as e:
            logger.error(f"Error loading rules from {file_path}: {e}")
        
        return rules
    
    @property
    def name(self) -> str:
        return self._name
    
    @property
    def description(self) -> str:
        return self._description
    
    @property
    def supported_formats(self) -> List[str]:
        return self._supported_formats
    
    def can_scan(self, file_path: str, parsed_data: Optional[Any] = None) -> bool:
        """Can scan any file."""
        return True
    
    def scan(self, file_path: str, parsed_data: Dict[str, Any]) -> ScanResult:
        """Scan using loaded rules."""
        vulnerabilities = []
        file_name = Path(file_path).name
        
        # Extract text content to scan
        content = self._extract_content(parsed_data)
        
        # Apply each enabled rule
        for rule in self.rules:
            # Check if file should be excluded
            if self._should_exclude_file(file_name, rule):
                continue
            
            # Check context requirements
            if not self._check_context(file_path, rule):
                continue
            
            # Check patterns
            for pattern in rule.patterns:
                matches = self._find_matches(pattern, content, rule)
                
                for match_text, position in matches:
                    vulnerabilities.append(Vulnerability(
                        severity=self._parse_severity(rule.severity),
                        category=rule.tags[0] if rule.tags else "security",
                        description=rule.name,
                        details=f"{rule.description}\nMatched: {match_text}",
                        remediation=rule.remediation,
                        location=f"Position {position}",
                        evidence={
                            'rule_id': rule.id,
                            'matched_pattern': pattern,
                            'matched_text': match_text,
                            'tags': rule.tags
                        }
                    ))
        
        return ScanResult(
            scanner_name=self.name,
            vulnerabilities=vulnerabilities,
            metadata={
                'rules_loaded': len(self.rules),
                'rules_checked': len([r for r in self.rules if r.enabled])
            }
        )
    
    def _extract_content(self, parsed_data: Any) -> str:
        """Extract searchable content from parsed data."""
        if isinstance(parsed_data, str):
            return parsed_data
        elif isinstance(parsed_data, dict):
            # Handle different data structures
            if 'content' in parsed_data:
                return str(parsed_data['content'])
            elif 'raw_content' in parsed_data:
                return str(parsed_data['raw_content'])
            elif 'metadata' in parsed_data:
                # Handle parsed result from YAML/Text parsers
                if isinstance(parsed_data['metadata'], dict) and 'custom_attributes' in parsed_data['metadata']:
                    attrs = parsed_data['metadata']['custom_attributes']
                    if 'raw_content' in attrs:
                        return str(attrs['raw_content'])
                    elif 'loaded_data' in attrs:
                        return str(attrs['loaded_data'])
                # Check if metadata is a ModelMetadata object
                elif hasattr(parsed_data['metadata'], 'custom_attributes'):
                    attrs = parsed_data['metadata'].custom_attributes
                    if 'raw_content' in attrs:
                        return str(attrs['raw_content'])
            # Fallback to string representation
            return str(parsed_data)
        else:
            return str(parsed_data)
    
    def _should_exclude_file(self, file_name: str, rule: Rule) -> bool:
        """Check if file should be excluded based on rule."""
        if not rule.exclude_files:
            return False
        
        for pattern in rule.exclude_files:
            if self._match_file_pattern(file_name, pattern):
                return True
        
        return False
    
    def _match_file_pattern(self, file_name: str, pattern: str) -> bool:
        """Match file name against pattern (supports wildcards)."""
        import fnmatch
        return fnmatch.fnmatch(file_name.lower(), pattern.lower())
    
    def _check_context(self, file_path: str, rule: Rule) -> bool:
        """Check if context requirements are met."""
        if not rule.context:
            return True
        
        # Check file extensions
        if 'file_extensions' in rule.context:
            ext = Path(file_path).suffix.lower()
            if ext not in rule.context['file_extensions']:
                return False
        
        return True
    
    def _find_matches(self, pattern: str, content: str, rule: Rule) -> List[tuple]:
        """Find all matches of pattern in content."""
        matches = []
        
        try:
            # Case-insensitive search
            for match in re.finditer(pattern, content, re.IGNORECASE | re.MULTILINE):
                match_text = match.group(0)
                
                # Check exclusions
                if self._should_exclude_match(match_text, rule):
                    continue
                
                matches.append((match_text, match.start()))
                
        except re.error as e:
            logger.warning(f"Invalid regex pattern '{pattern}': {e}")
        
        return matches
    
    def _should_exclude_match(self, match_text: str, rule: Rule) -> bool:
        """Check if match should be excluded."""
        if not rule.exclude_patterns:
            return False
        
        for exclude in rule.exclude_patterns:
            if exclude.lower() in match_text.lower():
                return True
        
        return False
    
    def _parse_severity(self, severity_str: str) -> Severity:
        """Parse severity string to enum."""
        severity_map = {
            'CRITICAL': Severity.CRITICAL,
            'HIGH': Severity.HIGH,
            'MEDIUM': Severity.MEDIUM,
            'LOW': Severity.LOW,
            'INFO': Severity.INFO
        }
        return severity_map.get(severity_str.upper(), Severity.MEDIUM)

# Removed specialized scanners - use ConfigurableRuleScanner directly with all YAML files