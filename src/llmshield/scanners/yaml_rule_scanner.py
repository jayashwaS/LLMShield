"""
YAML Rule-based Scanner for flexible detection using configuration files.
"""

import re
import yaml
import os
import math
import base64
from typing import Dict, List, Any, Optional, Tuple
from pathlib import Path
from dataclasses import dataclass
from fnmatch import fnmatch

from .base import BaseScanner, Vulnerability, Severity, ScanResult
from .utils import create_vulnerability
from ..core.logger import get_logger

logger = get_logger(__name__)


@dataclass
class DetectionRule:
    """Represents a detection rule loaded from YAML."""
    id: str
    name: str
    patterns: List[str]
    severity: Severity
    description: str
    remediation: str
    tags: List[str]
    category: str


class YamlRuleScanner(BaseScanner):
    """Scanner that uses YAML configuration for detection rules."""
    
    def __init__(self, config_path: Optional[str] = None):
        super().__init__()
        self.config_path = config_path or self._get_default_config_path()
        self.rules = self._load_rules()
        self.config = self._load_config()
        self.exclusions = self._load_exclusions()
        self.allowlist = self._load_allowlist()
        self._name = "YamlRuleScanner"
        self._description = "Scans using YAML-defined detection rules"
        self._supported_formats = ["*"]
    
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
        
    def _get_default_config_path(self) -> str:
        """Get the default configuration file path."""
        # Try multiple locations - prioritize detection_rules.yaml
        possible_paths = [
            Path(__file__).parent.parent.parent.parent / "config" / "detection_rules.yaml",
            Path(__file__).parent.parent.parent.parent / "config" / "scanner_rules_consolidated.yaml",
            Path.home() / ".llmshield" / "detection_rules.yaml",
            Path("/etc/llmshield/detection_rules.yaml"),
        ]
        
        for path in possible_paths:
            if path.exists():
                return str(path)
        
        # Return the first path as default (project config)
        return str(possible_paths[0])
    
    def _load_exclusions(self) -> Dict[str, Any]:
        """Load scanner exclusions configuration from main rules file."""
        # Exclusions are now in the main detection_rules.yaml
        return self.config.get('exclusions', {})
    
    def _load_allowlist(self) -> Dict[str, Any]:
        """Load false positive allowlist from main rules file."""
        # False positive handling is now in the main detection_rules.yaml
        return self.config.get('false_positive_handling', {})
    
    def _get_file_context(self, file_path: str) -> Dict[str, Any]:
        """Get context information for the file."""
        path = Path(file_path)
        filename = path.name
        extension = path.suffix
        
        context = {
            'filename': filename,
            'extension': extension,
            'is_tokenizer': False,
            'is_config': False,
            'is_model': False
        }
        
        # Check if it's a tokenizer file
        tokenizer_patterns = self.exclusions.get('scanner_exclusions', {}).get('vocabulary_files', {}).get('patterns', [])
        for pattern in tokenizer_patterns:
            if fnmatch(filename, pattern):
                context['is_tokenizer'] = True
                break
        
        # Check if it's a config file
        config_patterns = self.exclusions.get('scanner_exclusions', {}).get('config_files', {}).get('patterns', [])
        for pattern in config_patterns:
            if fnmatch(filename, pattern):
                context['is_config'] = True
                break
        
        # Check if it's a model file
        model_patterns = self.exclusions.get('scanner_exclusions', {}).get('model_files', {}).get('patterns', [])
        for pattern in model_patterns:
            if fnmatch(filename, pattern):
                context['is_model'] = True
                break
        
        return context
    
    def _should_scan_file(self, file_path: str, file_context: Dict[str, Any]) -> bool:
        """Check if this scanner should scan this file."""
        filename = Path(file_path).name
        scanner_name = self.name
        
        # Check each file exclusion category
        for category, config in self.exclusions.get('scanner_exclusions', {}).items():
            patterns = config.get('patterns', [])
            
            # Check if file matches any pattern in this category
            matches = False
            for pattern in patterns:
                if fnmatch(filename, pattern):
                    matches = True
                    break
            
            if matches:
                # Check if this scanner is in skip list
                skip_scanners = config.get('skip_scanners', [])
                if scanner_name in skip_scanners:
                    return False
                
                # Check if allowed_scanners is defined and scanner is not in it
                allowed_scanners = config.get('allowed_scanners', [])
                if allowed_scanners and scanner_name not in allowed_scanners:
                    return False
        
        return True
    
    def _load_config(self) -> Dict[str, Any]:
        """Load the full configuration."""
        try:
            with open(self.config_path, 'r') as f:
                return yaml.safe_load(f)
        except Exception as e:
            logger.warning(f"Could not load config from {self.config_path}: {e}", 
                          component="yaml_rule_scanner", phase="initialization")
            return {}
    
    def _load_rules(self) -> List[DetectionRule]:
        """Load detection rules from YAML configuration."""
        rules = []
        categories = []
        
        # Log rule loading start
        logger.log_rule_loading_start(self.config_path)
        
        try:
            with logger.phase_context("rule_loading"):
                with open(self.config_path, 'r') as f:
                    config = yaml.safe_load(f)
                
                # Ensure config is a dictionary
                if not isinstance(config, dict):
                    logger.warning(f"Config file {self.config_path} did not load as a dictionary")
                    return rules
            
            # Check global settings
            settings = config.get('settings', {})
            all_rules_enabled = settings.get('all_rules_enabled', True)
            
            # Track loaded categories
            rule_categories = []
                
            # Load secret detection rules
            if 'secrets' in config and isinstance(config['secrets'], dict):
                categories.append('secrets')
                for rule_id, rule_data in config['secrets'].items():
                    if isinstance(rule_data, dict):
                        # Check if rule is enabled
                        rule_enabled = rule_data.get('enabled', all_rules_enabled)
                        if not rule_enabled:
                            continue
                            
                        rules.append(DetectionRule(
                            id=rule_id,
                            name=rule_data.get('name', rule_id),
                            patterns=rule_data.get('patterns', []),
                            severity=self._parse_severity(rule_data.get('severity', 'MEDIUM')),
                            description=rule_data.get('description', ''),
                            remediation=rule_data.get('remediation', ''),
                            tags=rule_data.get('tags', []),
                            category='secrets'
                        ))
            
            # Load code execution patterns
            if 'code_execution' in config and isinstance(config['code_execution'], dict):
                categories.append('code_execution')
                for rule_id, rule_data in config['code_execution'].items():
                    if isinstance(rule_data, dict):
                        rules.append(DetectionRule(
                            id=rule_id,
                            name=rule_data.get('name', rule_id),
                            patterns=rule_data.get('patterns', []),
                            severity=self._parse_severity(rule_data.get('severity', 'HIGH')),
                            description=rule_data.get('description', ''),
                            remediation=rule_data.get('remediation', ''),
                            tags=rule_data.get('tags', []),
                            category='code_execution'
                        ))
            
            # Load malware signatures
            if 'malware_signatures' in config and isinstance(config['malware_signatures'], dict):
                categories.append('malware_signatures')
                for rule_id, rule_data in config['malware_signatures'].items():
                    if isinstance(rule_data, dict):
                        rules.append(DetectionRule(
                            id=rule_id,
                            name=rule_data.get('name', rule_id),
                                patterns=rule_data.get('patterns', []),
                                severity=self._parse_severity(rule_data.get('severity', 'CRITICAL')),
                                description=rule_data.get('description', ''),
                                remediation=rule_data.get('remediation', ''),
                                tags=rule_data.get('tags', []),
                                category='malware_signatures'
                            ))
                
            # Load network exfiltration patterns
            if 'network_exfiltration' in config and isinstance(config['network_exfiltration'], dict):
                categories.append('network_exfiltration')
                for rule_id, rule_data in config['network_exfiltration'].items():
                        if isinstance(rule_data, dict):
                            rules.append(DetectionRule(
                                id=rule_id,
                                name=rule_data.get('name', rule_id),
                                patterns=rule_data.get('patterns', []),
                                severity=self._parse_severity(rule_data.get('severity', 'HIGH')),
                                description=rule_data.get('description', ''),
                                remediation=rule_data.get('remediation', ''),
                                tags=rule_data.get('tags', []),
                                category='network_exfiltration'
                            ))
                
                # Keep backward compatibility - load malicious_code if exists
            if 'malicious_code' in config and isinstance(config['malicious_code'], dict):
                categories.append('malicious_code')
                for rule_id, rule_data in config['malicious_code'].items():
                    if isinstance(rule_data, dict):
                        # Check if rule is enabled
                        rule_enabled = rule_data.get('enabled', all_rules_enabled)
                        if not rule_enabled:
                            continue
                            
                        rules.append(DetectionRule(
                            id=rule_id,
                            name=rule_data.get('name', rule_id),
                            patterns=rule_data.get('patterns', []),
                            severity=self._parse_severity(rule_data.get('severity', 'HIGH')),
                            description=rule_data.get('description', ''),
                            remediation=rule_data.get('remediation', ''),
                            tags=rule_data.get('tags', []),
                            category='malicious_code'
                        ))
            
            # Load LLM security patterns
            if 'llm_security' in config and isinstance(config['llm_security'], dict):
                categories.append('llm_security')
                for rule_id, rule_data in config['llm_security'].items():
                    if isinstance(rule_data, dict):
                        rules.append(DetectionRule(
                            id=rule_id,
                            name=rule_data.get('name', rule_id),
                            patterns=rule_data.get('patterns', []),
                            severity=self._parse_severity(rule_data.get('severity', 'HIGH')),
                            description=rule_data.get('description', ''),
                            remediation=rule_data.get('remediation', ''),
                            tags=rule_data.get('tags', []),
                            category='llm_security'
                        ))
            
            # Load suspicious string patterns
            if 'suspicious_strings' in config and isinstance(config['suspicious_strings'], dict):
                categories.append('suspicious_strings')
                for rule_id, rule_data in config['suspicious_strings'].items():
                    if isinstance(rule_data, dict):
                        rules.append(DetectionRule(
                            id=rule_id,
                            name=rule_data.get('name', rule_id),
                            patterns=rule_data.get('patterns', []),
                            severity=self._parse_severity(rule_data.get('severity', 'MEDIUM')),
                            description=rule_data.get('description', ''),
                            remediation=rule_data.get('remediation', ''),
                            tags=rule_data.get('tags', []),
                            category='suspicious_strings'
                        ))
                
            # Load PyTorch threats
            if 'pytorch_threats' in config and isinstance(config['pytorch_threats'], dict):
                categories.append('pytorch_threats')
                for rule_id, rule_data in config['pytorch_threats'].items():
                        if isinstance(rule_data, dict):
                            rules.append(DetectionRule(
                                id=rule_id,
                                name=rule_data.get('name', rule_id),
                                patterns=rule_data.get('patterns', []),
                                severity=self._parse_severity(rule_data.get('severity', 'HIGH')),
                                description=rule_data.get('description', ''),
                                remediation=rule_data.get('remediation', ''),
                                tags=rule_data.get('tags', []),
                                category='pytorch_threats'
                            ))
                
            # Load CVE patterns
            if 'cve_patterns' in config and isinstance(config['cve_patterns'], dict):
                categories.append('cve_patterns')
                for rule_id, rule_data in config['cve_patterns'].items():
                        if isinstance(rule_data, dict):
                            rules.append(DetectionRule(
                                id=rule_id,
                                name=rule_data.get('name', rule_id),
                                patterns=rule_data.get('patterns', []),
                                severity=self._parse_severity(rule_data.get('severity', 'CRITICAL')),
                                description=rule_data.get('description', ''),
                                remediation=rule_data.get('remediation', ''),
                                tags=rule_data.get('tags', []),
                                category='cve_patterns'
                            ))
                
                # Log successful rule loading
                logger.log_rule_loading_success(len(rules), categories)
                logger.debug(f"Loaded {len(rules)} rules from categories: {', '.join(categories)}")
                
        except Exception as e:
            logger.log_rule_loading_failure(self.config_path, e)
            logger.error(f"Error loading rules: {e}", exc_info=True)
            # Return empty rules list if loading fails
            
        return rules
    
    def _parse_severity(self, severity_str: str) -> Severity:
        """Parse severity string to Severity enum."""
        severity_map = {
            'CRITICAL': Severity.CRITICAL,
            'HIGH': Severity.HIGH,
            'MEDIUM': Severity.MEDIUM,
            'LOW': Severity.LOW,
            'INFO': Severity.INFO
        }
        return severity_map.get(severity_str.upper(), Severity.MEDIUM)
    
    def scan(self, file_path: str, parsed_data: Dict[str, Any]) -> ScanResult:
        """Scan using YAML-defined rules."""
        vulnerabilities = []
        
        # Check if this scanner should skip this file type
        file_context = self._get_file_context(file_path)
        if not self._should_scan_file(file_path, file_context):
            return ScanResult(
                scanner_name=self.name,
                vulnerabilities=[],
                metadata={'skipped': True, 'reason': 'File type excluded for this scanner'}
            )
        
        # Parse the data structure properly
        data_to_scan = parsed_data
        if isinstance(parsed_data, dict):
            # Check various possible data locations in order of preference
            
            # 1. Direct custom_attributes at top level (from scan_directory.py)
            if any(key in parsed_data for key in ['loaded_data', 'raw_content', 'parsed_data']):
                # This is likely custom_attributes merged at top level
                if 'loaded_data' in parsed_data:
                    actual_data = parsed_data['loaded_data']
                    data_to_scan = {'content': actual_data}
                    if isinstance(actual_data, dict):
                        data_to_scan.update(actual_data)
                elif 'parsed_data' in parsed_data:
                    actual_data = parsed_data['parsed_data']
                    data_to_scan = {'content': actual_data}
                    if isinstance(actual_data, dict):
                        data_to_scan.update(actual_data)
                elif 'raw_content' in parsed_data:
                    data_to_scan = {'raw_content': parsed_data['raw_content']}
            
            # 2. Check metadata.custom_attributes structure
            elif 'metadata' in parsed_data:
                metadata = parsed_data.get('metadata', {})
                if isinstance(metadata, dict):
                    custom_attrs = metadata.get('custom_attributes', {})
                    if isinstance(custom_attrs, dict):
                        # Check for loaded_data
                        if 'loaded_data' in custom_attrs:
                            actual_data = custom_attrs['loaded_data']
                            # Create a new dict with the actual data for scanning
                            data_to_scan = {'content': actual_data}
                            if isinstance(actual_data, dict):
                                data_to_scan.update(actual_data)
                        # Also check for parsed_data (JSON files)
                        elif 'parsed_data' in custom_attrs:
                            actual_data = custom_attrs['parsed_data']
                            data_to_scan = {'content': actual_data}
                            if isinstance(actual_data, dict):
                                data_to_scan.update(actual_data)
                        # Also check for raw_content  
                        elif 'raw_content' in custom_attrs:
                            data_to_scan = {'raw_content': custom_attrs['raw_content']}
            
            # 3. Check direct custom_attributes (legacy format)
            elif 'custom_attributes' in parsed_data:
                custom_attrs = parsed_data.get('custom_attributes', {})
                if isinstance(custom_attrs, dict):
                    if 'loaded_data' in custom_attrs:
                        actual_data = custom_attrs['loaded_data']
                        data_to_scan = {'content': actual_data}
                        if isinstance(actual_data, dict):
                            data_to_scan.update(actual_data)
                    elif 'parsed_data' in custom_attrs:
                        actual_data = custom_attrs['parsed_data']
                        data_to_scan = {'content': actual_data}
                        if isinstance(actual_data, dict):
                            data_to_scan.update(actual_data)
        
        # Extract all strings to scan
        try:
            strings_to_scan = self._extract_strings(data_to_scan)
        except Exception as e:
            # Log error and return empty result
            return ScanResult(
                scanner_name=self.name,
                vulnerabilities=[],
                error=f"Failed to extract strings: {str(e)}",
                metadata={
                    'rules_loaded': len(self.rules),
                    'error': str(e)
                }
            )
        
        # Apply rule-based detection
        # Track unique findings to avoid duplicates
        seen_findings = set()
        
        for string_content in strings_to_scan:
            # Check against all loaded rules
            rule_vulns = self._check_rules(string_content, file_path, file_context)
            for vuln in rule_vulns:
                # Create a unique key for this finding based on rule_id, line_content, and match position
                finding_key = (
                    vuln.evidence.get('rule_id', ''),
                    vuln.evidence.get('line_content', ''),
                    vuln.evidence.get('match_position', 0)
                )
                if finding_key not in seen_findings:
                    seen_findings.add(finding_key)
                    vulnerabilities.append(vuln)
            
            # Check entropy if configured
            if self.config.get('entropy_rules'):
                entropy_vulns = self._check_entropy(string_content, file_path)
                for vuln in entropy_vulns:
                    # Create unique key for entropy findings
                    finding_key = (
                        'entropy',
                        vuln.evidence.get('masked_value', ''),
                        vuln.evidence.get('length', 0)
                    )
                    if finding_key not in seen_findings:
                        seen_findings.add(finding_key)
                        vulnerabilities.append(vuln)
        
        # PyTorch-specific checks
        if parsed_data.get('type') == 'pytorch' and 'pytorch_rules' in self.config:
            pytorch_vulns = self._check_pytorch_rules(parsed_data, file_path)
            vulnerabilities.extend(pytorch_vulns)
        
        # Pickle-specific checks
        if parsed_data.get('type') == 'pickle' and 'pickle_dangerous_opcodes' in self.config:
            pickle_vulns = self._check_pickle_opcodes(parsed_data, file_path)
            vulnerabilities.extend(pickle_vulns)
        
        # Log scan completion
        logger.log_scan_complete(file_path, self.name, len(vulnerabilities))
        
        return ScanResult(
            scanner_name=self.name,
            vulnerabilities=vulnerabilities,
            metadata={
                'rules_loaded': len(self.rules),
                'strings_scanned': len(strings_to_scan),
                'config_file': self.config_path
            }
        )
    
    def _extract_strings(self, parsed_data: Any) -> List[str]:
        """Extract all string content from parsed data."""
        strings = []
        
        # Handle case where parsed_data might not be a dict
        if not isinstance(parsed_data, dict):
            # Convert to dict if possible
            if hasattr(parsed_data, 'to_dict'):
                parsed_data = parsed_data.to_dict()
            elif hasattr(parsed_data, '__dict__'):
                parsed_data = vars(parsed_data)
            elif isinstance(parsed_data, (list, tuple)):
                # Handle list/tuple by extracting strings from all elements
                for item in parsed_data:
                    if isinstance(item, str):
                        strings.append(item)
                    else:
                        strings.extend(self._extract_strings(item))
                return strings
            else:
                # For other types, convert to string and return
                return [str(parsed_data)]
        
        def extract_recursive(obj, depth=0, max_depth=10):
            if depth > max_depth:  # Prevent infinite recursion
                return
                
            if isinstance(obj, str):
                strings.append(obj)
            elif isinstance(obj, bytes):
                try:
                    strings.append(obj.decode('utf-8', errors='ignore'))
                except:
                    pass
            elif isinstance(obj, dict):
                for key, value in obj.items():
                    # Also check keys for secrets
                    if isinstance(key, str):
                        strings.append(key)
                    extract_recursive(value, depth + 1)
            elif isinstance(obj, (list, tuple)):
                for item in obj:
                    extract_recursive(item, depth + 1)
            elif hasattr(obj, '__dict__'):
                try:
                    extract_recursive(vars(obj), depth + 1)
                except:
                    pass
        
        extract_recursive(parsed_data)
        
        # Also check raw content
        if 'raw_content' in parsed_data:
            if isinstance(parsed_data['raw_content'], bytes):
                try:
                    strings.append(parsed_data['raw_content'].decode('utf-8', errors='ignore'))
                except:
                    pass
            elif isinstance(parsed_data['raw_content'], str):
                strings.append(parsed_data['raw_content'])
        
        # Also check content key (added by our data_to_scan conversion)
        if 'content' in parsed_data and isinstance(parsed_data['content'], (dict, list)):
            extract_recursive(parsed_data['content'])
        
        return strings
    
    def _check_rules(self, content: str, file_path: str, file_context: Dict[str, Any] = None) -> List[Vulnerability]:
        """Check content against all loaded rules."""
        vulnerabilities = []
        
        # Split content into lines for line number tracking
        lines = content.splitlines()
        
        for rule in self.rules:
            # Skip certain rule categories for tokenizer files
            if file_context and file_context.get('is_tokenizer'):
                if rule.category in ['code_execution', 'malicious_code'] and self.name == 'SecretScanner':
                    continue
            
            for pattern in rule.patterns:
                try:
                    matches = re.finditer(pattern, content, re.IGNORECASE | re.MULTILINE)
                    for match in matches:
                        # For tokenizer files, apply stricter validation
                        if file_context and file_context.get('is_tokenizer'):
                            matched_text = match.group(0)
                            # Skip if it's just the word "token" or similar
                            if matched_text.lower() in self.allowlist.get('allowlist_words', []):
                                continue
                            # Skip if it's an ML parameter name
                            if matched_text.lower() in self.allowlist.get('ml_parameter_names', []):
                                continue
                        # Calculate line number
                        line_start = content[:match.start()].count('\n') + 1
                        line_end = content[:match.end()].count('\n') + 1
                        
                        # Get the actual line content
                        if line_start <= len(lines):
                            line_content = lines[line_start - 1].strip()
                        else:
                            line_content = match.group(0)
                        
                        # Get context
                        start = max(0, match.start() - 50)
                        end = min(len(content), match.end() + 50)
                        context = content[start:end]
                        
                        # Mask sensitive values for secrets
                        if rule.category == 'secrets':
                            secret_value = match.group(0)
                            masked_value = self._mask_secret(secret_value)
                            masked_context = context.replace(secret_value, masked_value)
                        else:
                            masked_context = context
                            masked_value = None
                        
                        vulnerabilities.append(create_vulnerability(
                            id=f"{rule.category.upper()}-{rule.id.upper()}-{len(vulnerabilities)+1}",
                            name=rule.name,
                            severity=rule.severity,
                            description=rule.description,
                            file_path=file_path,
                            details={
                                'category': rule.category,
                                'rule_id': rule.id,
                                'tags': rule.tags,
                                'context': masked_context,
                                'match_position': match.start(),
                                'masked_value': masked_value,
                                'line_number': line_start,
                                'line_content': line_content,
                                'artifact': f"Line {line_start}: {line_content}"
                            },
                            remediation=rule.remediation,
                            category=rule.category,
                            location=f"Line {line_start}"
                        ))
                except Exception as e:
                    # Continue with other patterns
                    continue
        
        return vulnerabilities
    
    def _check_entropy(self, content: str, file_path: str) -> List[Vulnerability]:
        """Check for high entropy strings based on configuration."""
        vulnerabilities = []
        entropy_config = self.config.get('entropy_rules', {})
        
        if not entropy_config:
            return vulnerabilities
        
        threshold = entropy_config.get('high_entropy_threshold', 4.5)
        min_length = entropy_config.get('min_length', 32)
        
        # Extract potential secrets
        tokens = re.findall(r'[A-Za-z0-9+/=_\-]{20,}', content)
        
        for token in tokens:
            if len(token) < min_length:
                continue
                
            entropy = self._calculate_entropy(token)
            
            if entropy > threshold:
                characteristics = self._analyze_string_characteristics(token)
                
                # Check if it matches suspicious characteristics
                suspicious_chars = entropy_config.get('suspicious_characteristics', {})
                if self._matches_characteristics(characteristics, suspicious_chars):
                    vulnerabilities.append(create_vulnerability(
                        id=f"ENTROPY-HIGH-{len(vulnerabilities)+1}",
                        name="High Entropy String Detected",
                        severity=Severity.MEDIUM,
                        description=f"High entropy string detected (entropy: {entropy:.2f}), possibly a secret or key",
                        file_path=file_path,
                        details={
                            'entropy': entropy,
                            'length': len(token),
                            'masked_value': self._mask_secret(token),
                            'characteristics': characteristics
                        },
                        remediation="Review high entropy strings and ensure they are not hardcoded secrets.",
                        category="entropy"
                    ))
        
        return vulnerabilities
    
    def _check_pytorch_rules(self, parsed_data: Dict[str, Any], file_path: str) -> List[Vulnerability]:
        """Check PyTorch-specific rules."""
        vulnerabilities = []
        pytorch_config = self.config.get('pytorch_rules', {})
        
        if not pytorch_config or 'content' not in parsed_data:
            return vulnerabilities
        
        state_dict = parsed_data.get('content', {})
        if not isinstance(state_dict, dict):
            return vulnerabilities
        
        # Check for suspicious keys
        suspicious_keys = pytorch_config.get('suspicious_keys', [])
        for key in state_dict.keys():
            key_lower = key.lower()
            for suspicious in suspicious_keys:
                if suspicious.lower() in key_lower:
                    vulnerabilities.append(create_vulnerability(
                        id=f"PYTORCH-SUSPICIOUS-KEY-{len(vulnerabilities)+1}",
                        name="Suspicious Key in PyTorch Model",
                        severity=Severity.HIGH,
                        description=f"Model contains suspicious key: {key}",
                        file_path=file_path,
                        details={
                            'key_name': key,
                            'matched_pattern': suspicious
                        },
                        remediation="Remove sensitive or suspicious keys from model state dict.",
                        category="pytorch"
                    ))
        
        # Check for suspicious attributes
        suspicious_attrs = pytorch_config.get('suspicious_attributes', [])
        for attr in suspicious_attrs:
            if attr in state_dict:
                vulnerabilities.append(create_vulnerability(
                    id=f"PYTORCH-SUSPICIOUS-ATTR-{len(vulnerabilities)+1}",
                    name="Suspicious Attribute in PyTorch Model",
                    severity=Severity.HIGH,
                    description=f"Model contains suspicious attribute: {attr}",
                    file_path=file_path,
                    details={
                        'attribute_name': attr,
                        'attribute_type': type(state_dict[attr]).__name__
                    },
                    remediation="Review and remove suspicious attributes that may contain malicious code.",
                    category="pytorch"
                ))
        
        return vulnerabilities
    
    def _check_pickle_opcodes(self, parsed_data: Dict[str, Any], file_path: str) -> List[Vulnerability]:
        """Check for dangerous pickle opcodes."""
        vulnerabilities = []
        dangerous_opcodes = self.config.get('pickle_dangerous_opcodes', [])
        
        if not dangerous_opcodes or 'opcodes' not in parsed_data:
            return vulnerabilities
        
        for opcode in parsed_data.get('opcodes', []):
            opcode_name = opcode.get('name', '')
            if opcode_name in dangerous_opcodes:
                vulnerabilities.append(create_vulnerability(
                    id=f"PICKLE-DANGEROUS-OPCODE-{len(vulnerabilities)+1}",
                    name=f"Dangerous Pickle Opcode: {opcode_name}",
                    severity=Severity.HIGH,
                    description=f"Dangerous pickle opcode '{opcode_name}' detected which can execute arbitrary code",
                    file_path=file_path,
                    details={
                        'opcode': opcode_name,
                        'position': opcode.get('pos', 'unknown'),
                        'arg': str(opcode.get('arg', ''))[:100]
                    },
                    remediation="Avoid using pickle format. Use safer alternatives like JSON or NPY formats.",
                    category="pickle"
                ))
        
        return vulnerabilities
    
    def _calculate_entropy(self, string: str) -> float:
        """Calculate Shannon entropy of a string."""
        if not string:
            return 0.0
        
        char_counts = {}
        for char in string:
            char_counts[char] = char_counts.get(char, 0) + 1
        
        entropy = 0.0
        length = len(string)
        for count in char_counts.values():
            probability = count / length
            if probability > 0:
                entropy -= probability * math.log2(probability)
        
        return entropy
    
    def _mask_secret(self, secret: str) -> str:
        """Mask a secret value for safe display."""
        if len(secret) <= 8:
            return "*" * len(secret)
        return f"{secret[:3]}{'*' * (len(secret) - 6)}{secret[-3:]}"
    
    def _analyze_string_characteristics(self, string: str) -> Dict[str, bool]:
        """Analyze string characteristics."""
        return {
            'has_uppercase': any(c.isupper() for c in string),
            'has_lowercase': any(c.islower() for c in string),
            'has_digits': any(c.isdigit() for c in string),
            'has_special': any(not c.isalnum() for c in string),
            'looks_random': self._calculate_entropy(string) > 4.0,
            'is_hex': all(c in '0123456789abcdefABCDEF' for c in string),
            'is_base64': all(c in 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=' for c in string)
        }
    
    def _matches_characteristics(self, actual: Dict[str, bool], expected: Any) -> bool:
        """Check if string characteristics match expected patterns."""
        # Handle both dict and list formats
        if isinstance(expected, dict):
            matches = 0
            total = len(expected)
            
            for key, expected_value in expected.items():
                if key in actual and actual[key] == expected_value:
                    matches += 1
            
            # Return true if at least 70% of characteristics match
            return (matches / total) >= 0.7 if total > 0 else False
        elif isinstance(expected, list):
            # Convert list of single-key dicts to a single dict
            expected_dict = {}
            for item in expected:
                if isinstance(item, dict):
                    expected_dict.update(item)
            
            if not expected_dict:
                return True  # No specific requirements
            
            matches = 0
            total = len(expected_dict)
            
            for key, expected_value in expected_dict.items():
                if key in actual and actual[key] == expected_value:
                    matches += 1
            
            # Return true if at least 70% of characteristics match
            return (matches / total) >= 0.7 if total > 0 else False
        else:
            # No specific requirements
            return True