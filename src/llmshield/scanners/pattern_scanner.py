"""Pattern-based vulnerability scanner using the vulnerability database."""

import re
from datetime import datetime
from pathlib import Path
from typing import Dict, Any, List, Optional

from ..core.logger import get_logger
from .base import BaseScanner, ScanResult, Vulnerability, Severity
from .vulnerability_db import vulnerability_db

logger = get_logger(__name__)


class PatternScanner(BaseScanner):
    """Scanner that detects vulnerabilities using pattern matching."""
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """Initialize pattern scanner."""
        super().__init__(config)
        self.vuln_db = vulnerability_db
        
    @property
    def name(self) -> str:
        return "PatternScanner"
        
    @property
    def description(self) -> str:
        return "Detects known vulnerability patterns and signatures"
        
    @property
    def supported_formats(self) -> List[str]:
        return ['*']  # Supports all formats
        
    def can_scan(self, file_path: Path, parsed_data: Dict[str, Any]) -> bool:
        """Pattern scanner can scan any parsed file."""
        return True
        
    def scan(self, file_path: Path, parsed_data: Dict[str, Any]) -> ScanResult:
        """Scan for known vulnerability patterns."""
        logger.info(f"Running pattern scan on {file_path}")
        
        vulnerabilities = []
        scan_metadata = {
            'patterns_checked': 0,
            'matches_found': 0
        }
        
        try:
            # Handle different types of parsed_data
            if not isinstance(parsed_data, dict):
                if hasattr(parsed_data, 'to_dict'):
                    parsed_data = parsed_data.to_dict()
                elif hasattr(parsed_data, '__dict__'):
                    parsed_data = vars(parsed_data)
                else:
                    parsed_data = {'raw_data': str(parsed_data)}
            
            framework = parsed_data.get('framework', 'unknown').lower()
            
            # Get vulnerabilities for this framework
            framework_vulns = self.vuln_db.get_by_framework(framework)
            
            # Check suspicious patterns from parser
            if parsed_data.get('suspicious_patterns'):
                for pattern in parsed_data['suspicious_patterns']:
                    # Handle both string and dict patterns
                    if isinstance(pattern, str):
                        pattern_text = pattern.lower()
                        pattern_dict = {'pattern': pattern}
                    elif isinstance(pattern, dict):
                        pattern_text = pattern.get('pattern', '').lower()
                        pattern_dict = pattern
                    else:
                        continue
                    
                    matching_vulns = self.vuln_db.search_by_pattern(pattern_text)
                    
                    if matching_vulns:
                        for db_vuln in matching_vulns:
                            vuln = Vulnerability(
                                severity=db_vuln.severity,
                                category="known-vulnerability",
                                description=db_vuln.name,
                                details=f"{db_vuln.description}. Found pattern: {pattern_text}",
                                remediation=db_vuln.remediation,
                                confidence=0.85,
                                cve_id=db_vuln.cve_id,
                                cwe_id=db_vuln.cwe_id,
                                evidence={'pattern': pattern_text, 'location': pattern_dict.get('location')}
                            )
                            vulnerabilities.append(vuln)
                            scan_metadata['matches_found'] += 1
                    else:
                        # Generic suspicious pattern
                        vuln = Vulnerability(
                            severity=Severity.MEDIUM,
                            category="suspicious-pattern",
                            description="Suspicious Pattern Detected",
                            details=f"Found suspicious pattern: {pattern_text}",
                            remediation="Review code for malicious intent",
                            confidence=0.7,
                            evidence=pattern_dict
                        )
                        vulnerabilities.append(vuln)
                        
            # Check for known malicious models
            model_name = file_path.stem.lower()
            for vuln_entry in self.vuln_db.get_all():
                if vuln_entry.detection_patterns:
                    for pattern in vuln_entry.detection_patterns:
                        scan_metadata['patterns_checked'] += 1
                        
                        # Check in model name
                        if pattern.lower() in model_name:
                            vuln = Vulnerability(
                                severity=vuln_entry.severity,
                                category="known-malicious",
                                description=vuln_entry.name,
                                details=f"{vuln_entry.description}. Model name matches: {pattern}",
                                remediation=vuln_entry.remediation,
                                confidence=0.95,
                                cve_id=vuln_entry.cve_id,
                                cwe_id=vuln_entry.cwe_id,
                                evidence={'pattern': pattern, 'model_name': str(file_path.name)}
                            )
                            vulnerabilities.append(vuln)
                            scan_metadata['matches_found'] += 1
                            
            # Check embedded code against patterns
            embedded_code = parsed_data.get('embedded_code', [])
            if not embedded_code and 'metadata' in parsed_data and isinstance(parsed_data['metadata'], dict):
                # Try to get from metadata for ParserResult.to_dict() format
                embedded_code = parsed_data.get('metadata', {}).get('custom_attributes', {}).get('embedded_code', [])
            
            for code_block in embedded_code:
                code_str = str(code_block).lower() if code_block else ""
                
                for vuln_entry in framework_vulns:
                    if vuln_entry.detection_patterns:
                        for pattern in vuln_entry.detection_patterns:
                            if pattern.lower() in code_str:
                                vuln = Vulnerability(
                                    severity=vuln_entry.severity,
                                    category="embedded-vulnerability",
                                    description=f"{vuln_entry.name} in Embedded Code",
                                    details=vuln_entry.description,
                                    remediation=vuln_entry.remediation,
                                    confidence=0.9,
                                    cve_id=vuln_entry.cve_id,
                                    cwe_id=vuln_entry.cwe_id,
                                    evidence={'pattern': pattern, 'code_snippet': code_str[:100]}
                                )
                                vulnerabilities.append(vuln)
                                scan_metadata['matches_found'] += 1
            
            # Also scan raw content if available (for JSON, YAML, etc)
            if 'metadata' in parsed_data and isinstance(parsed_data['metadata'], dict):
                custom_attrs = parsed_data.get('metadata', {}).get('custom_attributes', {})
                if 'parsed_data' in custom_attrs:
                    # Scan the actual JSON/YAML content
                    content_str = str(custom_attrs['parsed_data']).lower()
                    for vuln_entry in self.vuln_db.get_all():
                        if vuln_entry.detection_patterns:
                            for pattern in vuln_entry.detection_patterns:
                                if pattern.lower() in content_str:
                                    vuln = Vulnerability(
                                        severity=vuln_entry.severity,
                                        category="pattern-match",
                                        description=f"{vuln_entry.name}",
                                        details=f"{vuln_entry.description}. Pattern '{pattern}' found in content",
                                        remediation=vuln_entry.remediation,
                                        confidence=0.85,
                                        cve_id=vuln_entry.cve_id,
                                        cwe_id=vuln_entry.cwe_id,
                                        evidence={'pattern': pattern}
                                    )
                                    vulnerabilities.append(vuln)
                                    scan_metadata['matches_found'] += 1
                                    
            # Check for dangerous imports
            imports = parsed_data.get('imports', {})
            dangerous_modules = ['os', 'subprocess', 'socket', 'urllib', 'requests']
            
            for module in dangerous_modules:
                if module in imports:
                    matching_vulns = self.vuln_db.search_by_pattern(f"import {module}")
                    if matching_vulns:
                        for db_vuln in matching_vulns:
                            vuln = Vulnerability(
                                severity=db_vuln.severity,
                                category="dangerous-import",
                                description=f"{db_vuln.name}: {module}",
                                details=db_vuln.description,
                                remediation=db_vuln.remediation,
                                confidence=0.8,
                                cwe_id=db_vuln.cwe_id,
                                evidence={'module': module, 'functions': imports.get(module, [])}
                            )
                            vulnerabilities.append(vuln)
                            
        except Exception as e:
            logger.error(f"Error in pattern scan: {str(e)}")
            return ScanResult(
                scanner_name=self.name,
                error=str(e)
            )
            
        return ScanResult(
            scanner_name=self.name,
            vulnerabilities=vulnerabilities,
            metadata=scan_metadata
        )