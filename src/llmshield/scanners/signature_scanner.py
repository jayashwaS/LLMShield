"""
Signature Scanner - Detects known malicious patterns
"""

import re
from typing import Any, List, Optional
from .base import BaseScanner, Vulnerability, ScanResult, Severity
from .payload_signatures import PayloadSignatures


class SignatureScanner(BaseScanner):
    """Scanner for known malicious signatures and patterns"""
    
    def __init__(self):
        super().__init__()
        self._name = "SignatureScanner"
        self._description = "Detects known malicious signatures and patterns"
        self._supported_formats = [".pkl", ".pth", ".pt", ".h5", ".pb", ".onnx"]
        self.signatures_db = PayloadSignatures()
    
    def scan(self, file_path: str, parsed_data: Optional[Any] = None) -> ScanResult:
        """Scan for known malicious signatures"""
        vulnerabilities = []
        
        # Skip for vocabulary files
        from pathlib import Path
        filename = Path(file_path).name.lower()
        skip_files = ['vocab.json', 'tokenizer.json', 'merges.txt', 'tokenizer_config.json']
        if filename in skip_files:
            return ScanResult(
                scanner_name=self.name,
                vulnerabilities=[],
                metadata={'skipped': True, 'reason': 'Vocabulary file'}
            )
        
        # Add debug logging
        import logging
        logger = logging.getLogger(__name__)
        logger.info(f"SignatureScanner: Scanning {file_path}")
        logger.debug(f"SignatureScanner: parsed_data type: {type(parsed_data)}")
        
        if parsed_data:
            # Convert parsed data to searchable text
            searchable_text = self._data_to_text(parsed_data)
            logger.debug(f"SignatureScanner: searchable_text[:200]: {searchable_text[:200]}")
            
            # Check against known signatures
            for pattern, severity, category, description in self.signatures_db.get_all_signatures():
                if self._pattern_match(pattern, searchable_text):
                    vulnerabilities.append(Vulnerability(
                        severity=severity,
                        category=category,
                        description=description,
                        details=f"Matched pattern: {pattern}",
                        remediation="Remove or investigate the suspicious pattern"
                    ))
            
            # Check for obfuscation
            obfuscation_score = self._calculate_obfuscation_score(searchable_text)
            if obfuscation_score > 3:
                vulnerabilities.append(Vulnerability(
                    severity=Severity.MEDIUM,
                    category="Obfuscation",
                    description="High obfuscation score detected",
                    details=f"Obfuscation score: {obfuscation_score}/10",
                    remediation="Review code for hidden functionality"
                ))
            
            # Check for suspicious strings with context
            for suspicious in self.signatures_db.get_suspicious_strings():
                # Skip "token" in ML model files - it's too common
                if suspicious.lower() == "token" and any(ext in filename for ext in ['.json', '.md']):
                    continue
                    
                # Look for actual assignments or values, not just the word
                pattern = rf'\b{suspicious}["\']?\s*[:=]\s*["\']?[\w\-]{{10,}}'
                if re.search(pattern, searchable_text, re.IGNORECASE):
                    vulnerabilities.append(Vulnerability(
                        severity=Severity.LOW,
                        category="Information Disclosure",
                        description=f"Potential sensitive data: {suspicious}",
                        details=f"Found assignment pattern for '{suspicious}' which may contain sensitive data",
                        remediation="Ensure sensitive data is properly protected"
                    ))
        
        return ScanResult(
            scanner_name=self._name,
            vulnerabilities=vulnerabilities,
            scan_time=0.0
        )
    
    def _data_to_text(self, data: Any) -> str:
        """Convert nested data structures to searchable text"""
        if isinstance(data, str):
            return data
        elif isinstance(data, (int, float)):
            return str(data)
        elif isinstance(data, dict):
            parts = []
            for key, value in data.items():
                parts.append(str(key))
                parts.append(self._data_to_text(value))
            return " ".join(parts)
        elif isinstance(data, (list, tuple)):
            return " ".join(self._data_to_text(item) for item in data)
        elif hasattr(data, '__dict__'):
            return self._data_to_text(data.__dict__)
        else:
            return str(data)
    
    def _pattern_match(self, pattern: str, text: str) -> bool:
        """Check if pattern exists in text (case-insensitive)"""
        try:
            # Try as regex first
            if re.search(pattern, text, re.IGNORECASE):
                return True
        except re.error:
            # Fall back to simple substring search
            if pattern.lower() in text.lower():
                return True
        return False
    
    def _calculate_obfuscation_score(self, text: str) -> int:
        """Calculate obfuscation score (0-10)"""
        score = 0
        indicators = self.signatures_db.get_obfuscation_indicators()
        
        for indicator in indicators:
            count = text.lower().count(indicator.lower())
            if count > 0:
                score += min(count, 2)  # Cap contribution per indicator
        
        # Check for high entropy sections
        if self._has_high_entropy_sections(text):
            score += 2
        
        # Check for excessive special characters
        special_char_ratio = sum(1 for c in text if not c.isalnum() and not c.isspace()) / max(len(text), 1)
        if special_char_ratio > 0.3:
            score += 2
        
        return min(score, 10)  # Cap at 10
    
    def _has_high_entropy_sections(self, text: str) -> bool:
        """Check for high entropy sections that might indicate obfuscation"""
        # Simple heuristic: look for long strings without spaces
        words = text.split()
        for word in words:
            if len(word) > 50 and not any(c in word for c in ['.', '/', '\\', '_', '-']):
                return True
        return False
    
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
        """Check if scanner can handle the file"""
        return True  # Can scan any parsed data