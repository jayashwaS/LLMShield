"""
Entropy Scanner - Detects obfuscated payloads via entropy analysis
"""

import math
import base64
from collections import Counter
from typing import Any, List, Optional
from .base import BaseScanner, Vulnerability, ScanResult, Severity


class EntropyScanner(BaseScanner):
    """Scanner for detecting high-entropy obfuscated content"""
    
    def __init__(self):
        super().__init__()
        self._name = "EntropyScanner"
        self._description = "Detects obfuscated payloads using entropy analysis"
        self._supported_formats = [".pkl", ".pth", ".pt", ".h5", ".pb", ".onnx"]
        
        # Entropy thresholds
        self.HIGH_ENTROPY = 4.5  # Likely encrypted/compressed
        self.SUSPICIOUS_ENTROPY = 3.8  # Possibly obfuscated
        
        # Minimum string length to analyze
        self.MIN_LENGTH = 50
    
    def scan(self, file_path: str, parsed_data: Optional[Any] = None) -> ScanResult:
        """Scan for high entropy content indicating obfuscation"""
        vulnerabilities = []
        
        if parsed_data:
            # Extract all strings
            strings = self._extract_strings(parsed_data)
            
            # Analyze each string
            for string in strings:
                if len(string) >= self.MIN_LENGTH:
                    entropy = self._calculate_entropy(string)
                    
                    if entropy > self.HIGH_ENTROPY:
                        vulnerabilities.append(Vulnerability(
                            severity=Severity.HIGH,
                            category="High Entropy Content",
                            description="Likely encrypted or compressed data",
                            details=f"Entropy: {entropy:.2f} (threshold: {self.HIGH_ENTROPY})",
                            remediation="Investigate high entropy content for hidden payloads"
                        ))
                        
                        # Check if it's base64
                        if self._is_likely_base64(string):
                            decoded = self._try_decode_base64(string)
                            if decoded:
                                vulnerabilities.append(Vulnerability(
                                    severity=Severity.MEDIUM,
                                    category="Base64 Encoded Content",
                                    description="Base64 encoded data detected",
                                    details=f"Decoded preview: {decoded[:100]}...",
                                    remediation="Review decoded content for malicious code"
                                ))
                    
                    elif entropy > self.SUSPICIOUS_ENTROPY:
                        vulnerabilities.append(Vulnerability(
                            severity=Severity.MEDIUM,
                            category="Suspicious Entropy",
                            description="Possibly obfuscated content",
                            details=f"Entropy: {entropy:.2f} (threshold: {self.SUSPICIOUS_ENTROPY})",
                            remediation="Review content for obfuscation techniques"
                        ))
            
            # Check for suspicious byte patterns
            byte_patterns = self._find_byte_patterns(parsed_data)
            if byte_patterns:
                vulnerabilities.append(Vulnerability(
                    severity=Severity.MEDIUM,
                    category="Suspicious Byte Patterns",
                    description="Binary or obfuscated data patterns found",
                    details=f"Found {len(byte_patterns)} suspicious byte sequences",
                    remediation="Check for embedded executables or shellcode"
                ))
        
        return ScanResult(
            scanner_name=self.name,
            vulnerabilities=vulnerabilities,
            scan_time=0.0
        )
    
    def _calculate_entropy(self, data: str) -> float:
        """Calculate Shannon entropy of a string"""
        if not data:
            return 0.0
        
        # Count character frequencies
        freq = Counter(data)
        length = len(data)
        
        # Calculate entropy
        entropy = 0.0
        for count in freq.values():
            probability = count / length
            if probability > 0:
                entropy -= probability * math.log2(probability)
        
        return entropy
    
    def _extract_strings(self, data: Any, min_length: int = 10) -> List[str]:
        """Extract strings from nested data structures"""
        strings = []
        
        if isinstance(data, str):
            if len(data) >= min_length:
                strings.append(data)
        elif isinstance(data, bytes):
            try:
                decoded = data.decode('utf-8', errors='ignore')
                if len(decoded) >= min_length:
                    strings.append(decoded)
            except:
                pass
        elif isinstance(data, dict):
            for value in data.values():
                strings.extend(self._extract_strings(value, min_length))
        elif isinstance(data, (list, tuple)):
            for item in data:
                strings.extend(self._extract_strings(item, min_length))
        elif hasattr(data, '__dict__'):
            strings.extend(self._extract_strings(data.__dict__, min_length))
        
        return strings
    
    def _is_likely_base64(self, string: str) -> bool:
        """Check if string is likely base64 encoded"""
        # Remove whitespace
        string = string.strip()
        
        # Check length is multiple of 4
        if len(string) % 4 != 0:
            return False
        
        # Check character set
        base64_chars = set('ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=')
        if not all(c in base64_chars for c in string):
            return False
        
        # Check padding
        if string.endswith('=='):
            return True
        elif string.endswith('='):
            return True
        elif '=' not in string:
            return True
        
        return False
    
    def _try_decode_base64(self, string: str) -> Optional[str]:
        """Try to decode base64 string"""
        try:
            decoded = base64.b64decode(string)
            return decoded.decode('utf-8', errors='ignore')
        except:
            return None
    
    def _find_byte_patterns(self, data: Any) -> List[bytes]:
        """Find suspicious byte patterns"""
        patterns = []
        
        if isinstance(data, bytes):
            # Check for common executable headers
            if data.startswith(b'MZ'):  # PE header
                patterns.append(data[:100])
            elif data.startswith(b'\x7fELF'):  # ELF header
                patterns.append(data[:100])
            elif data.startswith(b'\xca\xfe\xba\xbe'):  # Mach-O
                patterns.append(data[:100])
            
            # Check for shellcode patterns
            if b'\x90' * 10 in data:  # NOP sled
                patterns.append(b'NOP sled detected')
            
        elif isinstance(data, dict):
            for value in data.values():
                patterns.extend(self._find_byte_patterns(value))
        elif isinstance(data, (list, tuple)):
            for item in data:
                patterns.extend(self._find_byte_patterns(item))
        
        return patterns
    
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