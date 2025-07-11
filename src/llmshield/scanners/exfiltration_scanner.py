"""
Exfiltration Scanner - Detects data exfiltration attempts
"""

import re
from typing import Any, List, Optional
from .base import BaseScanner, Vulnerability, ScanResult, Severity


class ExfiltrationScanner(BaseScanner):
    """Scanner for detecting data exfiltration attempts in models"""
    
    def __init__(self):
        super().__init__()
        self._name = "ExfiltrationScanner"
        self._description = "Detects data exfiltration and network communication attempts"
        self._supported_formats = [".pkl", ".pth", ".pt", ".h5", ".pb", ".onnx"]
        
        # Network-related patterns
        self.network_patterns = [
            # URLs and IPs
            r'https?://[^\s]+',
            r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b',
            # More specific domain pattern - requires at least 3 chars before TLD and word boundaries
            r'\b[a-zA-Z][a-zA-Z0-9-]{2,}\.(?:com|org|net|io|gov|edu|co\.uk|de|jp|fr|au|us|ru|ch|it|nl|se|no|es|mil|info|biz|name|ly|ai|ml|app|dev|cloud|xyz|online|tech|site|store|blog|wiki)\b',
            
            # Network functions
            r'socket\.',
            r'requests\.',
            r'urllib\.',
            r'httplib\.',
            r'http\.client',
            
            # Data transfer commands
            r'curl\s+.*(-d|--data)',
            r'wget\s+.*--post',
            r'nc\s+.*\d+',  # netcat
        ]
        
        # File access patterns
        self.file_patterns = [
            r'open\s*\(',
            r'file\s*\(',
            r'read\s*\(',
            r'write\s*\(',
            r'os\.path',
            r'pathlib',
            r'shutil\.',
        ]
        
        # Environment and system info access
        self.info_gathering_patterns = [
            r'os\.environ',
            r'platform\.',
            r'sys\.platform',
            r'getpass\.',
            r'pwd\.',
            r'grp\.',
        ]
        
        # Data encoding/encryption that might hide exfiltration
        self.encoding_patterns = [
            r'base64\.',
            r'hashlib\.',
            r'cryptography\.',
            r'Crypto\.',
            r'zlib\.',
            r'gzip\.',
        ]
    
    def scan(self, file_path: str, parsed_data: Optional[Any] = None) -> ScanResult:
        """Scan for data exfiltration indicators"""
        vulnerabilities = []
        
        # Skip for vocabulary files
        from pathlib import Path
        filename = Path(file_path).name.lower()
        skip_files = ['vocab.json', 'tokenizer.json', 'merges.txt']
        if filename in skip_files:
            return ScanResult(
                scanner_name=self.name,
                vulnerabilities=[],
                metadata={'skipped': True, 'reason': 'Vocabulary file'}
            )
        
        if parsed_data:
            # Convert to searchable text
            text = self._extract_all_text(parsed_data)
            
            # Check for network communication patterns
            network_matches = self._check_patterns(text, self.network_patterns)
            for match, pattern in network_matches:
                # Clean up the match for better display
                artifact = match if isinstance(match, str) else str(match)
                if len(artifact) > 200:
                    artifact = artifact[:200] + "..."
                
                vulnerabilities.append(Vulnerability(
                    severity=Severity.HIGH,
                    category="Network Communication",
                    description="Potential network communication detected",
                    details=f"Suspicious network-related content found",
                    remediation="Review network operations for data exfiltration",
                    evidence={'artifact': artifact}
                ))
            
            # Check for file access patterns
            file_matches = self._check_patterns(text, self.file_patterns)
            for match, pattern in file_matches:
                artifact = match if isinstance(match, str) else str(match)
                if len(artifact) > 200:
                    artifact = artifact[:200] + "..."
                    
                vulnerabilities.append(Vulnerability(
                    severity=Severity.MEDIUM,
                    category="File Access",
                    description="File system access detected",
                    details=f"Suspicious file operation found",
                    remediation="Verify file operations are legitimate",
                    evidence={'artifact': artifact}
                ))
            
            # Check for information gathering
            info_matches = self._check_patterns(text, self.info_gathering_patterns)
            for match, pattern in info_matches:
                artifact = match if isinstance(match, str) else str(match)
                if len(artifact) > 200:
                    artifact = artifact[:200] + "..."
                    
                vulnerabilities.append(Vulnerability(
                    severity=Severity.MEDIUM,
                    category="Information Gathering",
                    description="System information access detected",
                    details=f"Suspicious system information access found",
                    remediation="Check if system info access is necessary",
                    evidence={'artifact': artifact}
                ))
            
            # Check for encoding/encryption
            encoding_matches = self._check_patterns(text, self.encoding_patterns)
            if encoding_matches:
                vulnerabilities.append(Vulnerability(
                    severity=Severity.MEDIUM,
                    category="Data Encoding",
                    description="Data encoding/encryption functions detected",
                    details=f"Found {len(encoding_matches)} encoding operations",
                    remediation="Verify encoding is not hiding exfiltration"
                ))
            
            # Check for hardcoded credentials or API keys
            cred_patterns = [
                r'["\']?api[_-]?key["\']?\s*[:=]\s*["\'][^"\']+["\']',
                r'["\']?password["\']?\s*[:=]\s*["\'][^"\']+["\']',
                r'["\']?secret["\']?\s*[:=]\s*["\'][^"\']+["\']',
                r'["\']?token["\']?\s*[:=]\s*["\'][^"\']+["\']',
            ]
            cred_matches = self._check_patterns(text, cred_patterns)
            for match, pattern in cred_matches:
                # Mask sensitive parts of credentials
                artifact = match if isinstance(match, str) else str(match)
                # Try to mask the actual secret value
                if '=' in artifact:
                    parts = artifact.split('=', 1)
                    if len(parts) == 2:
                        artifact = parts[0] + '=<REDACTED>'
                elif ':' in artifact:
                    parts = artifact.split(':', 1)
                    if len(parts) == 2:
                        artifact = parts[0] + ':<REDACTED>'
                        
                vulnerabilities.append(Vulnerability(
                    severity=Severity.HIGH,
                    category="Hardcoded Credentials",
                    description="Potential hardcoded credentials found",
                    details=f"Credential pattern detected",
                    remediation="Remove hardcoded credentials immediately",
                    evidence={'artifact': artifact}
                ))
        
        return ScanResult(
            scanner_name=self.name,
            vulnerabilities=vulnerabilities,
            scan_time=0.0
        )
    
    def _extract_all_text(self, data: Any) -> str:
        """Extract all text from nested structures"""
        if isinstance(data, str):
            return data
        elif isinstance(data, (int, float, bool)):
            return str(data)
        elif isinstance(data, dict):
            parts = []
            for key, value in data.items():
                parts.append(str(key))
                parts.append(self._extract_all_text(value))
            return " ".join(parts)
        elif isinstance(data, (list, tuple)):
            return " ".join(self._extract_all_text(item) for item in data)
        elif hasattr(data, '__dict__'):
            return self._extract_all_text(data.__dict__)
        else:
            return str(data)
    
    def _check_patterns(self, text: str, patterns: List[str]) -> List[tuple]:
        """Check text against list of regex patterns"""
        matches = []
        for pattern in patterns:
            try:
                # Use finditer to get match objects with position info
                for match_obj in re.finditer(pattern, text, re.IGNORECASE):
                    match_text = match_obj.group(0)
                    # Get context around the match (50 chars before and after)
                    start = max(0, match_obj.start() - 50)
                    end = min(len(text), match_obj.end() + 50)
                    context = text[start:end]
                    
                    # Clean up context for display
                    context = context.replace('\n', ' ').replace('\r', ' ')
                    context = ' '.join(context.split())  # Normalize whitespace
                    
                    matches.append((context, pattern))
            except re.error:
                # Skip invalid regex patterns
                continue
        return matches
    
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