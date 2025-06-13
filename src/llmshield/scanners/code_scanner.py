"""
Code Scanner - Detects embedded code in ML models
"""

import ast
import re
import base64
from typing import Any, List, Optional
from .base import BaseScanner, Vulnerability, ScanResult, Severity


class CodeScanner(BaseScanner):
    """Scanner for detecting embedded malicious code patterns"""
    
    def __init__(self):
        super().__init__()
        self._name = "CodeScanner"
        self._description = "Detects embedded code execution patterns and dangerous functions"
        self._supported_formats = [".pkl", ".pth", ".pt", ".h5", ".pb", ".onnx"]
        
        # Suspicious function patterns
        self.dangerous_functions = {
            'eval', 'exec', 'compile', '__import__',
            'execfile', 'input', 'raw_input'
        }
        
        # Suspicious module imports
        self.suspicious_modules = {
            'subprocess', 'os', 'socket', 'requests',
            'urllib', 'urllib2', 'urllib3', 'httplib',
            'ftplib', 'telnetlib', 'paramiko'
        }
        
        # Code obfuscation patterns
        self.obfuscation_patterns = [
            r'\\x[0-9a-fA-F]{2}',  # Hex encoding
            r'\\[0-7]{3}',         # Octal encoding
            r'chr\s*\(\s*\d+\s*\)', # Character code conversion
            r'base64\.b64decode',   # Base64 decoding
        ]
    
    def scan(self, file_path: str, parsed_data: Optional[Any] = None) -> ScanResult:
        """Scan for embedded code in model data"""
        vulnerabilities = []
        
        if parsed_data:
            # Extract strings from parsed data
            strings = self._extract_strings(parsed_data)
            
            # Check for dangerous functions
            for string in strings:
                vulns = self._check_dangerous_code(string)
                vulnerabilities.extend(vulns)
            
            # Check for base64 encoded content
            for string in strings:
                if self._is_base64(string) and len(string) > 20:
                    decoded = self._decode_base64(string)
                    if decoded:
                        vulns = self._check_dangerous_code(decoded)
                        for vuln in vulns:
                            vuln.description = f"Base64 encoded: {vuln.description}"
                            vulnerabilities.append(vuln)
            
            # Check for obfuscated code
            for string in strings:
                if self._is_obfuscated(string):
                    vulnerabilities.append(Vulnerability(
                        severity=Severity.MEDIUM,
                        category="Obfuscated Code",
                        description="Potentially obfuscated code detected",
                        details=f"Obfuscated pattern found: {string[:100]}...",
                        remediation="Review code for malicious intent"
                    ))
        
        return ScanResult(
            scanner_name=self.name,
            vulnerabilities=vulnerabilities,
            scan_time=0.0
        )
    
    def _extract_strings(self, data: Any) -> List[str]:
        """Extract all strings from nested data structures"""
        strings = []
        
        if isinstance(data, str):
            strings.append(data)
        elif isinstance(data, dict):
            for value in data.values():
                strings.extend(self._extract_strings(value))
        elif isinstance(data, (list, tuple)):
            for item in data:
                strings.extend(self._extract_strings(item))
        elif hasattr(data, '__dict__'):
            strings.extend(self._extract_strings(data.__dict__))
        
        return strings
    
    def _check_dangerous_code(self, code: str) -> List[Vulnerability]:
        """Check for dangerous code patterns"""
        vulnerabilities = []
        
        # Check for dangerous function calls
        for func in self.dangerous_functions:
            pattern = rf'\b{func}\s*\('
            if re.search(pattern, code):
                vulnerabilities.append(Vulnerability(
                    severity=Severity.CRITICAL,
                    category="Dangerous Function",
                    description=f"Dangerous function '{func}' detected",
                    details=f"Found usage of {func} which can execute arbitrary code",
                    remediation="Remove or sandbox dangerous function calls"
                ))
        
        # Check for suspicious imports
        import_pattern = r'(?:import|from)\s+(\w+)'
        imports = re.findall(import_pattern, code)
        for module in imports:
            if module in self.suspicious_modules:
                vulnerabilities.append(Vulnerability(
                    severity=Severity.HIGH,
                    category="Suspicious Import",
                    description=f"Suspicious module '{module}' imported",
                    details=f"Module {module} can be used for malicious activities",
                    remediation="Review the necessity of this import"
                ))
        
        # Try to parse as Python AST
        try:
            tree = ast.parse(code)
            # Look for suspicious AST patterns
            for node in ast.walk(tree):
                if isinstance(node, ast.Call):
                    if hasattr(node.func, 'id') and node.func.id in self.dangerous_functions:
                        vulnerabilities.append(Vulnerability(
                            severity=Severity.CRITICAL,
                            category="AST Dangerous Function",
                            description=f"Dangerous function '{node.func.id}' in AST",
                            details="Confirmed dangerous function call in parsed AST",
                            remediation="Remove dangerous function calls"
                        ))
        except:
            # Not valid Python code, skip AST analysis
            pass
        
        return vulnerabilities
    
    def _is_base64(self, string: str) -> bool:
        """Check if string might be base64 encoded"""
        try:
            # Basic base64 pattern check
            pattern = r'^[A-Za-z0-9+/]*={0,2}$'
            if re.match(pattern, string.strip()):
                # Try to decode
                base64.b64decode(string)
                return True
        except:
            pass
        return False
    
    def _decode_base64(self, string: str) -> Optional[str]:
        """Safely decode base64 string"""
        try:
            decoded = base64.b64decode(string)
            return decoded.decode('utf-8', errors='ignore')
        except:
            return None
    
    def _is_obfuscated(self, string: str) -> bool:
        """Check if string contains obfuscation patterns"""
        for pattern in self.obfuscation_patterns:
            if re.search(pattern, string):
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