"""Enhanced code scanner that detects code in various formats including strings."""

import re
import ast
import base64
from typing import List, Dict, Any, Optional
from collections import defaultdict

from .base import BaseScanner, Vulnerability, Severity, ScanResult


class EnhancedCodeScanner(BaseScanner):
    """Scanner that detects code patterns in various formats including strings."""
    
    def __init__(self):
        super().__init__()
        # Dangerous functions and patterns
        self.dangerous_functions = {
            'eval', 'exec', 'compile', '__import__', 'execfile',
            'getattr', 'setattr', 'delattr', 'globals', 'locals'
        }
        
        # Suspicious module imports
        self.suspicious_modules = {
            'os', 'sys', 'subprocess', 'socket', 'requests', 
            'urllib', 'paramiko', 'ftplib', 'telnetlib', 'smtplib',
            'pickle', 'marshal', 'shelve', 'importlib', 'imp'
        }
        
        # Command execution patterns
        self.command_patterns = [
            r'os\.system\s*\(',
            r'subprocess\.\w+\s*\(',
            r'os\.popen\s*\(',
            r'commands\.\w+\s*\(',
            r'call\s*\(\s*\[',
            r'Popen\s*\(',
            r'\.exec\s*\(',
            r'\.spawn\s*\('
        ]
        
        # Network communication patterns
        self.network_patterns = [
            r'socket\.socket\s*\(',
            r'\.connect\s*\(\s*\(',
            r'requests\.\w+\s*\(',
            r'urllib\.request\.',
            r'urlopen\s*\(',
            r'HTTPConnection\s*\(',
            r'paramiko\.SSHClient\s*\('
        ]
        
        # Code execution indicators in strings
        self.code_indicators = [
            r'import\s+\w+',
            r'from\s+\w+\s+import',
            r'def\s+\w+\s*\(',
            r'class\s+\w+',
            r'lambda\s*\w*\s*:',
            r'return\s+',
            r'if\s+.*:',
            r'for\s+\w+\s+in\s+',
            r'while\s+.*:',
            r'try\s*:',
            r'except\s*.*:'
        ]
    
    @property
    def name(self) -> str:
        return "EnhancedCodeScanner"
    
    @property
    def description(self) -> str:
        return "Detects code patterns in various formats including strings and dictionaries"
    
    def can_scan(self, file_path: str, parsed_data: Dict[str, Any]) -> bool:
        """Can scan any file type."""
        return True
    
    @property
    def supported_formats(self) -> List[str]:
        return ["*"]  # Supports all formats
    
    def scan(self, file_path: str, parsed_data: Dict[str, Any]) -> ScanResult:
        """Scan for code patterns in various formats."""
        vulnerabilities = []
        
        # Scan the parsed data recursively
        self._scan_data_recursive(parsed_data, vulnerabilities, "")
        
        # Also scan any embedded code
        if 'embedded_code' in parsed_data:
            for code_block in parsed_data.get('embedded_code', []):
                self._analyze_code_block(code_block, vulnerabilities, "embedded_code")
        
        return ScanResult(
            scanner_name=self.name,
            file_path=file_path,
            vulnerabilities=vulnerabilities,
            metadata={"patterns_checked": len(self.dangerous_functions) + len(self.suspicious_modules)}
        )
    
    def _scan_data_recursive(self, data: Any, vulnerabilities: List[Vulnerability], path: str):
        """Recursively scan data structures for code patterns."""
        if isinstance(data, dict):
            for key, value in data.items():
                new_path = f"{path}.{key}" if path else key
                self._scan_data_recursive(value, vulnerabilities, new_path)
                
        elif isinstance(data, list):
            for i, item in enumerate(data):
                new_path = f"{path}[{i}]"
                self._scan_data_recursive(item, vulnerabilities, new_path)
                
        elif isinstance(data, str):
            # Check if string contains code patterns
            if self._looks_like_code(data):
                self._analyze_string_code(data, vulnerabilities, path)
            
            # Check for base64 encoded content
            if self._is_base64(data) and len(data) > 20:
                try:
                    decoded = base64.b64decode(data).decode('utf-8', errors='ignore')
                    if self._looks_like_code(decoded):
                        vulnerabilities.append(Vulnerability(
                            severity=Severity.HIGH,
                            category="Obfuscated Code",
                            description="Base64 encoded code detected",
                            details=f"Found base64 encoded code at {path}: {decoded[:100]}...",
                            remediation="Review encoded content for malicious code",
                            confidence=0.8
                        ))
                except:
                    pass
    
    def _looks_like_code(self, text: str) -> bool:
        """Check if a string looks like code."""
        if len(text) < 10:
            return False
        
        # Check for multiple code indicators
        indicator_count = 0
        for pattern in self.code_indicators:
            if re.search(pattern, text, re.IGNORECASE):
                indicator_count += 1
                if indicator_count >= 2:  # At least 2 indicators
                    return True
        
        # Check for dangerous functions
        for func in self.dangerous_functions:
            if func in text:
                return True
        
        # Check for suspicious imports
        for module in self.suspicious_modules:
            if f"import {module}" in text or f"from {module}" in text:
                return True
        
        return False
    
    def _analyze_string_code(self, code: str, vulnerabilities: List[Vulnerability], location: str):
        """Analyze code found in string format."""
        # Check for dangerous functions
        for func in self.dangerous_functions:
            pattern = rf'\b{func}\s*\('
            if re.search(pattern, code):
                vulnerabilities.append(Vulnerability(
                    severity=Severity.HIGH if func in ['eval', 'exec'] else Severity.MEDIUM,
                    category="Code Execution",
                    description=f"Dangerous function '{func}' in string code",
                    details=f"Found {func}() call in string at {location}",
                    remediation=f"Remove {func}() usage and use safe alternatives",
                    confidence=0.9
                ))
        
        # Check for command execution
        for pattern in self.command_patterns:
            if re.search(pattern, code):
                vulnerabilities.append(Vulnerability(
                    severity=Severity.CRITICAL,
                    category="Command Execution",
                    description="System command execution in string code",
                    details=f"Command execution pattern found at {location}: {pattern}",
                    remediation="Remove system command execution",
                    confidence=0.85
                ))
        
        # Check for network communication
        for pattern in self.network_patterns:
            if re.search(pattern, code):
                vulnerabilities.append(Vulnerability(
                    severity=Severity.HIGH,
                    category="Network Communication",
                    description="Network operations in string code",
                    details=f"Network pattern found at {location}: {pattern}",
                    remediation="Review network connections for unauthorized communication",
                    confidence=0.8
                ))
        
        # Check for suspicious imports
        import_pattern = r'(?:import|from)\s+([\w\.]+)'
        imports = re.findall(import_pattern, code)
        for imp in imports:
            base_module = imp.split('.')[0]
            if base_module in self.suspicious_modules:
                vulnerabilities.append(Vulnerability(
                    severity=Severity.MEDIUM,
                    category="Suspicious Import",
                    description=f"Import of suspicious module '{base_module}'",
                    details=f"Found 'import {imp}' at {location}",
                    remediation="Review necessity of this import",
                    confidence=0.7
                ))
    
    def _analyze_code_block(self, code: str, vulnerabilities: List[Vulnerability], location: str):
        """Analyze a code block for security issues."""
        try:
            # Try to parse as Python AST
            tree = ast.parse(code)
            self._analyze_ast(tree, vulnerabilities, location)
        except:
            # If AST parsing fails, do string analysis
            self._analyze_string_code(code, vulnerabilities, location)
    
    def _analyze_ast(self, tree: ast.AST, vulnerabilities: List[Vulnerability], location: str):
        """Analyze Python AST for security issues."""
        for node in ast.walk(tree):
            # Check for dangerous function calls
            if isinstance(node, ast.Call):
                func_name = self._get_function_name(node.func)
                if func_name in self.dangerous_functions:
                    vulnerabilities.append(Vulnerability(
                        severity=Severity.HIGH,
                        category="Code Execution",
                        description=f"Dangerous function call: {func_name}",
                        details=f"AST analysis found {func_name}() at {location}",
                        remediation=f"Replace {func_name}() with safe alternative",
                        confidence=0.95
                    ))
            
            # Check for imports
            elif isinstance(node, (ast.Import, ast.ImportFrom)):
                module_name = node.module if hasattr(node, 'module') else None
                if module_name and module_name in self.suspicious_modules:
                    vulnerabilities.append(Vulnerability(
                        severity=Severity.MEDIUM,
                        category="Suspicious Import",
                        description=f"Import of suspicious module: {module_name}",
                        details=f"AST found import of {module_name} at {location}",
                        remediation="Review module import necessity",
                        confidence=0.8
                    ))
    
    def _get_function_name(self, node: ast.AST) -> Optional[str]:
        """Extract function name from AST node."""
        if isinstance(node, ast.Name):
            return node.id
        elif isinstance(node, ast.Attribute):
            return node.attr
        return None
    
    def _is_base64(self, s: str) -> bool:
        """Check if string is likely base64 encoded."""
        try:
            if len(s) % 4 != 0:
                return False
            base64.b64decode(s, validate=True)
            return True
        except:
            return False