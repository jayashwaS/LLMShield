"""Pickle-specific vulnerability scanner."""

import pickle
import pickletools
from datetime import datetime
from pathlib import Path
from typing import Dict, Any, List, Set, Optional

from ..core.logger import get_logger
from .base import BaseScanner, ScanResult, Vulnerability, Severity

logger = get_logger(__name__)


class PickleScanner(BaseScanner):
    """Scanner for detecting vulnerabilities in pickle files."""
    
    # Dangerous pickle opcodes that can execute arbitrary code
    DANGEROUS_OPCODES = {
        'GLOBAL': Severity.CRITICAL,      # Can import any module
        'REDUCE': Severity.CRITICAL,      # Can call any callable
        'BUILD': Severity.HIGH,           # Can call object methods
        'INST': Severity.CRITICAL,        # Can instantiate any class
        'OBJ': Severity.HIGH,             # Can create arbitrary objects
        'NEWOBJ': Severity.HIGH,          # Can create objects with args
        'NEWOBJ_EX': Severity.HIGH,       # Can create objects with kwargs
        'STACK_GLOBAL': Severity.CRITICAL, # Stack-based GLOBAL
        'EXT1': Severity.MEDIUM,          # Extension registry (1 byte)
        'EXT2': Severity.MEDIUM,          # Extension registry (2 bytes)
        'EXT4': Severity.MEDIUM,          # Extension registry (4 bytes)
    }
    
    # Dangerous modules/functions that indicate potential malicious activity
    DANGEROUS_IMPORTS = {
        'os': ['system', 'popen', 'exec', 'spawnl', 'spawnlp', 'spawnv', 'spawnvp'],
        'subprocess': ['call', 'check_call', 'check_output', 'Popen', 'run'],
        'commands': ['getoutput', 'getstatusoutput'],
        'pty': ['spawn'],
        'posix': ['system', 'popen'],
        'builtins': ['eval', 'exec', 'compile', '__import__'],
        '__builtin__': ['eval', 'exec', 'compile', '__import__'],
        'imp': ['load_source', 'load_compiled', 'load_dynamic'],
        'importlib': ['import_module', '__import__'],
        'socket': ['socket', 'create_connection'],
        'urllib': ['urlopen', 'urlretrieve'],
        'urllib2': ['urlopen'],
        'requests': ['get', 'post', 'put', 'delete'],
        'ftplib': ['FTP'],
        'telnetlib': ['Telnet'],
        'smtplib': ['SMTP'],
    }
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """Initialize pickle scanner."""
        super().__init__(config)
        
    @property
    def name(self) -> str:
        return "PickleScanner"
        
    @property
    def description(self) -> str:
        return "Detects arbitrary code execution and other vulnerabilities in pickle files"
        
    @property
    def supported_formats(self) -> List[str]:
        return ['.pkl', '.pickle', '.pt', '.pth', '.model', '.sav']
        
    def can_scan(self, file_path: Path, parsed_data: Dict[str, Any]) -> bool:
        """Check if this scanner can handle the file."""
        # Convert to Path if string
        if isinstance(file_path, str):
            file_path = Path(file_path)
            
        # Check file extension
        if file_path.suffix.lower() in self.supported_formats:
            return True
            
        # Check if parsed data indicates pickle format
        if parsed_data.get('format') == 'pickle':
            return True
            
        # Check if file contains pickle data
        if parsed_data.get('contains_pickle', False):
            return True
            
        return False
        
    def scan(self, file_path: Path, parsed_data: Dict[str, Any]) -> ScanResult:
        """Scan pickle file for vulnerabilities."""
        # Convert to Path if string
        if isinstance(file_path, str):
            file_path = Path(file_path)
        logger.info(f"Scanning {file_path} for pickle vulnerabilities")
        
        vulnerabilities = []
        scan_metadata = {
            'opcodes_analyzed': 0,
            'dangerous_opcodes_found': 0,
            'suspicious_imports': []
        }
        
        try:
            # Analyze the file directly
            opcodes, imports = self._analyze_pickle_file(file_path)
                
            scan_metadata['opcodes_analyzed'] = len(opcodes)
            
            # Check for dangerous opcodes
            for opcode in opcodes:
                if opcode['name'] in self.DANGEROUS_OPCODES:
                    severity = self.DANGEROUS_OPCODES[opcode['name']]
                    vuln = Vulnerability(
                        severity=severity,
                        category="deserialization",
                        description=f"Dangerous Pickle Opcode: {opcode['name']} - Found dangerous pickle opcode '{opcode['name']}' at position {opcode.get('pos', 'unknown')} which can be used for arbitrary code execution",
                        details=f"Opcode: {opcode['name']}\nPosition: {opcode.get('pos', 'unknown')}\nArgs: {opcode.get('args')}",
                        remediation="Avoid using pickle for untrusted data. Consider using JSON or other safe formats",
                        confidence=0.95,
                        location=self._format_location(file_path, f"offset {opcode.get('pos', 'unknown')}"),
                        cve_id="CVE-2019-20907",
                        cwe_id="CWE-502",
                        evidence={
                            'opcode': opcode['name'],
                            'position': opcode.get('pos'),
                            'args': opcode.get('args')
                        }
                    )
                    vulnerabilities.append(vuln)
                    scan_metadata['dangerous_opcodes_found'] += 1
                    
            # Check for dangerous imports
            for module, functions in imports.items():
                if module in self.DANGEROUS_IMPORTS:
                    dangerous_funcs = set(functions) & set(self.DANGEROUS_IMPORTS[module])
                    if dangerous_funcs:
                        scan_metadata['suspicious_imports'].append(f"{module}.{','.join(dangerous_funcs)}")
                        vuln = Vulnerability(
                            severity=Severity.HIGH,
                            category="dangerous-import",
                            description=f"Dangerous Import: {module} - Pickle file imports dangerous module '{module}' with functions: {', '.join(dangerous_funcs)}",
                            details=f"Module: {module}\nFunctions: {', '.join(dangerous_funcs)}",
                            remediation="Review why these dangerous modules are being imported and remove if not necessary",
                            confidence=0.9,
                            cwe_id="CWE-94",
                            location=self._format_location(file_path),
                            evidence={
                                'module': module,
                                'functions': list(dangerous_funcs)
                            }
                        )
                        vulnerabilities.append(vuln)
                        
            # Check for suspicious patterns in parsed data
            if parsed_data.get('suspicious_patterns'):
                for pattern in parsed_data['suspicious_patterns']:
                    vuln = Vulnerability(
                        severity=Severity.MEDIUM,
                        category="suspicious-pattern",
                        description=f"Suspicious Pattern: {pattern['type']} - {pattern['description']}",
                        details=str(pattern),
                        remediation="Review the suspicious pattern and ensure it's legitimate",
                        confidence=0.8,
                        location=self._format_location(file_path),
                        evidence=pattern
                    )
                    vulnerabilities.append(vuln)
                    
            # Check for embedded code
            if parsed_data.get('embedded_code'):
                for code_block in parsed_data['embedded_code']:
                    vuln = Vulnerability(
                        severity=Severity.CRITICAL,
                        category="embedded-code",
                        description=f"Embedded Code Detected - Found embedded code in pickle file: {str(code_block)[:100]}...",
                        details=f"Code snippet: {str(code_block)[:200]}",
                        remediation="Embedded code in pickle files is extremely dangerous. Do not load this file",
                        confidence=1.0,
                        cwe_id="CWE-94",
                        location=self._format_location(file_path),
                        evidence={
                            'code_snippet': str(code_block)[:200]
                        }
                    )
                    vulnerabilities.append(vuln)
                    
        except Exception as e:
            logger.error(f"Error scanning pickle file: {str(e)}")
            return ScanResult(
                scanner_name=self.name,
                error=str(e)
            )
            
        return ScanResult(
            scanner_name=self.name,
            vulnerabilities=vulnerabilities,
            metadata=scan_metadata
        )
        
    def _analyze_pickle_file(self, file_path: Path) -> tuple:
        """Analyze pickle file and extract opcodes and imports."""
        opcodes = []
        imports = {}
        
        try:
            with open(file_path, 'rb') as f:
                # Use pickletools to disassemble
                for opcode, arg, pos in pickletools.genops(f):
                    opcodes.append({
                        'name': opcode.name,
                        'args': arg,
                        'pos': pos
                    })
                    
                    # Track imports
                    if opcode.name in ['GLOBAL', 'STACK_GLOBAL'] and arg:
                        if isinstance(arg, tuple) and len(arg) >= 2:
                            module, name = arg[0], arg[1]
                            if module not in imports:
                                imports[module] = []
                            imports[module].append(name)
                            
        except Exception as e:
            logger.warning(f"Error analyzing pickle opcodes: {str(e)}")
            
        return opcodes, imports