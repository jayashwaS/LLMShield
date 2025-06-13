"""
Anomaly Scanner - Detects unusual model structures and behaviors
"""

import math
from typing import Any, Dict, List, Optional
from .base import BaseScanner, Vulnerability, ScanResult, Severity


class AnomalyScanner(BaseScanner):
    """Scanner for detecting anomalous model structures"""
    
    def __init__(self):
        super().__init__()
        self._name = "AnomalyScanner"
        self._description = "Detects unusual model structures and anomalies"
        self._supported_formats = [".pkl", ".pth", ".pt", ".h5", ".pb", ".onnx"]
        
        # Expected model attributes by framework
        self.expected_attributes = {
            'pytorch': ['state_dict', 'optimizer', 'epoch', 'model_state_dict'],
            'tensorflow': ['model_config', 'training_config', 'model_weights'],
            'onnx': ['graph', 'model_version', 'producer_name'],
        }
    
    def scan(self, file_path: str, parsed_data: Optional[Any] = None) -> ScanResult:
        """Scan for anomalous model structures"""
        vulnerabilities = []
        
        if parsed_data and isinstance(parsed_data, dict):
            # Check for unexpected top-level keys
            framework = parsed_data.get('framework', 'unknown')
            if framework in self.expected_attributes:
                unexpected_keys = self._find_unexpected_keys(
                    parsed_data, 
                    self.expected_attributes[framework]
                )
                if unexpected_keys:
                    vulnerabilities.append(Vulnerability(
                        severity=Severity.MEDIUM,
                        category="Anomalous Structure",
                        description="Unexpected model attributes detected",
                        details=f"Unexpected keys: {', '.join(unexpected_keys[:5])}",
                        remediation="Review unexpected attributes for malicious content"
                    ))
            
            # Check for unusual data types
            unusual_types = self._find_unusual_types(parsed_data)
            if unusual_types:
                vulnerabilities.append(Vulnerability(
                    severity=Severity.MEDIUM,
                    category="Unusual Data Types",
                    description="Non-standard data types in model",
                    details=f"Found types: {', '.join(unusual_types)}",
                    remediation="Verify these data types are expected"
                ))
            
            # Check for suspiciously large strings
            large_strings = self._find_large_strings(parsed_data)
            if large_strings:
                vulnerabilities.append(Vulnerability(
                    severity=Severity.HIGH,
                    category="Embedded Data",
                    description="Suspiciously large strings found",
                    details=f"Found {len(large_strings)} strings > 10KB",
                    remediation="Check for embedded executables or data"
                ))
            
            # Check for nested depth anomaly
            max_depth = self._calculate_max_depth(parsed_data)
            if max_depth > 10:
                vulnerabilities.append(Vulnerability(
                    severity=Severity.LOW,
                    category="Structure Anomaly",
                    description="Unusually deep nesting detected",
                    details=f"Maximum nesting depth: {max_depth}",
                    remediation="Verify model structure is intentional"
                ))
        
        return ScanResult(
            scanner_name=self.name,
            vulnerabilities=vulnerabilities,
            scan_time=0.0
        )
    
    def _find_unexpected_keys(self, data: Dict, expected: List[str]) -> List[str]:
        """Find keys that are not in the expected list"""
        unexpected = []
        for key in data.keys():
            if isinstance(key, str) and key not in expected:
                # Skip common benign keys
                if key not in ['version', 'format', 'metadata', 'config']:
                    unexpected.append(key)
        return unexpected
    
    def _find_unusual_types(self, data: Any, path: str = "") -> List[str]:
        """Find unusual data types in the model"""
        unusual = []
        
        if isinstance(data, dict):
            for key, value in data.items():
                unusual.extend(self._find_unusual_types(value, f"{path}.{key}"))
        elif isinstance(data, (list, tuple)):
            for i, item in enumerate(data):
                unusual.extend(self._find_unusual_types(item, f"{path}[{i}]"))
        else:
            # Check for unusual types
            type_name = type(data).__name__
            if type_name not in ['str', 'int', 'float', 'bool', 'NoneType', 
                                 'list', 'dict', 'tuple', 'bytes', 'ndarray']:
                unusual.append(f"{type_name} at {path}")
        
        return unusual
    
    def _find_large_strings(self, data: Any, threshold: int = 10240) -> List[str]:
        """Find suspiciously large strings (>10KB by default)"""
        large_strings = []
        
        if isinstance(data, str) and len(data) > threshold:
            large_strings.append(data[:100] + "...")
        elif isinstance(data, dict):
            for value in data.values():
                large_strings.extend(self._find_large_strings(value, threshold))
        elif isinstance(data, (list, tuple)):
            for item in data:
                large_strings.extend(self._find_large_strings(item, threshold))
        
        return large_strings
    
    def _calculate_max_depth(self, data: Any, current_depth: int = 0) -> int:
        """Calculate maximum nesting depth of data structure"""
        if isinstance(data, dict):
            if not data:
                return current_depth
            return max(self._calculate_max_depth(v, current_depth + 1) 
                      for v in data.values())
        elif isinstance(data, (list, tuple)):
            if not data:
                return current_depth
            return max(self._calculate_max_depth(item, current_depth + 1) 
                      for item in data)
        else:
            return current_depth
    
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