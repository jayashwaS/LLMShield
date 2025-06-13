"""
PyTorch Attribute Scanner - Specialized scanner for PyTorch model attributes and metadata.
"""

import re
import json
from typing import Dict, Any, List, Optional
from pathlib import Path

from .yaml_rule_scanner import YamlRuleScanner
from .base import BaseScanner, Vulnerability, Severity, ScanResult
from .utils import create_vulnerability


class PyTorchAttributeScanner(YamlRuleScanner):
    """Scanner for PyTorch-specific attributes and security issues."""
    
    def __init__(self, config: Dict[str, Any] = None):
        # Extract config_path from config if provided, otherwise use default
        config_path = config.get('rules_path', None) if config else None
        super().__init__(config_path)
        self._name = "PyTorchAttributeScanner"
        self._description = "Scans PyTorch models for suspicious attributes and embedded secrets"
        self._supported_formats = ["pytorch", "pth", "pt"]
    
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
        """Can scan PyTorch files."""
        framework = parsed_data.get('framework', '').lower()
        file_ext = str(file_path).lower() if hasattr(file_path, '__str__') else ''
        return framework == 'pytorch' or any(ext in file_ext for ext in ['.pth', '.pt', '.ckpt'])
    
    def scan(self, file_path: str, parsed_data: Dict[str, Any]) -> ScanResult:
        """Scan PyTorch models for security issues in attributes and metadata."""
        vulnerabilities = []
        
        # Check if it's a PyTorch file
        framework = parsed_data.get('framework', '').lower()
        file_ext = str(file_path).lower()
        is_pytorch = framework == 'pytorch' or any(ext in file_ext for ext in ['.pth', '.pt', '.ckpt'])
        
        if not is_pytorch:
            return ScanResult(
                scanner_name=self.name,
                vulnerabilities=[],
                metadata={'skip_reason': 'Not a PyTorch model'}
            )
        
        # Try to get model data from parsed_data first
        model_data = None
        
        # Check if we have the loaded data in metadata
        if 'metadata' in parsed_data and isinstance(parsed_data['metadata'], dict):
            custom_attrs = parsed_data.get('metadata', {}).get('custom_attributes', {})
            if 'loaded_data' in custom_attrs:
                model_data = custom_attrs['loaded_data']
        elif 'custom_attributes' in parsed_data:
            # Old format
            if 'loaded_data' in parsed_data['custom_attributes']:
                model_data = parsed_data['custom_attributes']['loaded_data']
        elif 'content' in parsed_data:
            # Direct content
            model_data = parsed_data['content']
        
        # If we don't have model data, try to load it with torch if available
        if model_data is None:
            try:
                import torch
                model_data = torch.load(file_path, map_location='cpu')
            except ImportError:
                # PyTorch not installed, skip advanced scanning
                return ScanResult(
                    scanner_name=self.name,
                    vulnerabilities=[],
                    metadata={'skip_reason': 'PyTorch not installed and no parsed data available'}
                )
            except Exception as e:
                return ScanResult(
                    scanner_name=self.name,
                    vulnerabilities=[],
                    metadata={'skip_reason': f'Failed to load model: {str(e)}'}
                )
        
        if not isinstance(model_data, dict):
            # Wrap non-dict models
            model_data = {'model': model_data}
        
        # 1. Check state dict keys using YAML rules
        state_dict_vulns = self._check_state_dict_keys(model_data, file_path)
        vulnerabilities.extend(state_dict_vulns)
        
        # 2. Check for dangerous attributes
        attr_vulns = self._check_dangerous_attributes(model_data, file_path)
        vulnerabilities.extend(attr_vulns)
        
        # 3. Check for embedded code in tensors
        tensor_vulns = self._check_tensor_content(model_data, file_path)
        vulnerabilities.extend(tensor_vulns)
        
        # 4. Check metadata
        metadata_vulns = self._check_metadata(model_data, file_path)
        vulnerabilities.extend(metadata_vulns)
        
        # 5. Check for custom objects
        custom_obj_vulns = self._check_custom_objects(model_data, file_path)
        vulnerabilities.extend(custom_obj_vulns)
        
        # 6. Run general YAML rule checks on string content
        yaml_vulns = super().scan(file_path, parsed_data)
        # Filter to PyTorch-specific vulnerabilities
        pytorch_yaml_vulns = [
            vuln for vuln in yaml_vulns.vulnerabilities
            if any(x in str(vuln) for x in ['PYTORCH', 'pytorch', 'torch']) or vuln.category == 'llm_security'
        ]
        vulnerabilities.extend(pytorch_yaml_vulns)
        
        return ScanResult(
            scanner_name=self.name,
            vulnerabilities=vulnerabilities,
            metadata={
                'model_keys': len(model_data.keys()),
                'pytorch_version': parsed_data.get('metadata', {}).get('pytorch_version', 'unknown')
            }
        )
    
    def _check_state_dict_keys(self, model_data: Dict[str, Any], file_path: str) -> List[Vulnerability]:
        """Check state dict keys for suspicious patterns."""
        vulnerabilities = []
        pytorch_rules = self.config.get('pytorch_rules', {})
        suspicious_keys = pytorch_rules.get('suspicious_keys', [])
        
        for key in model_data.keys():
            key_lower = key.lower()
            
            # Check against configured suspicious keys
            for pattern in suspicious_keys:
                if pattern.lower() in key_lower:
                    # Check if the value contains actual secrets
                    value = model_data[key]
                    value_details = self._analyze_value(value)
                    
                    vulnerabilities.append(create_vulnerability(
                        id=f"PYTORCH-KEY-{pattern.upper()}-{len(vulnerabilities)+1}",
                        name=f"Suspicious PyTorch Model Key: {key}",
                        severity=Severity.HIGH if value_details['is_suspicious'] else Severity.MEDIUM,
                        description=f"Model contains key '{key}' that may contain sensitive information",
                        file_path=file_path,
                        details={
                            'key': key,
                            'pattern_matched': pattern,
                            'value_type': value_details['type'],
                            'value_details': value_details
                        },
                        remediation="Remove sensitive keys from model state dict. Store credentials separately.",
                        category="pytorch"
                    ))
        
        return vulnerabilities
    
    def _check_dangerous_attributes(self, model_data: Dict[str, Any], file_path: str) -> List[Vulnerability]:
        """Check for dangerous PyTorch attributes that could contain malicious code."""
        vulnerabilities = []
        pytorch_rules = self.config.get('pytorch_rules', {})
        suspicious_attrs = pytorch_rules.get('suspicious_attributes', [])
        
        # Additional dangerous attributes not in config
        dangerous_attrs = [
            '__code__', '__globals__', '__builtins__',
            '_modules', '_parameters', '_buffers'
        ]
        
        all_attrs = set(suspicious_attrs + dangerous_attrs)
        
        for attr in all_attrs:
            if attr in model_data:
                value = model_data[attr]
                
                # Check if attribute contains executable code
                if self._contains_code(value):
                    vulnerabilities.append(create_vulnerability(
                        id=f"PYTORCH-DANGEROUS-ATTR-{len(vulnerabilities)+1}",
                        name=f"Dangerous Attribute in PyTorch Model: {attr}",
                        severity=Severity.CRITICAL,
                        description=f"Model contains attribute '{attr}' with potential executable code",
                        file_path=file_path,
                        details={
                            'attribute': attr,
                            'contains_code': True,
                            'value_preview': str(value)[:100] + '...' if len(str(value)) > 100 else str(value)
                        },
                        remediation="Remove executable code from model attributes. This is a critical security risk.",
                        category="pytorch"
                    ))
                else:
                    vulnerabilities.append(create_vulnerability(
                        id=f"PYTORCH-SUSPICIOUS-ATTR-{len(vulnerabilities)+1}",
                        name=f"Suspicious Attribute: {attr}",
                        severity=Severity.MEDIUM,
                        description=f"Model contains suspicious attribute '{attr}'",
                        file_path=file_path,
                        details={
                            'attribute': attr,
                            'value_type': type(value).__name__
                        },
                        remediation="Review this attribute to ensure it doesn't contain sensitive data.",
                        category="pytorch"
                    ))
        
        return vulnerabilities
    
    def _check_tensor_content(self, model_data: Dict[str, Any], file_path: str) -> List[Vulnerability]:
        """Check tensor content for embedded strings or code."""
        vulnerabilities = []
        
        for key, value in model_data.items():
            if self._is_tensor_like(value):
                # Check if tensor contains string data
                string_data = self._extract_strings_from_tensor(value)
                if string_data:
                    for string_content in string_data:
                        # Check for secrets in tensor strings
                        if len(string_content) > 20:
                            secret_patterns = [r for r in self.rules if r.category == 'secrets']
                            for pattern in secret_patterns:
                                for regex in pattern.patterns:
                                    if re.search(regex, string_content, re.IGNORECASE):
                                        vulnerabilities.append(create_vulnerability(
                                            id=f"PYTORCH-TENSOR-SECRET-{len(vulnerabilities)+1}",
                                            name="Secret Found in Tensor Data",
                                            severity=Severity.CRITICAL,
                                            description=f"Tensor '{key}' contains embedded secrets",
                                            file_path=file_path,
                                            details={
                                                'tensor_key': key,
                                                'secret_type': pattern.name,
                                                'masked_value': self._mask_secret(string_content)
                                            },
                                            remediation="Remove secrets from tensor data. This is highly unusual and suspicious.",
                                            category="pytorch"
                                        ))
        
        return vulnerabilities
    
    def _check_metadata(self, model_data: Dict[str, Any], file_path: str) -> List[Vulnerability]:
        """Check model metadata for security issues."""
        vulnerabilities = []
        
        # Common metadata keys
        metadata_keys = ['_metadata', 'metadata', 'meta', 'config', 'model_config']
        
        for meta_key in metadata_keys:
            if meta_key in model_data:
                metadata = model_data[meta_key]
                if isinstance(metadata, dict):
                    # Check for secrets in metadata
                    meta_strings = self._extract_strings(metadata)
                    for string_content in meta_strings:
                        secret_vulns = self._check_rules(string_content, file_path)
                        for vuln in secret_vulns:
                            # Update evidence to include metadata key
                            vuln.evidence['metadata_key'] = meta_key
                            vuln.evidence['in_metadata'] = True
                        vulnerabilities.extend(secret_vulns)
        
        return vulnerabilities
    
    def _check_custom_objects(self, model_data: Dict[str, Any], file_path: str) -> List[Vulnerability]:
        """Check for custom objects that might contain malicious code."""
        vulnerabilities = []
        
        # Look for keys that suggest custom objects
        custom_indicators = ['custom_objects', 'custom_layers', 'user_defined', 'extra_objects']
        
        for key in model_data.keys():
            if any(indicator in key.lower() for indicator in custom_indicators):
                value = model_data[key]
                if self._contains_code(value):
                    vulnerabilities.append(create_vulnerability(
                        id=f"PYTORCH-CUSTOM-OBJECT-{len(vulnerabilities)+1}",
                        name=f"Custom Object with Code: {key}",
                        severity=Severity.HIGH,
                        description=f"Model contains custom object '{key}' with executable code",
                        file_path=file_path,
                        details={
                            'object_key': key,
                            'object_type': type(value).__name__,
                            'has_code': True
                        },
                        remediation="Review custom objects for malicious code. Consider using standard PyTorch layers.",
                        category="pytorch"
                    ))
        
        return vulnerabilities
    
    def _analyze_value(self, value: Any) -> Dict[str, Any]:
        """Analyze a value to determine if it's suspicious."""
        result = {
            'type': type(value).__name__,
            'is_suspicious': False,
            'reasons': []
        }
        
        if isinstance(value, str):
            # Check if it looks like a secret
            if len(value) > 20 and self._calculate_entropy(value) > 4.0:
                result['is_suspicious'] = True
                result['reasons'].append('high_entropy_string')
            
            # Check for common secret patterns
            secret_patterns = ['key', 'token', 'password', 'secret', 'credential']
            if any(pattern in value.lower() for pattern in secret_patterns):
                result['is_suspicious'] = True
                result['reasons'].append('contains_secret_keywords')
        
        elif isinstance(value, (list, tuple)) and len(value) > 0:
            # Check if list contains strings that look like secrets
            for item in value[:10]:  # Check first 10 items
                if isinstance(item, str) and len(item) > 20:
                    item_analysis = self._analyze_value(item)
                    if item_analysis['is_suspicious']:
                        result['is_suspicious'] = True
                        result['reasons'].append('contains_suspicious_strings')
                        break
        
        elif isinstance(value, dict):
            # Recursively check dictionary
            for k, v in list(value.items())[:10]:  # Check first 10 items
                if isinstance(k, str) and any(s in k.lower() for s in ['key', 'token', 'secret']):
                    result['is_suspicious'] = True
                    result['reasons'].append('suspicious_dict_keys')
                    break
        
        return result
    
    def _contains_code(self, value: Any) -> bool:
        """Check if a value contains executable code."""
        if hasattr(value, '__code__'):
            return True
        
        if isinstance(value, str):
            # Check for code patterns
            code_patterns = [
                r'\bdef\s+\w+\s*\(',
                r'\bclass\s+\w+\s*[:\(]',
                r'\blambda\s+\w*:',
                r'\bimport\s+\w+',
                r'\beval\s*\(',
                r'\bexec\s*\(',
                r'\b__import__\s*\('
            ]
            return any(re.search(pattern, value) for pattern in code_patterns)
        
        return False
    
    def _is_tensor_like(self, value: Any) -> bool:
        """Check if a value looks like a tensor."""
        # Simple heuristic - can be improved
        return (
            hasattr(value, 'shape') or
            hasattr(value, 'dtype') or
            isinstance(value, (list, tuple)) and len(value) > 0 and isinstance(value[0], (int, float, list))
        )
    
    def _extract_strings_from_tensor(self, tensor: Any) -> List[str]:
        """Extract string data from tensor-like objects."""
        strings = []
        
        # This is a simplified version - real implementation would handle actual tensor types
        if hasattr(tensor, 'tolist'):
            data = tensor.tolist()
        elif isinstance(tensor, (list, tuple)):
            data = tensor
        else:
            return strings
        
        # Flatten and extract strings
        def extract_from_nested(obj):
            if isinstance(obj, str) and len(obj) > 10:
                strings.append(obj)
            elif isinstance(obj, (list, tuple)):
                for item in obj:
                    extract_from_nested(item)
        
        extract_from_nested(data)
        return strings