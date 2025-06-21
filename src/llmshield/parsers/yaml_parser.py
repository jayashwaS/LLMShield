"""YAML file parser for configuration and metadata files."""

import yaml
from pathlib import Path
from typing import Dict, Any, List

from llmshield.core.logger import get_logger
from llmshield.parsers.base import BaseParser, ParserResult, ModelMetadata

logger = get_logger()


class YAMLParser(BaseParser):
    """Parser for YAML configuration files."""
    
    FRAMEWORK_NAME = "yaml"
    SUPPORTED_EXTENSIONS = {'.yaml', '.yml'}
    
    def parse(self, file_path: Path) -> ParserResult:
        """Parse YAML file and extract content."""
        logger.info(f"Parsing YAML file: {file_path}")
        
        # Extract basic metadata
        metadata = self.extract_metadata(file_path)
        
        result = ParserResult(
            metadata=metadata,
            warnings=[],
            suspicious_patterns=[],
            embedded_code=[],
            external_dependencies=[],
            serialization_format="yaml"
        )
        
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read()
                
            # Parse YAML
            try:
                data = yaml.safe_load(content)
                parsed_data = data if data else {}
                
                # Store the parsed data in metadata's custom_attributes
                result.metadata.custom_attributes = {
                    "parsed_data": parsed_data,
                    "raw_content": content  # Store raw content for secret scanning
                }
                
                # Update metadata if version info present
                if isinstance(data, dict):
                    if 'version' in data:
                        result.metadata.framework_version = str(data['version'])
                    if 'architecture' in data:
                        result.metadata.model_architecture = data['architecture']
                    
                    # Look for suspicious patterns in keys
                    suspicious_keys = self._check_suspicious_keys(data)
                    if suspicious_keys:
                        result.warnings.append(f"Found suspicious keys: {', '.join(suspicious_keys)}")
                        result.suspicious_patterns.extend([f"suspicious_key:{key}" for key in suspicious_keys])
                        
            except yaml.YAMLError as e:
                result.warnings.append(f"YAML parsing error: {e}")
                # Still store raw content for secret scanning
                result.metadata.custom_attributes = {
                    "parsed_data": {"_error": str(e)},
                    "raw_content": content
                }
                
        except Exception as e:
            logger.error(f"Failed to parse YAML file: {e}")
            result.warnings.append(f"Failed to parse file: {e}")
            
        return result
    
    def validate_format(self, file_path: Path) -> bool:
        """Validate that the file is a valid YAML file."""
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                yaml.safe_load(f)
            return True
        except:
            return False
    
    def _check_suspicious_keys(self, data: Dict[str, Any], prefix: str = "") -> List[str]:
        """Recursively check for suspicious keys in YAML data."""
        suspicious = []
        suspicious_patterns = [
            'password', 'secret', 'key', 'token', 'api_key', 'access_key',
            'private_key', 'credentials', 'auth', 'bearer', 'oauth'
        ]
        
        if isinstance(data, dict):
            for key, value in data.items():
                full_key = f"{prefix}.{key}" if prefix else key
                
                # Check if key contains suspicious patterns
                key_lower = str(key).lower()
                for pattern in suspicious_patterns:
                    if pattern in key_lower:
                        suspicious.append(full_key)
                        break
                
                # Recurse into nested structures
                if isinstance(value, dict):
                    suspicious.extend(self._check_suspicious_keys(value, full_key))
                elif isinstance(value, list):
                    for i, item in enumerate(value):
                        if isinstance(item, dict):
                            suspicious.extend(self._check_suspicious_keys(item, f"{full_key}[{i}]"))
                            
        return suspicious