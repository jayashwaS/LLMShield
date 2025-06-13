"""Parser for GGUF/GGML format files (llama.cpp models)."""

import struct
from pathlib import Path
from typing import Any, Dict, List, Optional, Set

from llmshield.core.logger import get_logger
from llmshield.core.exceptions import FileParsingError, CorruptedFileError
from llmshield.parsers.base import BaseParser, ParserResult, ModelMetadata

logger = get_logger()


class GGUFParser(BaseParser):
    """Parser for GGUF/GGML format files."""
    
    SUPPORTED_EXTENSIONS: Set[str] = {'.gguf', '.ggml', '.q4_0', '.q4_1', '.q5_0', '.q5_1', '.q8_0'}
    FRAMEWORK_NAME: str = "gguf"
    
    # GGUF magic number
    GGUF_MAGIC = b'GGUF'
    GGML_MAGIC = b'ggjt'  # Legacy GGML format
    
    def validate_format(self, file_path: Path) -> bool:
        """Validate that the file is a valid GGUF/GGML file."""
        try:
            with open(file_path, 'rb') as f:
                magic = f.read(4)
                return magic in [self.GGUF_MAGIC, self.GGML_MAGIC]
        except Exception:
            return False
    
    def parse(self, file_path: Path) -> ParserResult:
        """Parse GGUF/GGML model file."""
        logger.info(f"Parsing GGUF/GGML file: {file_path}")
        
        metadata = self.extract_metadata(file_path)
        warnings = []
        suspicious_patterns = []
        embedded_code = []
        external_dependencies = []
        
        try:
            with open(file_path, 'rb') as f:
                magic = f.read(4)
                
                if magic == self.GGUF_MAGIC:
                    result = self._parse_gguf_format(f, metadata)
                elif magic == self.GGML_MAGIC:
                    result = self._parse_ggml_format(f, metadata)
                else:
                    # Try to parse as quantized format
                    result = self._parse_quantized_format(file_path, metadata)
                
                warnings.extend(result.get('warnings', []))
                suspicious_patterns.extend(result.get('patterns', []))
                
                # Check for embedded metadata
                if 'metadata_kv' in result:
                    for key, value in result['metadata_kv'].items():
                        if isinstance(value, str):
                            # Check for suspicious content
                            if any(s in value.lower() for s in ['exec', 'eval', 'import', 'subprocess']):
                                suspicious_patterns.append(f"Suspicious metadata: {key}")
                                warnings.append(f"Suspicious content in metadata key '{key}'")
        
        except Exception as e:
            logger.error(f"Error parsing GGUF/GGML file: {e}")
            warnings.append(f"Parse error: {str(e)}")
            raise FileParsingError(f"Failed to parse GGUF/GGML file: {e}")
        
        return ParserResult(
            metadata=metadata,
            warnings=warnings,
            suspicious_patterns=suspicious_patterns,
            embedded_code=embedded_code,
            external_dependencies=external_dependencies,
            serialization_format="gguf"
        )
    
    def _parse_gguf_format(self, f, metadata: ModelMetadata) -> Dict[str, Any]:
        """Parse GGUF format file."""
        result = {'warnings': [], 'patterns': []}
        
        try:
            # Read version
            version = struct.unpack('<I', f.read(4))[0]
            metadata.custom_attributes['gguf_version'] = version
            
            # Read tensor count and metadata KV count
            tensor_count = struct.unpack('<Q', f.read(8))[0]
            kv_count = struct.unpack('<Q', f.read(8))[0]
            
            metadata.custom_attributes['tensor_count'] = tensor_count
            
            # Read metadata key-value pairs
            metadata_kv = {}
            for _ in range(kv_count):
                key_length = struct.unpack('<Q', f.read(8))[0]
                if key_length > 1024:  # Sanity check
                    result['warnings'].append("Unusually long metadata key")
                    break
                
                key = f.read(key_length).decode('utf-8', errors='ignore')
                value_type = struct.unpack('<I', f.read(4))[0]
                
                # Read value based on type (simplified)
                if value_type == 8:  # String type
                    str_length = struct.unpack('<Q', f.read(8))[0]
                    if str_length < 1024 * 1024:  # Limit string size
                        value = f.read(str_length).decode('utf-8', errors='ignore')
                        metadata_kv[key] = value
                else:
                    # Skip other types for now
                    metadata_kv[key] = f"<type_{value_type}>"
            
            result['metadata_kv'] = metadata_kv
            
            # Extract model info from metadata
            if 'general.architecture' in metadata_kv:
                metadata.model_architecture = metadata_kv['general.architecture']
            if 'general.name' in metadata_kv:
                metadata.model_name = metadata_kv['general.name']
            
        except Exception as e:
            result['warnings'].append(f"GGUF parsing error: {str(e)}")
        
        return result
    
    def _parse_ggml_format(self, f, metadata: ModelMetadata) -> Dict[str, Any]:
        """Parse legacy GGML format file."""
        result = {'warnings': [], 'patterns': []}
        
        try:
            # Read version
            version = struct.unpack('<I', f.read(4))[0]
            metadata.custom_attributes['ggml_version'] = version
            metadata.custom_attributes['format_type'] = 'ggml_legacy'
            
            # GGML format is less structured, so we do basic checks
            result['warnings'].append("Legacy GGML format - limited metadata available")
            
        except Exception as e:
            result['warnings'].append(f"GGML parsing error: {str(e)}")
        
        return result
    
    def _parse_quantized_format(self, file_path: Path, metadata: ModelMetadata) -> Dict[str, Any]:
        """Parse quantized model format based on extension."""
        result = {'warnings': [], 'patterns': []}
        
        ext = file_path.suffix.lower()
        if ext in ['.q4_0', '.q4_1', '.q5_0', '.q5_1', '.q8_0']:
            quant_type = ext[1:]  # Remove the dot
            metadata.custom_attributes['quantization'] = quant_type
            metadata.custom_attributes['format_type'] = 'quantized'
            result['warnings'].append(f"Quantized model format: {quant_type}")
        
        return result