"""Parser for Safetensors format files."""

import json
import struct
from pathlib import Path
from typing import Any, Dict, List, Optional, Set

from llmshield.core.logger import get_logger
from llmshield.core.exceptions import FileParsingError, CorruptedFileError
from llmshield.parsers.base import BaseParser, ParserResult, ModelMetadata

logger = get_logger()


class SafetensorsParser(BaseParser):
    """Parser for Safetensors files (.safetensors)."""
    
    SUPPORTED_EXTENSIONS: Set[str] = {'.safetensors'}
    FRAMEWORK_NAME: str = "safetensors"
    
    def validate_format(self, file_path: Path) -> bool:
        """Validate that the file is a valid Safetensors file."""
        try:
            with open(file_path, 'rb') as f:
                # Read header length (first 8 bytes)
                header_size_bytes = f.read(8)
                if len(header_size_bytes) != 8:
                    return False
                
                header_size = struct.unpack('<Q', header_size_bytes)[0]
                
                # Sanity check header size
                if header_size > 100 * 1024 * 1024:  # 100MB header would be suspicious
                    return False
                
                # Read and parse header
                header_bytes = f.read(header_size)
                header = json.loads(header_bytes)
                
                # Check for required fields
                return isinstance(header, dict) and '__metadata__' in header
        
        except Exception:
            return False
    
    def parse(self, file_path: Path) -> ParserResult:
        """Parse Safetensors file."""
        logger.info(f"Parsing Safetensors file: {file_path}")
        
        metadata = self.extract_metadata(file_path)
        warnings = []
        suspicious_patterns = []
        embedded_code = []
        external_dependencies = []
        
        try:
            with open(file_path, 'rb') as f:
                # Read header
                header_size = struct.unpack('<Q', f.read(8))[0]
                
                # Check header size
                if header_size > 100 * 1024 * 1024:  # 100MB
                    warnings.append(f"Unusually large header size: {header_size} bytes")
                    suspicious_patterns.append("oversized_header")
                
                header_bytes = f.read(header_size)
                header = json.loads(header_bytes)
                
                # Extract metadata
                file_metadata = header.get('__metadata__', {})
                metadata.custom_attributes['safetensors_metadata'] = file_metadata
                
                # Check for suspicious metadata keys
                for key, value in file_metadata.items():
                    if any(suspicious in key.lower() for suspicious in 
                          ['exec', 'eval', 'code', 'script', 'command', 'shell']):
                        warnings.append(f"Suspicious metadata key: {key}")
                        suspicious_patterns.append(f"metadata:{key}")
                    
                    # Check values for suspicious content
                    if isinstance(value, str):
                        suspicious_imports = self.check_suspicious_imports(value)
                        if suspicious_imports:
                            warnings.append(f"Suspicious content in metadata {key}: {suspicious_imports}")
                            suspicious_patterns.extend(suspicious_imports)
                
                # Extract tensor information
                tensors = {k: v for k, v in header.items() if k != '__metadata__'}
                tensor_info = []
                total_params = 0
                
                for name, info in tensors.items():
                    if isinstance(info, dict):
                        dtype = info.get('dtype', 'unknown')
                        shape = info.get('shape', [])
                        data_offsets = info.get('data_offsets', [])
                        
                        # Calculate tensor size
                        tensor_size = 1
                        for dim in shape:
                            tensor_size *= dim
                        total_params += tensor_size
                        
                        tensor_info.append({
                            'name': name,
                            'dtype': dtype,
                            'shape': shape,
                            'size': tensor_size
                        })
                        
                        # Check for suspicious tensor names
                        if any(suspicious in name.lower() for suspicious in 
                              ['exec', 'eval', 'payload', 'backdoor', 'trigger']):
                            warnings.append(f"Suspicious tensor name: {name}")
                            suspicious_patterns.append(f"tensor:{name}")
                
                metadata.parameters_count = total_params
                metadata.custom_attributes['tensors'] = tensor_info[:20]  # First 20 tensors
                metadata.custom_attributes['total_tensors'] = len(tensors)
                
                # Verify file integrity
                # The actual tensor data starts after header
                expected_data_start = 8 + header_size
                file_size = file_path.stat().st_size
                data_size = file_size - expected_data_start
                
                # Calculate expected data size from tensor info
                expected_data_size = 0
                dtype_sizes = {
                    'F32': 4, 'F16': 2, 'BF16': 2,
                    'I32': 4, 'I16': 2, 'I8': 1,
                    'U32': 4, 'U16': 2, 'U8': 1,
                    'BOOL': 1
                }
                
                for info in tensors.values():
                    if isinstance(info, dict):
                        dtype = info.get('dtype', 'F32')
                        shape = info.get('shape', [])
                        size = dtype_sizes.get(dtype, 4)
                        tensor_elements = 1
                        for dim in shape:
                            tensor_elements *= dim
                        expected_data_size += tensor_elements * size
                
                # Check for hidden data
                if data_size > expected_data_size * 1.1:  # 10% tolerance
                    size_diff = data_size - expected_data_size
                    warnings.append(f"File contains {size_diff} bytes of unexpected data")
                    suspicious_patterns.append("hidden_data")
                
                # Safetensors is generally safe, but check for known issues
                if len(tensors) > 10000:
                    warnings.append(f"Unusually high number of tensors: {len(tensors)}")
                
                # Check if any tensor has unusual properties
                for name, info in tensors.items():
                    if isinstance(info, dict):
                        shape = info.get('shape', [])
                        # Check for unusual shapes
                        if len(shape) > 10:
                            warnings.append(f"Tensor {name} has unusual number of dimensions: {len(shape)}")
                        if any(dim < 0 for dim in shape):
                            warnings.append(f"Tensor {name} has negative dimensions")
                            suspicious_patterns.append(f"negative_dims:{name}")
        
        except json.JSONDecodeError as e:
            logger.error(f"Invalid JSON in header: {e}")
            warnings.append(f"Invalid header format: {str(e)}")
            raise CorruptedFileError(f"Invalid Safetensors header: {e}")
        
        except Exception as e:
            logger.error(f"Error parsing Safetensors file: {e}")
            warnings.append(f"Parse error: {str(e)}")
        
        return ParserResult(
            metadata=metadata,
            warnings=warnings,
            suspicious_patterns=suspicious_patterns,
            embedded_code=embedded_code,
            external_dependencies=external_dependencies,
            serialization_format="safetensors"
        )