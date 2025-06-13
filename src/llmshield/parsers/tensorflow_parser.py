"""Parser for TensorFlow model files."""

import json
import struct
from pathlib import Path
from typing import Any, Dict, List, Optional, Set

import h5py
import numpy as np

from llmshield.core.logger import get_logger
from llmshield.core.exceptions import FileParsingError, CorruptedFileError
from llmshield.parsers.base import BaseParser, ParserResult, ModelMetadata

logger = get_logger()


class TensorFlowParser(BaseParser):
    """Parser for TensorFlow model files (.pb, .h5, .keras)."""
    
    SUPPORTED_EXTENSIONS: Set[str] = {'.pb', '.h5', '.hdf5', '.keras'}
    FRAMEWORK_NAME: str = "tensorflow"
    
    def validate_format(self, file_path: Path) -> bool:
        """Validate that the file is a valid TensorFlow file."""
        try:
            ext = file_path.suffix.lower()
            
            if ext == '.pb':
                # Check for protobuf format
                with open(file_path, 'rb') as f:
                    magic = f.read(4)
                    # Protobuf files often start with specific bytes
                    return len(magic) == 4
            
            elif ext in ['.h5', '.hdf5', '.keras']:
                # Check HDF5 format
                with h5py.File(file_path, 'r') as f:
                    # Valid HDF5 file
                    return True
            
            return False
        
        except Exception:
            return False
    
    def parse(self, file_path: Path) -> ParserResult:
        """Parse TensorFlow model file."""
        logger.info(f"Parsing TensorFlow file: {file_path}")
        
        metadata = self.extract_metadata(file_path)
        ext = file_path.suffix.lower()
        
        if ext == '.pb':
            return self._parse_pb_format(file_path, metadata)
        elif ext in ['.h5', '.hdf5', '.keras']:
            return self._parse_h5_format(file_path, metadata)
        else:
            raise UnsupportedFormatError(f"Unsupported TensorFlow format: {ext}")
    
    def _parse_pb_format(self, file_path: Path, metadata: ModelMetadata) -> ParserResult:
        """Parse Protocol Buffer format."""
        warnings = []
        suspicious_patterns = []
        embedded_code = []
        external_dependencies = []
        
        try:
            # Read protobuf file
            with open(file_path, 'rb') as f:
                content = f.read()
            
            # Look for suspicious patterns in the binary
            suspicious_strings = self._extract_suspicious_strings(content)
            if suspicious_strings:
                warnings.append(f"Found suspicious strings: {suspicious_strings[:5]}...")
                suspicious_patterns.extend(suspicious_strings)
            
            # Check file size
            if len(content) > 1024 * 1024 * 1024:  # 1GB
                warnings.append("Large model file - may contain hidden data")
            
            metadata.custom_attributes['format_type'] = 'protobuf'
            
        except Exception as e:
            logger.error(f"Error parsing PB file: {e}")
            warnings.append(f"Parse error: {str(e)}")
        
        return ParserResult(
            metadata=metadata,
            warnings=warnings,
            suspicious_patterns=suspicious_patterns,
            embedded_code=embedded_code,
            external_dependencies=external_dependencies,
            serialization_format="tensorflow_pb"
        )
    
    def _parse_h5_format(self, file_path: Path, metadata: ModelMetadata) -> ParserResult:
        """Parse HDF5/Keras format."""
        warnings = []
        suspicious_patterns = []
        embedded_code = []
        external_dependencies = []
        
        try:
            with h5py.File(file_path, 'r') as f:
                # Extract model structure
                if 'model_config' in f.attrs:
                    model_config = json.loads(f.attrs['model_config'])
                    metadata.model_architecture = model_config.get('class_name', 'Unknown')
                    metadata.custom_attributes['model_config'] = model_config
                    
                    # Check for custom objects
                    if 'config' in model_config:
                        config = model_config['config']
                        if 'layers' in config:
                            metadata.layers = self._extract_layer_info(config['layers'])
                            
                            # Check for Lambda layers (can contain arbitrary code)
                            lambda_layers = [l for l in metadata.layers 
                                           if l.get('class_name') == 'Lambda']
                            if lambda_layers:
                                warnings.append(f"Found {len(lambda_layers)} Lambda layers - may contain arbitrary code")
                                for layer in lambda_layers:
                                    suspicious_patterns.append(f"Lambda layer: {layer.get('name', 'unnamed')}")
                
                # Check for custom training code
                if 'training_config' in f.attrs:
                    training_config = json.loads(f.attrs['training_config'])
                    if 'custom_objects' in training_config:
                        warnings.append("Model contains custom objects")
                        suspicious_patterns.append("custom_objects")
                
                # Count parameters
                total_params = 0
                if 'model_weights' in f:
                    def count_params(name, obj):
                        nonlocal total_params
                        if isinstance(obj, h5py.Dataset):
                            total_params += obj.size
                    
                    f['model_weights'].visititems(count_params)
                    metadata.parameters_count = total_params
                
                # Check for suspicious attributes
                for key in f.attrs.keys():
                    if any(suspicious in key.lower() for suspicious in 
                          ['exec', 'eval', 'code', 'script', 'lambda']):
                        warnings.append(f"Suspicious attribute: {key}")
                        suspicious_patterns.append(key)
                
                # Check for non-standard groups
                standard_groups = {'model_weights', 'model_config', 'training_config'}
                extra_groups = set(f.keys()) - standard_groups
                if extra_groups:
                    warnings.append(f"Non-standard groups found: {extra_groups}")
                    suspicious_patterns.extend(list(extra_groups))
        
        except Exception as e:
            logger.error(f"Error parsing H5 file: {e}")
            warnings.append(f"Parse error: {str(e)}")
        
        return ParserResult(
            metadata=metadata,
            warnings=warnings,
            suspicious_patterns=suspicious_patterns,
            embedded_code=embedded_code,
            external_dependencies=external_dependencies,
            serialization_format="tensorflow_h5"
        )
    
    def _extract_layer_info(self, layers: List[Dict]) -> List[Dict[str, Any]]:
        """Extract layer information from model config."""
        layer_info = []
        
        for layer in layers:
            info = {
                'class_name': layer.get('class_name', 'Unknown'),
                'name': layer.get('config', {}).get('name', 'unnamed'),
            }
            
            # Extract important config
            config = layer.get('config', {})
            if 'units' in config:
                info['units'] = config['units']
            if 'activation' in config:
                info['activation'] = config['activation']
            if 'filters' in config:
                info['filters'] = config['filters']
            
            layer_info.append(info)
        
        return layer_info
    
    def _extract_suspicious_strings(self, content: bytes) -> List[str]:
        """Extract suspicious strings from binary content."""
        suspicious_keywords = [
            b'exec', b'eval', b'__import__', b'compile',
            b'subprocess', b'os.system', b'socket',
            b'urllib', b'requests', b'<script',
            b'javascript:', b'cmd.exe', b'/bin/sh'
        ]
        
        found = []
        for keyword in suspicious_keywords:
            if keyword in content:
                # Try to extract surrounding context
                index = content.find(keyword)
                start = max(0, index - 20)
                end = min(len(content), index + len(keyword) + 20)
                context = content[start:end].decode('utf-8', errors='ignore')
                found.append(f"{keyword.decode()}: {context}")
        
        return found