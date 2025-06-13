"""Parser for MessagePack format files (Flax/JAX models)."""

import msgpack
from pathlib import Path
from typing import Any, Dict, List, Optional, Set

from llmshield.core.logger import get_logger
from llmshield.core.exceptions import FileParsingError, CorruptedFileError
from llmshield.parsers.base import BaseParser, ParserResult, ModelMetadata

logger = get_logger()


class MsgPackParser(BaseParser):
    """Parser for MessagePack format files (.msgpack, .flax)."""
    
    SUPPORTED_EXTENSIONS: Set[str] = {'.msgpack', '.flax'}
    FRAMEWORK_NAME: str = "flax"
    
    def validate_format(self, file_path: Path) -> bool:
        """Validate that the file is a valid MessagePack file."""
        try:
            with open(file_path, 'rb') as f:
                # Try to unpack the header
                unpacker = msgpack.Unpacker(f, raw=False, max_buffer_size=1024*1024)
                next(unpacker)  # Try to read first object
                return True
        except Exception:
            return False
    
    def parse(self, file_path: Path) -> ParserResult:
        """Parse MessagePack model file."""
        logger.info(f"Parsing MessagePack file: {file_path}")
        
        metadata = self.extract_metadata(file_path)
        warnings = []
        suspicious_patterns = []
        embedded_code = []
        external_dependencies = []
        
        try:
            with open(file_path, 'rb') as f:
                data = msgpack.unpack(f, raw=False, strict_map_key=False)
            
            # Analyze the structure
            structure_info = self._analyze_structure(data, file_path)
            metadata.custom_attributes.update(structure_info)
            
            # Check for suspicious patterns
            suspicious = self._check_suspicious_content(data)
            if suspicious:
                warnings.extend(suspicious['warnings'])
                suspicious_patterns.extend(suspicious['patterns'])
            
            # Count parameters if possible
            if isinstance(data, dict):
                param_count = self._count_parameters(data)
                if param_count > 0:
                    metadata.parameters_count = param_count
        
        except Exception as e:
            logger.error(f"Error parsing MessagePack file: {e}")
            warnings.append(f"Parse error: {str(e)}")
            raise FileParsingError(f"Failed to parse MessagePack file: {e}")
        
        return ParserResult(
            metadata=metadata,
            warnings=warnings,
            suspicious_patterns=suspicious_patterns,
            embedded_code=embedded_code,
            external_dependencies=external_dependencies,
            serialization_format="msgpack"
        )
    
    def _analyze_structure(self, data: Any, file_path: Path) -> Dict[str, Any]:
        """Analyze the structure of the MessagePack data."""
        info = {
            'data_type': type(data).__name__,
            'format_type': 'msgpack'
        }
        
        if isinstance(data, dict):
            info['top_level_keys'] = list(data.keys())[:10]  # First 10 keys
            
            # Check for Flax model structure
            if 'params' in data or 'opt_state' in data:
                info['model_type'] = 'flax_checkpoint'
            
            # Check for state dict
            if any(key in data for key in ['state', 'state_dict', 'model_state']):
                info['has_state_dict'] = True
        
        elif isinstance(data, (list, tuple)):
            info['length'] = len(data)
        
        return info
    
    def _check_suspicious_content(self, data: Any) -> Dict[str, List[str]]:
        """Check for suspicious content in the data."""
        warnings = []
        patterns = []
        
        def check_value(value, path=""):
            if isinstance(value, str):
                # Check for suspicious strings
                suspicious_keywords = [
                    'exec', 'eval', '__import__', 'compile',
                    'subprocess', 'os.system', 'socket',
                    'urllib', 'requests', 'base64'
                ]
                for keyword in suspicious_keywords:
                    if keyword in value.lower():
                        patterns.append(f"{keyword} at {path}")
                        warnings.append(f"Suspicious keyword '{keyword}' found")
            
            elif isinstance(value, dict):
                for k, v in value.items():
                    check_value(v, f"{path}.{k}" if path else k)
            
            elif isinstance(value, (list, tuple)):
                for i, item in enumerate(value):
                    check_value(item, f"{path}[{i}]")
        
        check_value(data)
        
        return {'warnings': warnings, 'patterns': patterns}
    
    def _count_parameters(self, data: Dict) -> int:
        """Count the number of parameters in the model."""
        total = 0
        
        def count_in_dict(d):
            nonlocal total
            for k, v in d.items():
                if isinstance(v, dict):
                    count_in_dict(v)
                elif hasattr(v, 'shape'):
                    # NumPy array or similar
                    total += v.size if hasattr(v, 'size') else 0
                elif isinstance(v, (list, tuple)) and len(v) > 0:
                    # Check if it's a nested parameter structure
                    if all(isinstance(x, (int, float)) for x in v[:10]):
                        total += len(v)
        
        if isinstance(data, dict):
            count_in_dict(data)
        
        return total