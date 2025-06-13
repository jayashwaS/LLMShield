"""Parser for PyTorch model files."""

import io
import pickle
import struct
import zipfile
from pathlib import Path
from typing import Any, Dict, List, Optional, Set

import torch

from llmshield.core.logger import get_logger
from llmshield.core.exceptions import FileParsingError, CorruptedFileError
from llmshield.parsers.base import BaseParser, ParserResult, ModelMetadata
from llmshield.parsers.pickle_parser import PickleParser

logger = get_logger()


class PyTorchParser(BaseParser):
    """Parser for PyTorch model files (.pt, .pth)."""
    
    SUPPORTED_EXTENSIONS: Set[str] = {'.pt', '.pth', '.bin'}
    FRAMEWORK_NAME: str = "pytorch"
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """Initialize PyTorch parser."""
        super().__init__(config)
        self.pickle_parser = PickleParser(config)
    
    def validate_format(self, file_path: Path) -> bool:
        """Validate that the file is a valid PyTorch file."""
        try:
            # Check if it's a zip file (newer PyTorch format)
            if zipfile.is_zipfile(file_path):
                with zipfile.ZipFile(file_path, 'r') as zf:
                    # Check for PyTorch zip structure
                    # PyTorch saves with pattern: archive_name/data.pkl
                    return any('data.pkl' in name for name in zf.namelist())
            
            # Otherwise, check if it's a pickle file
            return self.pickle_parser.validate_format(file_path)
        
        except Exception:
            return False
    
    def parse(self, file_path: Path) -> ParserResult:
        """Parse PyTorch model file."""
        logger.info(f"Parsing PyTorch file: {file_path}")
        
        metadata = self.extract_metadata(file_path)
        
        # Check if it's a zip-based PyTorch file
        if zipfile.is_zipfile(file_path):
            return self._parse_zip_format(file_path, metadata)
        else:
            # Fallback to pickle parser for older format
            result = self.pickle_parser.parse(file_path)
            result.metadata.framework = "pytorch"
            result.metadata.format = "pytorch_legacy"
            return result
    
    def _parse_zip_format(self, file_path: Path, metadata: ModelMetadata) -> ParserResult:
        """Parse newer zip-based PyTorch format."""
        warnings = []
        suspicious_patterns = []
        embedded_code = []
        external_dependencies = []
        
        try:
            with zipfile.ZipFile(file_path, 'r') as zf:
                # List all files in the archive
                file_list = zf.namelist()
                metadata.custom_attributes['archive_files'] = file_list
                
                # Check for suspicious files
                suspicious_files = [f for f in file_list if 
                                  f.endswith(('.py', '.pyc', '.exe', '.dll', '.so', '.sh', '.bat'))]
                if suspicious_files:
                    warnings.append(f"Suspicious files in archive: {suspicious_files}")
                    suspicious_patterns.extend(suspicious_files)
                
                # Parse main data file
                if 'data.pkl' in file_list:
                    with zf.open('data.pkl') as f:
                        # Analyze pickle content
                        pickle_data = f.read()
                        pickle_analysis = self._analyze_pickle_data(pickle_data)
                        suspicious_patterns.extend(pickle_analysis['suspicious_patterns'])
                        embedded_code.extend(pickle_analysis['embedded_code'])
                        external_dependencies.extend(pickle_analysis['imports'])
                
                # Check version info
                if 'version' in file_list:
                    with zf.open('version') as f:
                        version = f.read().decode('utf-8').strip()
                        metadata.framework_version = version
                
                # Extract model structure if available
                if 'model.json' in file_list:
                    with zf.open('model.json') as f:
                        import json
                        model_info = json.load(f)
                        metadata.model_architecture = model_info.get('architecture')
                        metadata.custom_attributes['model_info'] = model_info
                
                # Count parameters
                metadata.parameters_count = self._count_parameters(file_path)
        
        except Exception as e:
            logger.error(f"Error parsing PyTorch zip file: {e}")
            warnings.append(f"Parse error: {str(e)}")
        
        return ParserResult(
            metadata=metadata,
            warnings=warnings,
            suspicious_patterns=suspicious_patterns,
            embedded_code=embedded_code,
            external_dependencies=external_dependencies,
            serialization_format="pytorch_zip"
        )
    
    def _analyze_pickle_data(self, pickle_data: bytes) -> Dict[str, Any]:
        """Analyze pickle data from PyTorch file."""
        # Write to temporary file for analysis
        import tempfile
        with tempfile.NamedTemporaryFile(suffix='.pkl', delete=False) as tmp:
            tmp.write(pickle_data)
            tmp_path = Path(tmp.name)
        
        try:
            # Use pickle parser to analyze
            result = self.pickle_parser.parse(tmp_path)
            return {
                'suspicious_patterns': result.suspicious_patterns,
                'embedded_code': result.embedded_code,
                'imports': result.external_dependencies,
            }
        finally:
            # Clean up temp file
            tmp_path.unlink()
    
    def _count_parameters(self, file_path: Path) -> Optional[int]:
        """Count the number of parameters in the model."""
        try:
            # Load model with weights_only=True for safety
            state_dict = torch.load(file_path, map_location='cpu', weights_only=True)
            
            total_params = 0
            if isinstance(state_dict, dict):
                for key, tensor in state_dict.items():
                    if hasattr(tensor, 'numel'):
                        total_params += tensor.numel()
            
            return total_params
        
        except Exception as e:
            logger.debug(f"Could not count parameters: {e}")
            return None