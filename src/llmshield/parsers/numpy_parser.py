"""Parser for NumPy array files."""

import numpy as np
from pathlib import Path
from typing import Any, Dict, List, Optional, Set
import zipfile
import pickle

from llmshield.core.logger import get_logger
from llmshield.core.exceptions import FileParsingError, CorruptedFileError
from llmshield.parsers.base import BaseParser, ParserResult, ModelMetadata

logger = get_logger()


class NumpyParser(BaseParser):
    """Parser for NumPy array files (.npy, .npz)."""
    
    SUPPORTED_EXTENSIONS: Set[str] = {'.npy', '.npz'}
    FRAMEWORK_NAME: str = "numpy"
    
    def validate_format(self, file_path: Path) -> bool:
        """Validate that the file is a valid NumPy file."""
        try:
            ext = file_path.suffix.lower()
            if ext == '.npy':
                # Check NPY magic number
                with open(file_path, 'rb') as f:
                    magic = f.read(6)
                    return magic == b'\x93NUMPY'
            elif ext == '.npz':
                # Check if it's a valid zip file
                return zipfile.is_zipfile(file_path)
            return False
        except Exception:
            return False
    
    def parse(self, file_path: Path) -> ParserResult:
        """Parse NumPy array file."""
        logger.info(f"Parsing NumPy file: {file_path}")
        
        metadata = self.extract_metadata(file_path)
        warnings = []
        suspicious_patterns = []
        embedded_code = []
        external_dependencies = []
        
        try:
            ext = file_path.suffix.lower()
            
            if ext == '.npy':
                result = self._parse_npy_file(file_path, metadata)
            else:  # .npz
                result = self._parse_npz_file(file_path, metadata)
            
            warnings.extend(result.get('warnings', []))
            suspicious_patterns.extend(result.get('patterns', []))
            
            # NumPy files can contain pickled objects
            if result.get('has_pickle', False):
                warnings.append("File contains pickled Python objects - potential security risk")
                suspicious_patterns.append("pickled_objects")
        
        except Exception as e:
            logger.error(f"Error parsing NumPy file: {e}")
            warnings.append(f"Parse error: {str(e)}")
            raise FileParsingError(f"Failed to parse NumPy file: {e}")
        
        return ParserResult(
            metadata=metadata,
            warnings=warnings,
            suspicious_patterns=suspicious_patterns,
            embedded_code=embedded_code,
            external_dependencies=external_dependencies,
            serialization_format="numpy"
        )
    
    def _parse_npy_file(self, file_path: Path, metadata: ModelMetadata) -> Dict[str, Any]:
        """Parse .npy file."""
        result = {'warnings': [], 'patterns': [], 'has_pickle': False}
        
        try:
            # Load with allow_pickle=False first for safety
            try:
                arr = np.load(file_path, allow_pickle=False)
                metadata.custom_attributes['shape'] = str(arr.shape)
                metadata.custom_attributes['dtype'] = str(arr.dtype)
                metadata.parameters_count = arr.size
            except ValueError:
                # File contains Python objects
                result['has_pickle'] = True
                result['warnings'].append("File requires pickle to load - contains Python objects")
                
                # Try to load with pickle enabled to inspect
                try:
                    arr = np.load(file_path, allow_pickle=True)
                    if isinstance(arr, np.ndarray) and arr.dtype == object:
                        result['warnings'].append("Array contains Python objects")
                        # Sample first few objects
                        for i, obj in enumerate(arr.flat):
                            if i >= 5:  # Check first 5 objects
                                break
                            obj_type = type(obj).__name__
                            if obj_type not in ['int', 'float', 'str', 'bytes', 'bool', 'NoneType']:
                                result['patterns'].append(f"Object type: {obj_type}")
                except Exception as e:
                    result['warnings'].append(f"Failed to inspect pickled content: {str(e)}")
            
            # Check for unusually large files
            file_size = file_path.stat().st_size
            if file_size > 1024 * 1024 * 1024:  # 1GB
                result['warnings'].append(f"Large file size: {file_size / (1024**3):.2f} GB")
        
        except Exception as e:
            result['warnings'].append(f"NPY parsing error: {str(e)}")
        
        return result
    
    def _parse_npz_file(self, file_path: Path, metadata: ModelMetadata) -> Dict[str, Any]:
        """Parse .npz file."""
        result = {'warnings': [], 'patterns': [], 'has_pickle': False}
        
        try:
            # NPZ files are zip archives
            with zipfile.ZipFile(file_path, 'r') as zf:
                # List all files in the archive
                file_list = zf.namelist()
                metadata.custom_attributes['num_arrays'] = len([f for f in file_list if f.endswith('.npy')])
                
                # Check for non-NPY files
                non_npy_files = [f for f in file_list if not f.endswith('.npy')]
                if non_npy_files:
                    result['warnings'].append(f"Non-NPY files in archive: {non_npy_files}")
                    result['patterns'].extend([f"non_npy:{f}" for f in non_npy_files])
            
            # Load the NPZ file
            try:
                npz = np.load(file_path, allow_pickle=False)
                arrays_info = []
                total_params = 0
                
                for key in npz.files:
                    arr = npz[key]
                    arrays_info.append({
                        'name': key,
                        'shape': str(arr.shape),
                        'dtype': str(arr.dtype)
                    })
                    total_params += arr.size
                
                metadata.custom_attributes['arrays'] = arrays_info
                metadata.parameters_count = total_params
                
            except ValueError:
                # Contains pickled objects
                result['has_pickle'] = True
                result['warnings'].append("NPZ file contains pickled objects")
                
                # Try to inspect with pickle
                try:
                    npz = np.load(file_path, allow_pickle=True)
                    for key in npz.files:
                        arr = npz[key]
                        if isinstance(arr, np.ndarray) and arr.dtype == object:
                            result['patterns'].append(f"Pickled array: {key}")
                except Exception as e:
                    result['warnings'].append(f"Failed to inspect pickled arrays: {str(e)}")
        
        except Exception as e:
            result['warnings'].append(f"NPZ parsing error: {str(e)}")
        
        return result