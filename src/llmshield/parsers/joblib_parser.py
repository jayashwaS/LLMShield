"""Parser for Joblib serialized files."""

import joblib
import pickle
from pathlib import Path
from typing import Any, Dict, List, Optional, Set

from llmshield.core.logger import get_logger
from llmshield.core.exceptions import FileParsingError, CorruptedFileError
from llmshield.parsers.base import BaseParser, ParserResult, ModelMetadata

logger = get_logger()


class JoblibParser(BaseParser):
    """Parser for Joblib serialized files (.joblib, .pkl with joblib)."""
    
    SUPPORTED_EXTENSIONS: Set[str] = {'.joblib', '.jbl'}
    FRAMEWORK_NAME: str = "joblib"
    
    def validate_format(self, file_path: Path) -> bool:
        """Validate that the file is a valid Joblib file."""
        try:
            # Joblib files are essentially pickle files with some metadata
            with open(file_path, 'rb') as f:
                # Try to load just the header
                header = f.read(16)
                # Joblib uses pickle protocol, so check for pickle signature
                return header.startswith(b'\x80') or b'joblib' in header
        except Exception:
            return False
    
    def parse(self, file_path: Path) -> ParserResult:
        """Parse Joblib serialized file."""
        logger.info(f"Parsing Joblib file: {file_path}")
        
        metadata = self.extract_metadata(file_path)
        warnings = []
        suspicious_patterns = []
        embedded_code = []
        external_dependencies = []
        
        try:
            # Joblib uses pickle under the hood, so we need to be careful
            warnings.append("Joblib files use pickle serialization - potential security risk")
            
            # First, analyze the file structure without fully loading
            structure_info = self._analyze_file_structure(file_path)
            warnings.extend(structure_info.get('warnings', []))
            suspicious_patterns.extend(structure_info.get('patterns', []))
            
            # Try to get basic info about the content
            content_info = self._inspect_content(file_path)
            metadata.custom_attributes.update(content_info.get('metadata', {}))
            warnings.extend(content_info.get('warnings', []))
            
            # Check for suspicious pickle opcodes
            pickle_analysis = self._analyze_pickle_content(file_path)
            if pickle_analysis:
                warnings.extend(pickle_analysis.get('warnings', []))
                suspicious_patterns.extend(pickle_analysis.get('patterns', []))
                embedded_code.extend(pickle_analysis.get('code', []))
        
        except Exception as e:
            logger.error(f"Error parsing Joblib file: {e}")
            warnings.append(f"Parse error: {str(e)}")
            raise FileParsingError(f"Failed to parse Joblib file: {e}")
        
        return ParserResult(
            metadata=metadata,
            warnings=warnings,
            suspicious_patterns=suspicious_patterns,
            embedded_code=embedded_code,
            external_dependencies=external_dependencies,
            serialization_format="joblib"
        )
    
    def _analyze_file_structure(self, file_path: Path) -> Dict[str, Any]:
        """Analyze the file structure without fully loading."""
        result = {'warnings': [], 'patterns': []}
        
        try:
            file_size = file_path.stat().st_size
            if file_size > 1024 * 1024 * 1024:  # 1GB
                result['warnings'].append(f"Large file size: {file_size / (1024**3):.2f} GB")
            
            # Check if it's a compressed joblib file
            with open(file_path, 'rb') as f:
                header = f.read(32)
                if b'zlib' in header or header.startswith(b'\x78\x9c'):
                    result['warnings'].append("Compressed joblib file detected")
                elif b'gzip' in header or header.startswith(b'\x1f\x8b'):
                    result['warnings'].append("Gzip compressed joblib file detected")
        
        except Exception as e:
            result['warnings'].append(f"Structure analysis error: {str(e)}")
        
        return result
    
    def _inspect_content(self, file_path: Path) -> Dict[str, Any]:
        """Try to get basic info about the content."""
        result = {'metadata': {}, 'warnings': []}
        
        try:
            # Try to load with joblib but with restrictions
            # Note: This is still risky but we're doing it for analysis
            try:
                # Get the type without fully instantiating
                with open(file_path, 'rb') as f:
                    # Read enough to identify the type
                    content = f.read(1024)
                    
                    # Look for class names in the pickle
                    if b'sklearn' in content:
                        result['metadata']['likely_framework'] = 'scikit-learn'
                        result['warnings'].append("Contains scikit-learn objects")
                    if b'numpy' in content:
                        result['metadata']['uses_numpy'] = True
                    if b'pandas' in content:
                        result['metadata']['uses_pandas'] = True
                    if b'tensorflow' in content or b'keras' in content:
                        result['warnings'].append("May contain TensorFlow/Keras objects")
                    
            except Exception:
                pass
        
        except Exception as e:
            result['warnings'].append(f"Content inspection error: {str(e)}")
        
        return result
    
    def _analyze_pickle_content(self, file_path: Path) -> Optional[Dict[str, Any]]:
        """Analyze pickle opcodes in the file."""
        result = {'warnings': [], 'patterns': [], 'code': []}
        
        dangerous_opcodes = {
            b'c': 'GLOBAL - imports modules/classes',
            b'R': 'REDUCE - calls functions',
            b'b': 'BUILD - builds objects',
            b'i': 'INST - creates class instances',
            b'o': 'OBJ - builds class instances',
            b'\x93': 'STACK_GLOBAL - imports (protocol 4)',
            b'\x94': 'MEMOIZE - memory reference',
            b'\x95': 'FRAME - protocol 4 frame'
        }
        
        try:
            with open(file_path, 'rb') as f:
                content = f.read(min(1024 * 1024, file_path.stat().st_size))  # Read up to 1MB
                
                for opcode, description in dangerous_opcodes.items():
                    if opcode in content:
                        result['patterns'].append(f"Pickle opcode: {description}")
                
                # Look for specific dangerous patterns
                dangerous_imports = [
                    b'os\nsystem', b'subprocess', b'eval', b'exec',
                    b'compile', b'__import__', b'open', b'file',
                    b'input', b'raw_input', b'execfile'
                ]
                
                for pattern in dangerous_imports:
                    if pattern in content:
                        result['warnings'].append(f"Dangerous pattern found: {pattern.decode('utf-8', errors='ignore')}")
                        result['code'].append(f"Potential code execution: {pattern.decode('utf-8', errors='ignore')}")
        
        except Exception as e:
            result['warnings'].append(f"Pickle analysis error: {str(e)}")
        
        return result if result['patterns'] or result['warnings'] else None