"""Parser for checkpoint files (.ckpt and related formats)."""

import struct
import pickle
from pathlib import Path
from typing import Any, Dict, List, Optional, Set

from llmshield.core.logger import get_logger
from llmshield.core.exceptions import FileParsingError, CorruptedFileError
from llmshield.parsers.base import BaseParser, ParserResult, ModelMetadata

logger = get_logger()


class CheckpointParser(BaseParser):
    """Parser for checkpoint files (.ckpt, .ckpt.index, .ckpt.data)."""
    
    SUPPORTED_EXTENSIONS: Set[str] = {'.ckpt'}
    FRAMEWORK_NAME: str = "checkpoint"
    
    def validate_format(self, file_path: Path) -> bool:
        """Validate that the file is a valid checkpoint file."""
        try:
            # Checkpoint files can be in various formats
            # Most commonly they're pickle files or have associated index/data files
            
            # Check if it's a pickle-based checkpoint
            with open(file_path, 'rb') as f:
                header = f.read(16)
                # Check for pickle protocol
                if header.startswith(b'\x80'):
                    return True
                # Check for zip file (some checkpoints are zipped)
                if header.startswith(b'PK'):
                    return True
                # Check for TensorFlow checkpoint
                if b'model_checkpoint_path' in header:
                    return True
            
            # Check for associated files
            base_path = file_path.with_suffix('')
            if (base_path.with_suffix('.ckpt.index').exists() or 
                base_path.with_suffix('.ckpt.data-00000-of-00001').exists()):
                return True
            
            return False
        except Exception:
            return False
    
    def parse(self, file_path: Path) -> ParserResult:
        """Parse checkpoint file."""
        logger.info(f"Parsing checkpoint file: {file_path}")
        
        metadata = self.extract_metadata(file_path)
        warnings = []
        suspicious_patterns = []
        embedded_code = []
        external_dependencies = []
        
        try:
            # Determine checkpoint type
            ckpt_type = self._determine_checkpoint_type(file_path)
            metadata.custom_attributes['checkpoint_type'] = ckpt_type
            
            if ckpt_type == 'tensorflow_v2':
                result = self._parse_tensorflow_checkpoint(file_path, metadata)
            elif ckpt_type == 'pickle':
                result = self._parse_pickle_checkpoint(file_path, metadata)
            elif ckpt_type == 'pytorch':
                result = self._parse_pytorch_checkpoint(file_path, metadata)
            else:
                result = self._parse_generic_checkpoint(file_path, metadata)
            
            warnings.extend(result.get('warnings', []))
            suspicious_patterns.extend(result.get('patterns', []))
            embedded_code.extend(result.get('code', []))
            external_dependencies.extend(result.get('dependencies', []))
        
        except Exception as e:
            logger.error(f"Error parsing checkpoint file: {e}")
            warnings.append(f"Parse error: {str(e)}")
            raise FileParsingError(f"Failed to parse checkpoint file: {e}")
        
        return ParserResult(
            metadata=metadata,
            warnings=warnings,
            suspicious_patterns=suspicious_patterns,
            embedded_code=embedded_code,
            external_dependencies=external_dependencies,
            serialization_format="checkpoint"
        )
    
    def _determine_checkpoint_type(self, file_path: Path) -> str:
        """Determine the type of checkpoint file."""
        # Check for TensorFlow v2 checkpoint files
        base_path = file_path.with_suffix('')
        if (base_path.with_suffix('.ckpt.index').exists() or 
            file_path.name.endswith('.ckpt.index')):
            return 'tensorflow_v2'
        
        # Check file content
        try:
            with open(file_path, 'rb') as f:
                header = f.read(256)
                
                # PyTorch checkpoint
                if b'torch' in header or b'pytorch' in header.lower():
                    return 'pytorch'
                
                # Pickle-based
                if header.startswith(b'\x80'):
                    return 'pickle'
                
                # TensorFlow v1
                if b'tensorflow' in header.lower() or b'model_checkpoint_path' in header:
                    return 'tensorflow_v1'
        except Exception:
            pass
        
        return 'unknown'
    
    def _parse_tensorflow_checkpoint(self, file_path: Path, metadata: ModelMetadata) -> Dict[str, Any]:
        """Parse TensorFlow checkpoint."""
        result = {'warnings': [], 'patterns': [], 'code': [], 'dependencies': ['tensorflow']}
        
        try:
            # Check for index file
            index_file = file_path.with_suffix('.ckpt.index')
            if not index_file.exists():
                index_file = file_path
            
            if index_file.name.endswith('.index'):
                result['warnings'].append("TensorFlow v2 checkpoint with index file")
                # The actual data is in .data files
                data_files = list(file_path.parent.glob(f"{file_path.stem}.data-*"))
                if data_files:
                    metadata.custom_attributes['data_shards'] = len(data_files)
                    total_size = sum(f.stat().st_size for f in data_files)
                    metadata.custom_attributes['total_size_bytes'] = total_size
            
            # Check for checkpoint metadata file
            ckpt_file = file_path.with_suffix('')
            if ckpt_file.exists():
                with open(ckpt_file, 'rb') as f:
                    content = f.read(1024)
                    if b'model_checkpoint_path' in content:
                        result['warnings'].append("TensorFlow v1 checkpoint detected")
        
        except Exception as e:
            result['warnings'].append(f"TensorFlow checkpoint parsing error: {str(e)}")
        
        return result
    
    def _parse_pickle_checkpoint(self, file_path: Path, metadata: ModelMetadata) -> Dict[str, Any]:
        """Parse pickle-based checkpoint."""
        result = {'warnings': [], 'patterns': [], 'code': [], 'dependencies': []}
        
        result['warnings'].append("Pickle-based checkpoint - potential security risk")
        
        try:
            # Analyze pickle content for dangerous opcodes
            with open(file_path, 'rb') as f:
                content = f.read(min(1024 * 1024, file_path.stat().st_size))
                
                # Look for dangerous patterns
                dangerous_patterns = [
                    (b'os\nsystem', 'os.system call'),
                    (b'subprocess', 'subprocess module'),
                    (b'eval', 'eval function'),
                    (b'exec', 'exec function'),
                    (b'__import__', 'dynamic import'),
                    (b'compile', 'compile function'),
                ]
                
                for pattern, desc in dangerous_patterns:
                    if pattern in content:
                        result['patterns'].append(f"Dangerous pattern: {desc}")
                        result['code'].append(desc)
                
                # Check for specific frameworks
                if b'torch' in content:
                    result['dependencies'].append('torch')
                    metadata.custom_attributes['likely_framework'] = 'pytorch'
                if b'tensorflow' in content:
                    result['dependencies'].append('tensorflow')
                if b'numpy' in content:
                    result['dependencies'].append('numpy')
        
        except Exception as e:
            result['warnings'].append(f"Pickle checkpoint parsing error: {str(e)}")
        
        return result
    
    def _parse_pytorch_checkpoint(self, file_path: Path, metadata: ModelMetadata) -> Dict[str, Any]:
        """Parse PyTorch checkpoint."""
        result = {'warnings': [], 'patterns': [], 'code': [], 'dependencies': ['torch']}
        
        try:
            # PyTorch checkpoints are usually pickle files with specific structure
            result['warnings'].append("PyTorch checkpoint detected")
            metadata.custom_attributes['framework'] = 'pytorch'
            
            # Check file size
            file_size = file_path.stat().st_size
            if file_size > 5 * 1024 * 1024 * 1024:  # 5GB
                result['warnings'].append(f"Very large checkpoint: {file_size / (1024**3):.2f} GB")
        
        except Exception as e:
            result['warnings'].append(f"PyTorch checkpoint parsing error: {str(e)}")
        
        return result
    
    def _parse_generic_checkpoint(self, file_path: Path, metadata: ModelMetadata) -> Dict[str, Any]:
        """Parse generic/unknown checkpoint format."""
        result = {'warnings': [], 'patterns': [], 'code': [], 'dependencies': []}
        
        result['warnings'].append("Unknown checkpoint format - limited analysis available")
        
        try:
            # Do basic analysis
            file_size = file_path.stat().st_size
            metadata.custom_attributes['file_size_bytes'] = file_size
            
            # Try to read as binary and look for clues
            with open(file_path, 'rb') as f:
                sample = f.read(4096)
                
                # Look for framework indicators
                frameworks = {
                    b'keras': 'keras',
                    b'torch': 'pytorch',
                    b'tensorflow': 'tensorflow',
                    b'paddle': 'paddlepaddle',
                    b'mxnet': 'mxnet',
                    b'caffe': 'caffe'
                }
                
                for indicator, framework in frameworks.items():
                    if indicator in sample.lower():
                        metadata.custom_attributes['possible_framework'] = framework
                        result['dependencies'].append(framework)
                        break
        
        except Exception as e:
            result['warnings'].append(f"Generic checkpoint parsing error: {str(e)}")
        
        return result