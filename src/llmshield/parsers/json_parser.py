"""Parser for JSON configuration and model files."""

import json
from pathlib import Path
from typing import Any, Dict, List, Optional, Set

from llmshield.core.logger import get_logger
from llmshield.core.exceptions import FileParsingError, CorruptedFileError
from llmshield.parsers.base import BaseParser, ParserResult, ModelMetadata

logger = get_logger()


class JSONParser(BaseParser):
    """Parser for JSON format files (config.json, tokenizer.json, etc.)."""
    
    SUPPORTED_EXTENSIONS: Set[str] = {'.json'}
    FRAMEWORK_NAME: str = "json"
    
    # Common HuggingFace config files
    KNOWN_CONFIG_FILES = {
        'config.json': 'model_config',
        'tokenizer.json': 'tokenizer',
        'tokenizer_config.json': 'tokenizer_config',
        'preprocessor_config.json': 'preprocessor_config',
        'generation_config.json': 'generation_config',
        'special_tokens_map.json': 'special_tokens'
    }
    
    def validate_format(self, file_path: Path) -> bool:
        """Validate that the file is a valid JSON file."""
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                json.load(f)
                return True
        except Exception:
            return False
    
    def parse(self, file_path: Path) -> ParserResult:
        """Parse JSON file."""
        logger.info(f"Parsing JSON file: {file_path}")
        
        metadata = self.extract_metadata(file_path)
        warnings = []
        suspicious_patterns = []
        embedded_code = []
        external_dependencies = []
        
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                data = json.load(f)
            
            # Determine the type of JSON file
            filename = file_path.name
            if filename in self.KNOWN_CONFIG_FILES:
                metadata.custom_attributes['config_type'] = self.KNOWN_CONFIG_FILES[filename]
            
            # Analyze the structure
            analysis = self._analyze_json_content(data, file_path)
            metadata.custom_attributes.update(analysis['metadata'])
            warnings.extend(analysis['warnings'])
            suspicious_patterns.extend(analysis['patterns'])
            
            # Check for code execution patterns
            code_patterns = self._check_for_code_patterns(data)
            if code_patterns:
                embedded_code.extend(code_patterns['code'])
                warnings.extend(code_patterns['warnings'])
            
            # Extract model information if available
            if isinstance(data, dict):
                if 'model_type' in data:
                    metadata.model_architecture = data['model_type']
                if 'architectures' in data:
                    metadata.custom_attributes['architectures'] = data['architectures']
                if '_name_or_path' in data:
                    metadata.model_name = data['_name_or_path']
                if 'torch_dtype' in data:
                    metadata.custom_attributes['dtype'] = data['torch_dtype']
                if 'transformers_version' in data:
                    metadata.framework_version = data['transformers_version']
                    external_dependencies.append(f"transformers=={data['transformers_version']}")
        
            # Store the parsed JSON data for scanners to analyze
            metadata.custom_attributes['parsed_data'] = data
            metadata.custom_attributes['raw_content'] = json.dumps(data, indent=2)
        
        except Exception as e:
            logger.error(f"Error parsing JSON file: {e}")
            warnings.append(f"Parse error: {str(e)}")
            raise FileParsingError(f"Failed to parse JSON file: {e}")
        
        return ParserResult(
            metadata=metadata,
            warnings=warnings,
            suspicious_patterns=suspicious_patterns,
            embedded_code=embedded_code,
            external_dependencies=external_dependencies,
            serialization_format="json"
        )
    
    def _analyze_json_content(self, data: Any, file_path: Path) -> Dict[str, Any]:
        """Analyze JSON content for suspicious patterns."""
        result = {
            'metadata': {},
            'warnings': [],
            'patterns': []
        }
        
        def check_value(value, path=""):
            if isinstance(value, str):
                # Check for suspicious patterns
                suspicious_patterns = [
                    ('eval(', 'JavaScript eval'),
                    ('exec(', 'Python exec'),
                    ('__import__', 'Dynamic import'),
                    ('subprocess', 'Subprocess execution'),
                    ('os.system', 'System command'),
                    ('<script', 'Script tag'),
                    ('javascript:', 'JavaScript URL'),
                    ('data:text/html', 'Data URL with HTML'),
                    ('file://', 'File URL'),
                ]
                
                for pattern, desc in suspicious_patterns:
                    if pattern in value:
                        result['patterns'].append(f"{desc} at {path}: {value[:100]}")
                        result['warnings'].append(f"Found {desc} pattern")
                
                # Check for base64 encoded content
                if len(value) > 100 and all(c in 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=' for c in value.strip()):
                    result['warnings'].append(f"Possible base64 encoded content at {path}")
                    result['patterns'].append(f"base64 at {path}")
            
            elif isinstance(value, dict):
                # Check for Lambda layer configs (TensorFlow/Keras)
                if value.get('class_name') == 'Lambda':
                    result['warnings'].append(f"Lambda layer found at {path} - may contain arbitrary code")
                    result['patterns'].append(f"Lambda layer at {path}")
                
                for k, v in value.items():
                    check_value(v, f"{path}.{k}" if path else k)
            
            elif isinstance(value, list):
                for i, item in enumerate(value):
                    check_value(item, f"{path}[{i}]")
        
        check_value(data)
        
        # Check for suspicious top-level keys
        if isinstance(data, dict):
            suspicious_keys = ['custom_objects', 'lambda', 'function', 'code', 'script']
            for key in suspicious_keys:
                if key in data:
                    result['warnings'].append(f"Suspicious top-level key: {key}")
                    result['patterns'].append(f"Key: {key}")
        
        return result
    
    def _check_for_code_patterns(self, data: Any) -> Optional[Dict[str, List[str]]]:
        """Check for embedded code patterns."""
        code_snippets = []
        warnings = []
        
        def extract_code(value, path=""):
            if isinstance(value, str):
                # Check if it looks like code
                code_indicators = [
                    'def ', 'class ', 'import ', 'from ',
                    'function(', 'function (', '=>', 'var ', 'let ', 'const '
                ]
                
                if any(indicator in value for indicator in code_indicators) and len(value) > 50:
                    code_snippets.append(f"Potential code at {path}: {value[:200]}...")
                    warnings.append(f"Found potential code snippet at {path}")
            
            elif isinstance(value, dict):
                for k, v in value.items():
                    extract_code(v, f"{path}.{k}" if path else k)
            
            elif isinstance(value, list):
                for i, item in enumerate(value):
                    extract_code(item, f"{path}[{i}]")
        
        extract_code(data)
        
        if code_snippets:
            return {'code': code_snippets, 'warnings': warnings}
        return None