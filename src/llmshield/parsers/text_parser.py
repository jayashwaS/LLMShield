"""Parser for plain text files (.txt, .py, .env, .conf, .cfg, etc.)."""

import re
from pathlib import Path
from typing import Any, Dict, List, Optional, Set

from llmshield.core.logger import get_logger
from llmshield.core.exceptions import FileParsingError
from llmshield.parsers.base import BaseParser, ParserResult, ModelMetadata

logger = get_logger()


class TextParser(BaseParser):
    """Parser for plain text files including source code and config files."""
    
    SUPPORTED_EXTENSIONS: Set[str] = {
        '.txt', '.text', '.py', '.js', '.java', '.cpp', '.c', '.h', '.hpp',
        '.env', '.conf', '.cfg', '.ini', '.properties', '.xml', '.toml',
        '.sh', '.bash', '.ps1', '.bat', '.cmd', '.log', '.md', '.rst',
        '.html', '.htm', '.css', '.sql', '.r', '.m', '.go', '.rs', '.swift'
    }
    FRAMEWORK_NAME: str = "text"
    
    def validate_format(self, file_path: Path) -> bool:
        """Validate that the file is a text file."""
        try:
            # Try to read as text
            with open(file_path, 'r', encoding='utf-8') as f:
                f.read(1024)  # Read first 1KB to test
            return True
        except (UnicodeDecodeError, IOError):
            return False
    
    def parse(self, file_path: Path) -> ParserResult:
        """Parse text file."""
        logger.info(f"Parsing text file: {file_path}")
        
        metadata = self.extract_metadata(file_path)
        warnings = []
        suspicious_patterns = []
        embedded_code = []
        external_dependencies = []
        
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
            
            # Store raw content for scanners
            metadata.custom_attributes['raw_content'] = content
            metadata.custom_attributes['file_type'] = file_path.suffix.lower()
            
            # Analyze content based on file type
            if file_path.suffix.lower() in ['.py', '.js', '.java', '.cpp', '.c']:
                # Source code file
                analysis = self._analyze_source_code(content, file_path)
            elif file_path.suffix.lower() in ['.env', '.conf', '.cfg', '.ini']:
                # Config file
                analysis = self._analyze_config_file(content, file_path)
            else:
                # Generic text file
                analysis = self._analyze_generic_text(content, file_path)
            
            metadata.custom_attributes.update(analysis['metadata'])
            warnings.extend(analysis['warnings'])
            suspicious_patterns.extend(analysis['patterns'])
            embedded_code.extend(analysis.get('code', []))
            external_dependencies.extend(analysis.get('dependencies', []))
            
        except Exception as e:
            logger.error(f"Error parsing text file: {e}")
            warnings.append(f"Parse error: {str(e)}")
            raise FileParsingError(f"Failed to parse text file: {e}")
        
        return ParserResult(
            metadata=metadata,
            warnings=warnings,
            suspicious_patterns=suspicious_patterns,
            embedded_code=embedded_code,
            external_dependencies=external_dependencies,
            serialization_format="text"
        )
    
    def _analyze_source_code(self, content: str, file_path: Path) -> Dict[str, Any]:
        """Analyze source code files for security issues."""
        result = {
            'metadata': {'content_type': 'source_code'},
            'warnings': [],
            'patterns': [],
            'code': [],
            'dependencies': []
        }
        
        # Check for dangerous patterns
        dangerous_patterns = [
            (r'\beval\s*\(', 'Dynamic code evaluation'),
            (r'\bexec\s*\(', 'Dynamic code execution'),
            (r'__import__\s*\(', 'Dynamic import'),
            (r'subprocess\.(call|run|Popen)', 'Subprocess execution'),
            (r'os\.(system|popen|exec)', 'OS command execution'),
            (r'socket\.(socket|connect)', 'Network operations'),
            (r'requests\.(get|post|put|delete)', 'HTTP requests'),
            (r'urllib\.(request|urlopen)', 'URL operations'),
            (r'pickle\.(loads|load)', 'Pickle deserialization'),
            (r'yaml\.(load|unsafe_load)', 'Unsafe YAML loading')
        ]
        
        lines = content.splitlines()
        for i, line in enumerate(lines, 1):
            for pattern, desc in dangerous_patterns:
                if re.search(pattern, line):
                    result['patterns'].append({
                        'type': desc,
                        'pattern': pattern,
                        'line': i,
                        'content': line.strip()
                    })
                    result['warnings'].append(f"{desc} found at line {i}")
        
        # Extract imports (Python example)
        if file_path.suffix == '.py':
            import_pattern = r'^(?:from\s+(\S+)\s+)?import\s+(.+)$'
            for i, line in enumerate(lines, 1):
                match = re.match(import_pattern, line.strip())
                if match:
                    module = match.group(1) or match.group(2).split()[0]
                    result['dependencies'].append(module)
        
        return result
    
    def _analyze_config_file(self, content: str, file_path: Path) -> Dict[str, Any]:
        """Analyze configuration files."""
        result = {
            'metadata': {'content_type': 'configuration'},
            'warnings': [],
            'patterns': []
        }
        
        # Parse key-value pairs
        config_data = {}
        lines = content.splitlines()
        
        for i, line in enumerate(lines, 1):
            line = line.strip()
            if not line or line.startswith('#') or line.startswith(';'):
                continue
            
            # Try different config formats
            if '=' in line:
                key, _, value = line.partition('=')
                key = key.strip()
                value = value.strip().strip('"\'')
                config_data[key] = value
                
                # Check for sensitive keys
                sensitive_keys = ['password', 'secret', 'key', 'token', 'credential', 'api']
                if any(s in key.lower() for s in sensitive_keys):
                    result['patterns'].append({
                        'type': 'Sensitive configuration',
                        'key': key,
                        'line': i
                    })
                    result['warnings'].append(f"Sensitive configuration '{key}' at line {i}")
        
        result['metadata']['config_entries'] = len(config_data)
        result['metadata']['parsed_data'] = config_data
        
        return result
    
    def _analyze_generic_text(self, content: str, file_path: Path) -> Dict[str, Any]:
        """Analyze generic text files."""
        result = {
            'metadata': {'content_type': 'text'},
            'warnings': [],
            'patterns': []
        }
        
        # Look for patterns that might indicate secrets
        secret_patterns = [
            (r'[A-Z0-9]{20,}', 'Potential API key or token'),
            (r'-----BEGIN .+ KEY-----', 'Private key'),
            (r'password\s*[:=]\s*\S+', 'Password in plain text'),
            (r'(secret|token|key)\s*[:=]\s*\S+', 'Potential secret')
        ]
        
        lines = content.splitlines()
        for i, line in enumerate(lines, 1):
            for pattern, desc in secret_patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    result['patterns'].append({
                        'type': desc,
                        'pattern': pattern,
                        'line': i
                    })
                    result['warnings'].append(f"{desc} found at line {i}")
        
        result['metadata']['line_count'] = len(lines)
        result['metadata']['char_count'] = len(content)
        
        return result