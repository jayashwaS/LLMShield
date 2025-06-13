"""Parser for pickle files - handles .pkl, .pickle files."""

import ast
import dis
import io
import pickle
import pickletools
from pathlib import Path
from typing import Any, Dict, List, Set

from llmshield.core.logger import get_logger
from llmshield.core.exceptions import FileParsingError, CorruptedFileError
from llmshield.parsers.base import BaseParser, ParserResult, ModelMetadata

logger = get_logger()


class RestrictedUnpickler(pickle.Unpickler):
    """Restricted unpickler that prevents dangerous operations."""
    
    ALLOWED_MODULES = {
        'collections', 'numpy', 'torch', 'tensorflow',
        'pandas', 'sklearn', 'scipy', 'matplotlib'
    }
    
    def find_class(self, module: str, name: str):
        """Override find_class to restrict imports."""
        # Log all attempts to import
        logger.debug(f"Pickle attempting to import: {module}.{name}")
        
        # For analysis, we don't actually import - just record
        raise pickle.UnpicklingError(f"Restricted import: {module}.{name}")


class PickleParser(BaseParser):
    """Parser for pickle files."""
    
    SUPPORTED_EXTENSIONS: Set[str] = {'.pkl', '.pickle', '.pth', '.pt'}
    FRAMEWORK_NAME: str = "pickle"
    
    def validate_format(self, file_path: Path) -> bool:
        """Validate that the file is a valid pickle file."""
        try:
            with open(file_path, 'rb') as f:
                # Try to read pickle opcodes
                pickletools.dis(f, annotate=0, out=io.StringIO())
            return True
        except Exception:
            return False
    
    def parse(self, file_path: Path) -> ParserResult:
        """Parse pickle file and extract metadata."""
        logger.info(f"Parsing pickle file: {file_path}")
        
        metadata = self.extract_metadata(file_path)
        warnings = []
        suspicious_patterns = []
        embedded_code = []
        external_dependencies = []
        
        try:
            # Analyze pickle opcodes
            opcodes_analysis = self._analyze_opcodes(file_path)
            suspicious_patterns.extend(opcodes_analysis['suspicious_opcodes'])
            embedded_code.extend(opcodes_analysis['embedded_code'])
            external_dependencies.extend(opcodes_analysis['imports'])
            
            # Check for dangerous patterns
            if opcodes_analysis['has_reduce']:
                warnings.append("Contains REDUCE opcode - potential arbitrary code execution")
            if opcodes_analysis['has_global']:
                warnings.append("Contains GLOBAL opcode - imports external modules")
            if opcodes_analysis['has_exec']:
                warnings.append("Contains code execution patterns")
            
            # Try to get basic structure (safely)
            structure_info = self._analyze_structure(file_path)
            metadata.custom_attributes['structure'] = structure_info
            
        except Exception as e:
            logger.error(f"Error parsing pickle file: {e}")
            warnings.append(f"Parse error: {str(e)}")
        
        return ParserResult(
            metadata=metadata,
            warnings=warnings,
            suspicious_patterns=suspicious_patterns,
            embedded_code=embedded_code,
            external_dependencies=external_dependencies,
            serialization_format="pickle"
        )
    
    def _analyze_opcodes(self, file_path: Path) -> Dict[str, Any]:
        """Analyze pickle opcodes for security issues."""
        analysis = {
            'suspicious_opcodes': [],
            'embedded_code': [],
            'imports': [],
            'has_reduce': False,
            'has_global': False,
            'has_exec': False,
        }
        
        dangerous_opcodes = {
            'REDUCE': 'Can execute arbitrary code',
            'GLOBAL': 'Imports modules/functions',
            'INST': 'Creates class instances',
            'OBJ': 'Creates objects',
            'NEWOBJ': 'Creates new objects',
            'NEWOBJ_EX': 'Creates new objects with kwargs',
            'BUILD': 'Builds objects',
            'STACK_GLOBAL': 'Stack-based global import',
        }
        
        try:
            with open(file_path, 'rb') as f:
                output = io.StringIO()
                pickletools.dis(f, annotate=0, out=output)
                opcodes_text = output.getvalue()
            
            lines = opcodes_text.split('\n')
            for i, line in enumerate(lines):
                line = line.strip()
                if not line:
                    continue
                
                # Check for dangerous opcodes
                for opcode, description in dangerous_opcodes.items():
                    if opcode in line.split():  # Check if opcode is a word in the line
                        analysis['suspicious_opcodes'].append(f"{opcode}: {description}")
                        if opcode == 'REDUCE':
                            analysis['has_reduce'] = True
                        elif opcode in ['GLOBAL', 'STACK_GLOBAL']:
                            analysis['has_global'] = True
                            # For STACK_GLOBAL, look at previous lines for module/function names
                            if opcode == 'STACK_GLOBAL':
                                # Look for the two previous SHORT_BINUNICODE lines
                                module_name = None
                                func_name = None
                                for j in range(i-1, max(0, i-10), -1):
                                    if 'SHORT_BINUNICODE' in lines[j] and "'" in lines[j]:
                                        parts = lines[j].split("'")
                                        if len(parts) >= 2:
                                            if func_name is None:
                                                func_name = parts[1]
                                            elif module_name is None:
                                                module_name = parts[1]
                                                break
                                if module_name and func_name:
                                    analysis['imports'].append(f"{module_name}.{func_name}")
                                elif module_name:
                                    analysis['imports'].append(module_name)
                            # For GLOBAL, extract from current line
                            elif "'" in line:
                                parts = line.split("'")
                                if len(parts) >= 2:
                                    module = parts[1]  
                                    # Try to get function name
                                    if len(parts) >= 4:
                                        func = parts[3]
                                        analysis['imports'].append(f"{module}.{func}")
                                    else:
                                        analysis['imports'].append(module)
                
                # Check for code patterns
                if any(pattern in line for pattern in ['exec', 'eval', 'compile', '__code__']):
                    analysis['has_exec'] = True
                    analysis['embedded_code'].append({
                        'type': 'potential_exec',
                        'line': line,
                        'risk': 'high'
                    })
        
        except Exception as e:
            logger.warning(f"Error analyzing opcodes: {e}")
        
        return analysis
    
    def _analyze_structure(self, file_path: Path) -> Dict[str, Any]:
        """Safely analyze pickle structure without executing."""
        structure = {
            'format_version': None,
            'protocol': None,
            'size_bytes': file_path.stat().st_size,
            'opcodes_count': 0,
        }
        
        try:
            with open(file_path, 'rb') as f:
                # Get pickle protocol version
                magic = f.read(2)
                f.seek(0)
                
                if magic[:1] == b'\x80':
                    structure['protocol'] = magic[1]
                
                # Count opcodes
                output = io.StringIO()
                pickletools.dis(f, annotate=0, out=output)
                structure['opcodes_count'] = len(output.getvalue().split('\n'))
        
        except Exception as e:
            logger.debug(f"Error analyzing structure: {e}")
        
        return structure