"""Parser manager to coordinate all model parsers."""

from pathlib import Path
from typing import Dict, List, Optional, Type

from llmshield.core.logger import get_logger
from llmshield.core.exceptions import UnsupportedFormatError
from llmshield.parsers.base import BaseParser, ParserResult
from llmshield.parsers.pickle_parser import PickleParser
from llmshield.parsers.pytorch_parser import PyTorchParser
from llmshield.parsers.tensorflow_parser import TensorFlowParser
from llmshield.parsers.yaml_parser import YAMLParser
from llmshield.parsers.joblib_parser import JoblibParser
from llmshield.parsers.checkpoint_parser import CheckpointParser
from llmshield.parsers.json_parser import JSONParser
from llmshield.parsers.text_parser import TextParser

logger = get_logger()


class ParserManager:
    """Manages all available parsers and routes files to appropriate parser."""
    
    def __init__(self, config: Optional[Dict] = None):
        """Initialize parser manager with all available parsers."""
        self.config = config or {}
        
        # Register all parsers (order matters - more specific parsers first)
        self.parsers: List[Type[BaseParser]] = [
            PyTorchParser,      # Check PyTorch before generic pickle
            TensorFlowParser,
            CheckpointParser,   # .ckpt files
            JSONParser,         # JSON configuration files
            JoblibParser,       # Scikit-learn models
            YAMLParser,         # YAML configuration files
            TextParser,         # Text files, source code, configs
            PickleParser,       # Generic pickle parser last
        ]
        
        # Initialize parser instances
        self.parser_instances: Dict[str, BaseParser] = {}
        for parser_class in self.parsers:
            instance = parser_class(config)
            self.parser_instances[parser_class.FRAMEWORK_NAME] = instance
    
    def get_supported_formats(self) -> Dict[str, List[str]]:
        """Get all supported formats grouped by framework."""
        formats = {}
        for parser_class in self.parsers:
            formats[parser_class.FRAMEWORK_NAME] = list(parser_class.SUPPORTED_EXTENSIONS)
        return formats
    
    def is_supported(self, file_path: Path) -> bool:
        """Check if file format is supported."""
        for parser_class in self.parsers:
            if parser_class.supports_file(file_path):
                return True
        return False
    
    def get_parser(self, file_path: Path) -> BaseParser:
        """Get appropriate parser for the file."""
        # Check each parser in order
        for parser_class in self.parsers:
            if parser_class.supports_file(file_path):
                parser = self.parser_instances[parser_class.FRAMEWORK_NAME]
                # Validate that it's actually the right format
                if parser.validate_format(file_path):
                    return parser
        
        raise UnsupportedFormatError(
            f"No parser found for file: {file_path}. "
            f"Supported formats: {self.get_supported_formats()}"
        )
    
    def parse_file(self, file_path: Path) -> ParserResult:
        """Parse a model file using the appropriate parser."""
        file_path = Path(file_path)
        
        if not file_path.exists():
            raise FileNotFoundError(f"File not found: {file_path}")
        
        logger.info(f"Attempting to parse file: {file_path}")
        
        try:
            with logger.component_context("parser_manager"):
                # Get appropriate parser
                parser = self.get_parser(file_path)
                parser_name = parser.__class__.__name__
                
                # Log parser selection
                logger.log_parsing_start(str(file_path), parser_name)
                logger.info(f"Using parser: {parser_name}")
                
                # Parse the file
                result = parser.parse(file_path)
                
                # Log successful parsing with metadata
                metadata = {
                    'framework': result.metadata.framework,
                    'format': result.metadata.format,
                    'file_size': result.metadata.file_size,
                    'model_type': getattr(result.metadata, 'model_type', None),
                    'warnings': len(result.warnings),
                    'suspicious_patterns': len(result.suspicious_patterns)
                }
                logger.log_parsing_success(str(file_path), metadata)
                
                # Log summary
                logger.info(f"Parse complete. Warnings: {len(result.warnings)}, "
                           f"Suspicious patterns: {len(result.suspicious_patterns)}")
                
                return result
                
        except Exception as e:
            logger.log_parsing_failure(str(file_path), e)
            logger.error(f"Failed to parse {file_path.name}: {str(e)}")
            raise
    
    def validate_file(self, file_path: Path) -> bool:
        """Validate that a file is in a supported format."""
        try:
            parser = self.get_parser(file_path)
            return parser.validate_format(file_path)
        except UnsupportedFormatError:
            return False