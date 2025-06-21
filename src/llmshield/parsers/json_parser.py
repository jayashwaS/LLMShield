"""Parser for JSON files."""

import json
from pathlib import Path
from typing import Any, Dict, Set

from llmshield.core.logger import get_logger
from llmshield.core.exceptions import FileParsingError
from llmshield.parsers.base import BaseParser, ParserResult, ModelMetadata

logger = get_logger()


class JSONParser(BaseParser):
    """Parser for JSON configuration files."""
    
    SUPPORTED_EXTENSIONS: Set[str] = {'.json'}
    FRAMEWORK_NAME: str = "json"
    
    @classmethod
    def supports_file(cls, file_path: Path) -> bool:
        """Check if this parser supports the given file."""
        return file_path.suffix.lower() in cls.SUPPORTED_EXTENSIONS
    
    def validate_format(self, file_path: Path) -> bool:
        """Validate that the file is a valid JSON file."""
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                json.load(f)
            return True
        except (json.JSONDecodeError, IOError):
            return False
    
    def parse(self, file_path: Path) -> ParserResult:
        """Parse JSON file and extract content."""
        file_path = Path(file_path)
        
        if not self.validate_format(file_path):
            raise FileParsingError(f"Invalid JSON file: {file_path}")
        
        logger.info(f"Parsing JSON file: {file_path}")
        
        try:
            # Read the file
            with open(file_path, 'r', encoding='utf-8') as f:
                raw_content = f.read()
                
            # Parse JSON
            data = json.loads(raw_content)
            
            # Create metadata
            metadata = ModelMetadata(
                framework=self.FRAMEWORK_NAME,
                format="json",
                size=file_path.stat().st_size,
                hash=self._calculate_hash(file_path),
                custom_attributes={
                    'raw_content': raw_content,
                    'loaded_data': data
                }
            )
            
            return ParserResult(
                framework=self.FRAMEWORK_NAME,
                model_data=data,
                metadata=metadata
            )
            
        except Exception as e:
            logger.error(f"Error parsing JSON file {file_path}: {e}")
            raise FileParsingError(f"Failed to parse JSON file: {e}")