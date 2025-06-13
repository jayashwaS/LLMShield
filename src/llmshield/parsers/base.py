"""Base parser interface for all model parsers."""

import hashlib
from abc import ABC, abstractmethod
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional, Set

from llmshield.core.exceptions import FileParsingError, UnsupportedFormatError


@dataclass
class ModelMetadata:
    """Metadata extracted from a model file."""
    
    file_path: Path
    file_size: int
    file_hash: str
    format: str
    framework: str
    framework_version: Optional[str] = None
    model_architecture: Optional[str] = None
    layers: List[Dict[str, Any]] = None
    parameters_count: Optional[int] = None
    creation_date: Optional[str] = None
    training_metadata: Optional[Dict[str, Any]] = None
    custom_attributes: Optional[Dict[str, Any]] = None
    
    def __post_init__(self):
        """Initialize default values."""
        if self.layers is None:
            self.layers = []
        if self.custom_attributes is None:
            self.custom_attributes = {}


@dataclass
class ParserResult:
    """Result from parsing a model file."""
    
    metadata: ModelMetadata
    warnings: List[str]
    suspicious_patterns: List[str]
    embedded_code: List[Dict[str, Any]]
    external_dependencies: List[str]
    serialization_format: str
    
    def __post_init__(self):
        """Initialize default values."""
        if self.warnings is None:
            self.warnings = []
        if self.suspicious_patterns is None:
            self.suspicious_patterns = []
        if self.embedded_code is None:
            self.embedded_code = []
        if self.external_dependencies is None:
            self.external_dependencies = []


class BaseParser(ABC):
    """Abstract base class for all model parsers."""
    
    SUPPORTED_EXTENSIONS: Set[str] = set()
    FRAMEWORK_NAME: str = ""
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """Initialize parser with optional configuration."""
        self.config = config or {}
        
    @classmethod
    def supports_file(cls, file_path: Path) -> bool:
        """Check if this parser supports the given file."""
        return file_path.suffix.lower() in cls.SUPPORTED_EXTENSIONS
    
    def calculate_file_hash(self, file_path: Path, algorithm: str = "sha256") -> str:
        """Calculate hash of the file."""
        hash_func = hashlib.new(algorithm)
        with open(file_path, 'rb') as f:
            for chunk in iter(lambda: f.read(4096), b""):
                hash_func.update(chunk)
        return hash_func.hexdigest()
    
    @abstractmethod
    def parse(self, file_path: Path) -> ParserResult:
        """Parse the model file and extract metadata."""
        pass
    
    @abstractmethod
    def validate_format(self, file_path: Path) -> bool:
        """Validate that the file is in the expected format."""
        pass
    
    def extract_metadata(self, file_path: Path) -> ModelMetadata:
        """Extract basic metadata from the file."""
        if not file_path.exists():
            raise FileParsingError(f"File not found: {file_path}")
        
        file_stat = file_path.stat()
        file_hash = self.calculate_file_hash(file_path)
        
        return ModelMetadata(
            file_path=file_path,
            file_size=file_stat.st_size,
            file_hash=file_hash,
            format=file_path.suffix.lower(),
            framework=self.FRAMEWORK_NAME,
        )
    
    def check_suspicious_imports(self, code: str) -> List[str]:
        """Check for suspicious imports in embedded code."""
        suspicious_patterns = [
            "os.system",
            "subprocess",
            "eval",
            "exec", 
            "__import__",
            "compile",
            "open(",
            "file(",
            "input(",
            "raw_input",
            "socket",
            "urllib",
            "requests",
            "http.client",
            "ftplib",
            "telnetlib",
            "smtplib",
            "email",
            "ctypes",
            "cffi",
            "cryptography",
            "pickle.loads",
            "marshal.loads",
            "shelve",
            "tempfile",
            "shutil.rmtree",
            "os.remove",
            "pathlib.Path.unlink",
        ]
        
        found_patterns = []
        for pattern in suspicious_patterns:
            if pattern in code:
                found_patterns.append(pattern)
        
        return found_patterns