# Development Guide

## Contributing to LLMShield

We welcome contributions! This guide will help you get started with developing new features, scanners, and parsers for LLMShield.

## Development Setup

### Prerequisites

- Python 3.8 or higher
- Git
- Virtual environment tool (venv, virtualenv, or conda)
- Development tools (pytest, black, flake8)

### Setting Up Development Environment

1. **Fork and clone the repository**
```bash
git clone https://github.com/YOUR_USERNAME/llmshield.git
cd llmshield
```

2. **Create virtual environment**
```bash
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

3. **Install in development mode**
```bash
pip install -r requirements.txt
pip install -e ".[dev]"
```

4. **Install pre-commit hooks**
```bash
pre-commit install
```

## Project Structure

```
llmshield/
├── src/llmshield/
│   ├── cli/              # Command-line interface
│   │   ├── main.py       # Main CLI entry point
│   │   └── commands/     # CLI commands
│   ├── core/             # Core functionality
│   │   ├── config.py     # Configuration management
│   │   ├── logger.py     # Logging setup
│   │   └── exceptions.py # Custom exceptions
│   ├── parsers/          # File parsers
│   │   ├── base.py       # Base parser interface
│   │   └── *.py          # Specific format parsers
│   ├── scanners/         # Security scanners
│   │   ├── base.py       # Base scanner interface
│   │   └── *.py          # Specific scanners
│   ├── reports/          # Report generators
│   │   ├── base.py       # Base reporter interface
│   │   └── *.py          # Format-specific reporters
│   └── integrations/     # External integrations
├── config/               # Configuration files
│   └── detection_rules.yaml
├── tests/                # Test suite
├── docs/                 # Documentation
└── examples/             # Example files
```

## Adding a New Scanner

### 1. Create Scanner Class

Create a new file in `src/llmshield/scanners/`:

```python
# src/llmshield/scanners/my_scanner.py
from typing import Dict, Any, List
from pathlib import Path
from .base import BaseScanner, ScanResult, Vulnerability, Severity

class MyScanner(BaseScanner):
    """Scanner for detecting specific vulnerabilities."""
    
    def __init__(self, config: Dict[str, Any] = None):
        super().__init__(config)
        self._name = "MyScanner"
        self._description = "Detects my specific vulnerability type"
        self._supported_formats = [".pkl", ".pth", ".py"]  # Supported file extensions
    
    @property
    def name(self) -> str:
        return self._name
    
    @property
    def description(self) -> str:
        return self._description
    
    @property
    def supported_formats(self) -> List[str]:
        return self._supported_formats
    
    def can_scan(self, file_path: Path, parsed_data: Dict[str, Any]) -> bool:
        """Check if this scanner can handle the file."""
        # Check file extension
        if file_path.suffix.lower() in self.supported_formats:
            return True
        
        # Check parsed data format
        if parsed_data.get('format') in ['pickle', 'pytorch']:
            return True
            
        return False
    
    def scan(self, file_path: Path, parsed_data: Dict[str, Any]) -> ScanResult:
        """Perform the actual scanning."""
        vulnerabilities = []
        
        # Your detection logic here
        if self._detect_vulnerability(parsed_data):
            vuln = Vulnerability(
                severity=Severity.HIGH,
                category="my-category",
                description="Vulnerability detected",
                details="Detailed information about the finding",
                remediation="How to fix this issue",
                confidence=0.95,
                location=f"Line 10",
                evidence={"key": "value"}
            )
            vulnerabilities.append(vuln)
        
        return ScanResult(
            scanner_name=self.name,
            vulnerabilities=vulnerabilities,
            metadata={"scanned_items": 100}
        )
    
    def _detect_vulnerability(self, data: Dict[str, Any]) -> bool:
        """Helper method for detection logic."""
        # Implement your detection logic
        return False
```

### 2. Register Scanner

Add your scanner to `src/llmshield/scanners/__init__.py`:

```python
from .my_scanner import MyScanner

__all__ = [
    # ... existing scanners ...
    'MyScanner',
]
```

### 3. Update Scanner Manager

Register in `src/llmshield/scanners/scanner_manager.py`:

```python
def initialize_default_scanners(self):
    """Initialize all default scanners."""
    from . import (
        # ... existing imports ...
        MyScanner
    )
    
    default_scanners = [
        # ... existing scanners ...
        MyScanner(),
    ]
```

### 4. Add Tests

Create `tests/test_my_scanner.py`:

```python
import pytest
from llmshield.scanners.my_scanner import MyScanner
from pathlib import Path

def test_my_scanner_detection():
    scanner = MyScanner()
    
    # Create test data
    test_file = Path("test.pkl")
    parsed_data = {
        "format": "pickle",
        "content": {"suspicious": "data"}
    }
    
    # Run scan
    result = scanner.scan(test_file, parsed_data)
    
    # Verify results
    assert len(result.vulnerabilities) > 0
    assert result.vulnerabilities[0].severity == Severity.HIGH
```

## Adding a New Parser

### 1. Create Parser Class

Create a new file in `src/llmshield/parsers/`:

```python
# src/llmshield/parsers/my_format_parser.py
from pathlib import Path
from typing import Set
from .base import BaseParser, ParserResult, ModelMetadata

class MyFormatParser(BaseParser):
    """Parser for my custom format."""
    
    SUPPORTED_EXTENSIONS: Set[str] = {'.myformat', '.mf'}
    FRAMEWORK_NAME: str = "myframework"
    
    def validate_format(self, file_path: Path) -> bool:
        """Validate that the file is in the correct format."""
        try:
            # Check magic bytes or file structure
            with open(file_path, 'rb') as f:
                header = f.read(4)
                return header == b'MYFM'
        except:
            return False
    
    def parse(self, file_path: Path) -> ParserResult:
        """Parse the file and extract information."""
        metadata = self.extract_metadata(file_path)
        warnings = []
        suspicious_patterns = []
        
        try:
            # Parse file content
            with open(file_path, 'rb') as f:
                # Your parsing logic here
                content = self._parse_content(f)
            
            # Extract information
            metadata.custom_attributes['version'] = content.get('version')
            
            # Check for suspicious patterns
            if self._has_suspicious_content(content):
                suspicious_patterns.append({
                    'type': 'suspicious_function',
                    'pattern': 'eval',
                    'location': 'block_5'
                })
            
            return ParserResult(
                metadata=metadata,
                warnings=warnings,
                suspicious_patterns=suspicious_patterns,
                content=content
            )
            
        except Exception as e:
            raise FileParsingError(f"Failed to parse: {e}")
    
    def _parse_content(self, file_handle):
        """Parse file content."""
        # Implement parsing logic
        return {}
    
    def _has_suspicious_content(self, content):
        """Check for suspicious patterns."""
        # Implement detection logic
        return False
```

### 2. Register Parser

Add to `src/llmshield/parsers/parser_manager.py`:

```python
from llmshield.parsers.my_format_parser import MyFormatParser

# In __init__ method:
self.parsers: List[Type[BaseParser]] = [
    # ... existing parsers ...
    MyFormatParser,
]
```

## Adding Detection Rules

### 1. Add to YAML Rules

Edit `config/detection_rules.yaml`:

```yaml
# New category
my_detections:
  my_pattern:
    name: "My Detection Pattern"
    enabled: true
    patterns:
      - "dangerous_pattern_[0-9]+"
      - "malicious_\\w+"
    severity: "HIGH"
    description: "Detects my specific pattern"
    remediation: "Remove or sanitize the pattern"
    tags: ["custom", "dangerous"]
```

### 2. Create Rule-Based Scanner

```python
from .yaml_rule_scanner import YamlRuleScanner

class MyRuleScanner(YamlRuleScanner):
    def __init__(self):
        super().__init__()
        self._name = "MyRuleScanner"
        self._description = "Custom rule-based scanner"
        
    def scan(self, file_path: str, parsed_data: Dict[str, Any]) -> ScanResult:
        # Use parent's scan with filtering
        result = super().scan(file_path, parsed_data)
        
        # Filter to only your rules
        filtered_vulns = [
            v for v in result.vulnerabilities 
            if v.category == 'my_detections'
        ]
        
        return ScanResult(
            scanner_name=self.name,
            vulnerabilities=filtered_vulns
        )
```

## Testing

### Running Tests

```bash
# Run all tests
pytest

# Run specific test file
pytest tests/test_my_scanner.py

# Run with coverage
pytest --cov=llmshield tests/

# Run specific test
pytest tests/test_my_scanner.py::test_detection
```

### Writing Tests

```python
# tests/test_my_feature.py
import pytest
from llmshield.scanners import MyScanner

class TestMyScanner:
    @pytest.fixture
    def scanner(self):
        return MyScanner()
    
    @pytest.fixture
    def malicious_data(self):
        return {
            "content": "malicious_pattern_123",
            "metadata": {"version": "1.0"}
        }
    
    def test_detects_pattern(self, scanner, malicious_data):
        result = scanner.scan("test.pkl", malicious_data)
        assert len(result.vulnerabilities) == 1
        assert result.vulnerabilities[0].severity == Severity.HIGH
    
    def test_clean_file(self, scanner):
        clean_data = {"content": "safe_content"}
        result = scanner.scan("test.pkl", clean_data)
        assert len(result.vulnerabilities) == 0
```

## Code Style

### Format Code

```bash
# Format with black
black src/llmshield

# Check with flake8
flake8 src/llmshield

# Sort imports
isort src/llmshield
```

### Style Guidelines

1. **Follow PEP 8**
2. **Use type hints**
3. **Document all public methods**
4. **Keep methods focused and small**
5. **Write descriptive variable names**

Example:

```python
from typing import Dict, List, Optional

def analyze_patterns(
    content: str,
    patterns: List[str],
    case_sensitive: bool = False
) -> Optional[Dict[str, Any]]:
    """
    Analyze content for matching patterns.
    
    Args:
        content: The text to analyze
        patterns: List of regex patterns to search for
        case_sensitive: Whether to use case-sensitive matching
        
    Returns:
        Dictionary with matches or None if no matches found
    """
    # Implementation
```

## Debugging

### Enable Debug Logging

```python
# In your code
from llmshield.core.logger import get_logger

logger = get_logger(__name__)
logger.debug("Detailed information for debugging")
```

```bash
# Run with debug logging
LLMSHIELD_LOG_LEVEL=DEBUG llmshield scan test.pkl
```

### Using Debugger

```python
# Add breakpoint
import pdb; pdb.set_trace()

# Or use IDE debugger with pytest
pytest --pdb tests/test_my_scanner.py
```

## Documentation

### Docstring Format

```python
def my_method(self, param1: str, param2: int = 10) -> Dict[str, Any]:
    """
    Brief description of what the method does.
    
    Longer description with more details about the behavior,
    edge cases, and important notes.
    
    Args:
        param1: Description of first parameter
        param2: Description of second parameter (default: 10)
        
    Returns:
        Description of return value
        
    Raises:
        ValueError: When param1 is empty
        TypeError: When param2 is not an integer
        
    Example:
        >>> scanner = MyScanner()
        >>> result = scanner.my_method("test", 20)
        >>> print(result)
        {'status': 'success', 'value': 20}
    """
```

### Updating Documentation

1. **API changes**: Update method docstrings
2. **New features**: Add to user guide
3. **New scanners**: Document in scanners.md
4. **Configuration**: Update configuration.md

## Submitting Changes

### 1. Create Feature Branch

```bash
git checkout -b feature/my-new-scanner
```

### 2. Make Changes

- Write code
- Add tests
- Update documentation
- Run tests locally

### 3. Commit Changes

```bash
git add .
git commit -m "feat: Add MyScanner for detecting X vulnerabilities"
```

### Commit Message Format

- `feat:` New feature
- `fix:` Bug fix
- `docs:` Documentation only
- `style:` Code style changes
- `refactor:` Code refactoring
- `test:` Test changes
- `chore:` Build process or auxiliary tool changes

### 4. Push and Create PR

```bash
git push origin feature/my-new-scanner
```

Then create a Pull Request on GitHub with:
- Clear description
- Link to related issues
- Test results
- Documentation updates

## Performance Considerations

### Optimization Tips

1. **Use generators** for large data processing
2. **Cache compiled regex** patterns
3. **Limit memory usage** with streaming
4. **Profile code** to find bottlenecks

```python
# Cache regex patterns
class MyScanner(BaseScanner):
    def __init__(self):
        super().__init__()
        # Compile patterns once
        self._patterns = [
            re.compile(pattern) 
            for pattern in self.get_patterns()
        ]
    
    def scan_content(self, content: str):
        # Use pre-compiled patterns
        for pattern in self._patterns:
            if pattern.search(content):
                yield self._create_vulnerability(pattern)
```

### Memory Management

```python
def parse_large_file(self, file_path: Path):
    """Parse large files in chunks."""
    chunk_size = 1024 * 1024  # 1MB chunks
    
    with open(file_path, 'rb') as f:
        while True:
            chunk = f.read(chunk_size)
            if not chunk:
                break
            yield self._process_chunk(chunk)
```

## Release Process

1. **Update version** in `setup.py`
2. **Update CHANGELOG.md**
3. **Run full test suite**
4. **Create release tag**
5. **Build and publish**

```bash
# Tag release
git tag -a v0.2.0 -m "Release version 0.2.0"
git push origin v0.2.0

# Build package
python setup.py sdist bdist_wheel

# Upload to PyPI (maintainers only)
twine upload dist/*
```

## Getting Help

- **Discord**: Join our developer community
- **GitHub Issues**: Report bugs or request features
- **Email**: dev@llmshield.io

## Resources

- [Python Security Guide](https://python.readthedocs.io/en/latest/library/security_warnings.html)
- [OWASP ML Security](https://owasp.org/www-project-machine-learning-security/)
- [pickle Security](https://docs.python.org/3/library/pickle.html#security)
- [ML Model Attacks](https://github.com/mitre/advmlthreatmatrix)