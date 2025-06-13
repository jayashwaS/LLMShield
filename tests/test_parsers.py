"""Tests for model parsers."""

import json
import pickle
import struct
import tempfile
from pathlib import Path

import pytest

from llmshield.parsers import (
    ParserManager,
    PickleParser,
    PyTorchParser,
    SafetensorsParser,
)
from llmshield.core.exceptions import UnsupportedFormatError


class TestParserManager:
    """Test ParserManager functionality."""
    
    def test_supported_formats(self):
        """Test getting supported formats."""
        manager = ParserManager()
        formats = manager.get_supported_formats()
        
        assert 'pickle' in formats
        assert 'pytorch' in formats
        assert 'tensorflow' in formats
        assert 'onnx' in formats
        assert 'safetensors' in formats
        
        assert '.pkl' in formats['pickle']
        assert '.pt' in formats['pytorch']
        assert '.safetensors' in formats['safetensors']
    
    def test_is_supported(self):
        """Test format support checking."""
        manager = ParserManager()
        
        assert manager.is_supported(Path('model.pkl'))
        assert manager.is_supported(Path('model.pt'))
        assert manager.is_supported(Path('model.pth'))
        assert manager.is_supported(Path('model.safetensors'))
        assert manager.is_supported(Path('model.onnx'))
        assert manager.is_supported(Path('model.h5'))
        assert manager.is_supported(Path('model.pb'))
        
        assert not manager.is_supported(Path('model.txt'))
        assert not manager.is_supported(Path('model.json'))
        assert not manager.is_supported(Path('model.zip'))


class TestPickleParser:
    """Test PickleParser functionality."""
    
    def test_parse_safe_pickle(self):
        """Test parsing a safe pickle file."""
        parser = PickleParser()
        
        # Create a safe pickle file
        with tempfile.NamedTemporaryFile(suffix='.pkl', delete=False) as f:
            data = {'model': 'test', 'weights': [1, 2, 3]}
            pickle.dump(data, f)
            temp_path = Path(f.name)
        
        try:
            result = parser.parse(temp_path)
            
            assert result.metadata.framework == 'pickle'
            assert result.metadata.file_path == temp_path
            assert len(result.warnings) == 0
            assert len(result.suspicious_patterns) == 0
        
        finally:
            temp_path.unlink()
    
    def test_parse_suspicious_pickle(self):
        """Test parsing a suspicious pickle file."""
        parser = PickleParser()
        
        # Create a pickle with dangerous patterns
        with tempfile.NamedTemporaryFile(suffix='.pkl', delete=False) as f:
            # This creates a pickle that would import os.system
            f.write(b'\x80\x04\x95\x1a\x00\x00\x00\x00\x00\x00\x00\x8c\x02os\x94\x8c\x06system\x94\x93\x94.')
            temp_path = Path(f.name)
        
        try:
            result = parser.parse(temp_path)
            
            assert len(result.warnings) > 0
            assert len(result.suspicious_patterns) > 0
            assert any('GLOBAL' in p for p in result.suspicious_patterns)
            assert any('os.system' in str(d) for d in result.external_dependencies)
        
        finally:
            temp_path.unlink()


class TestSafetensorsParser:
    """Test SafetensorsParser functionality."""
    
    def test_parse_valid_safetensors(self):
        """Test parsing a valid safetensors file."""
        parser = SafetensorsParser()
        
        # Create a minimal safetensors file
        with tempfile.NamedTemporaryFile(suffix='.safetensors', delete=False) as f:
            # Create header
            header = {
                '__metadata__': {'format': 'pt'},
                'weight': {
                    'dtype': 'F32',
                    'shape': [2, 3],
                    'data_offsets': [0, 24]
                }
            }
            header_bytes = json.dumps(header).encode('utf-8')
            header_size = len(header_bytes)
            
            # Write header size (8 bytes, little-endian)
            f.write(struct.pack('<Q', header_size))
            # Write header
            f.write(header_bytes)
            # Write dummy tensor data (6 floats * 4 bytes = 24 bytes)
            f.write(b'\x00' * 24)
            
            temp_path = Path(f.name)
        
        try:
            result = parser.parse(temp_path)
            
            assert result.metadata.framework == 'safetensors'
            assert result.metadata.parameters_count == 6  # 2x3 tensor
            assert len(result.warnings) == 0
            assert len(result.suspicious_patterns) == 0
        
        finally:
            temp_path.unlink()
    
    def test_parse_suspicious_safetensors(self):
        """Test parsing a safetensors file with suspicious metadata."""
        parser = SafetensorsParser()
        
        # Create a safetensors file with suspicious metadata
        with tempfile.NamedTemporaryFile(suffix='.safetensors', delete=False) as f:
            header = {
                '__metadata__': {
                    'format': 'pt',
                    'exec_command': 'os.system("echo hacked")',
                    'eval_code': '__import__("os").system("ls")'
                },
                'backdoor_weight': {
                    'dtype': 'F32',
                    'shape': [10],
                    'data_offsets': [0, 40]
                }
            }
            header_bytes = json.dumps(header).encode('utf-8')
            header_size = len(header_bytes)
            
            f.write(struct.pack('<Q', header_size))
            f.write(header_bytes)
            f.write(b'\x00' * 40)
            
            temp_path = Path(f.name)
        
        try:
            result = parser.parse(temp_path)
            
            assert len(result.warnings) > 0
            assert len(result.suspicious_patterns) > 0
            assert any('exec' in p for p in result.suspicious_patterns)
            assert any('backdoor' in p for p in result.suspicious_patterns)
        
        finally:
            temp_path.unlink()


def test_parser_manager_parse_file():
    """Test ParserManager file parsing."""
    manager = ParserManager()
    
    # Create a test pickle file
    with tempfile.NamedTemporaryFile(suffix='.pkl', delete=False) as f:
        pickle.dump({'test': 'data'}, f)
        temp_path = Path(f.name)
    
    try:
        result = manager.parse_file(temp_path)
        
        assert result.metadata.framework == 'pickle'
        assert result.metadata.file_size > 0
        assert result.metadata.file_hash is not None
    
    finally:
        temp_path.unlink()


def test_parser_manager_unsupported_format():
    """Test ParserManager with unsupported format."""
    manager = ParserManager()
    
    with tempfile.NamedTemporaryFile(suffix='.txt', delete=False) as f:
        f.write(b'not a model file')
        temp_path = Path(f.name)
    
    try:
        with pytest.raises(UnsupportedFormatError):
            manager.parse_file(temp_path)
    
    finally:
        temp_path.unlink()