"""Configuration management for LLMShield."""

import json
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional

import yaml
from pydantic import BaseModel, Field


class ScannerConfig(BaseModel):
    """Scanner configuration settings."""
    
    max_file_size: int = Field(default=5 * 1024 * 1024 * 1024, description="Maximum file size in bytes (5GB)")
    timeout: int = Field(default=300, description="Scan timeout in seconds")
    parallel_workers: int = Field(default=4, description="Number of parallel workers")
    cache_enabled: bool = Field(default=True, description="Enable caching")
    cache_dir: str = Field(default="~/.llmshield/cache", description="Cache directory")


class VertexAIConfig(BaseModel):
    """Vertex AI configuration settings."""
    
    project_id: Optional[str] = Field(default=None, description="Google Cloud project ID")
    location: str = Field(default="us-central1", description="Vertex AI location")
    model_name: str = Field(default="gemini-1.5-flash", description="Gemini model name")
    credentials_path: Optional[str] = Field(default=None, description="Path to GCP credentials JSON")
    max_tokens: int = Field(default=2048, description="Maximum tokens for AI response")
    temperature: float = Field(default=0.1, description="Temperature for AI generation")


class HuggingFaceConfig(BaseModel):
    """HuggingFace configuration settings."""
    
    api_token: Optional[str] = Field(default=None, description="HuggingFace API token")
    cache_dir: str = Field(default="~/.llmshield/models/huggingface", description="Model cache directory")
    timeout: int = Field(default=600, description="Download timeout in seconds")


class OllamaConfig(BaseModel):
    """Ollama configuration settings."""
    
    api_url: str = Field(default="http://localhost:11434", description="Ollama API URL")
    timeout: int = Field(default=600, description="Request timeout in seconds")


class ReportConfig(BaseModel):
    """Report configuration settings."""
    
    output_dir: str = Field(default="./reports", description="Report output directory")
    formats: List[str] = Field(default=["json", "html", "text"], description="Report formats")
    include_ai_insights: bool = Field(default=True, description="Include AI-generated insights")
    verbose: bool = Field(default=False, description="Verbose reporting")


class LLMShieldConfig(BaseModel):
    """Main LLMShield configuration."""
    
    scanner: ScannerConfig = Field(default_factory=ScannerConfig)
    vertex_ai: VertexAIConfig = Field(default_factory=VertexAIConfig)
    huggingface: HuggingFaceConfig = Field(default_factory=HuggingFaceConfig)
    ollama: OllamaConfig = Field(default_factory=OllamaConfig)
    report: ReportConfig = Field(default_factory=ReportConfig)
    log_level: str = Field(default="INFO", description="Logging level")
    log_file: Optional[str] = Field(default=None, description="Log file path")


class ConfigManager:
    """Manages LLMShield configuration."""
    
    DEFAULT_CONFIG_PATH = Path.home() / ".llmshield" / "config.yaml"
    
    def __init__(self, config_path: Optional[Path] = None):
        """Initialize configuration manager."""
        self.config_path = config_path or self.DEFAULT_CONFIG_PATH
        self.config = self._load_config()
    
    def _load_config(self) -> LLMShieldConfig:
        """Load configuration from file or create default."""
        if self.config_path.exists():
            try:
                with open(self.config_path, 'r') as f:
                    if self.config_path.suffix == '.yaml' or self.config_path.suffix == '.yml':
                        config_data = yaml.safe_load(f)
                    else:
                        config_data = json.load(f)
                return LLMShieldConfig(**config_data)
            except Exception as e:
                print(f"Warning: Failed to load config from {self.config_path}: {e}")
                print("Using default configuration")
        
        return LLMShieldConfig()
    
    def save_config(self, config: Optional[LLMShieldConfig] = None):
        """Save configuration to file."""
        config = config or self.config
        
        # Create config directory if it doesn't exist
        self.config_path.parent.mkdir(parents=True, exist_ok=True)
        
        with open(self.config_path, 'w') as f:
            if self.config_path.suffix == '.yaml' or self.config_path.suffix == '.yml':
                yaml.dump(config.dict(), f, default_flow_style=False)
            else:
                json.dump(config.dict(), f, indent=2)
    
    def get(self, key: str, default: Any = None) -> Any:
        """Get configuration value by dot-separated key."""
        keys = key.split('.')
        value = self.config.dict()
        
        for k in keys:
            if isinstance(value, dict) and k in value:
                value = value[k]
            else:
                return default
        
        return value
    
    def set(self, key: str, value: Any):
        """Set configuration value by dot-separated key."""
        keys = key.split('.')
        config_dict = self.config.dict()
        
        # Navigate to the parent of the target key
        current = config_dict
        for k in keys[:-1]:
            if k not in current:
                current[k] = {}
            current = current[k]
        
        # Set the value
        current[keys[-1]] = value
        
        # Recreate config object
        self.config = LLMShieldConfig(**config_dict)
    
    def update_from_env(self):
        """Update configuration from environment variables."""
        env_mappings = {
            'LLMSHIELD_LOG_LEVEL': 'log_level',
            'LLMSHIELD_VERTEX_PROJECT_ID': 'vertex_ai.project_id',
            'LLMSHIELD_VERTEX_CREDENTIALS': 'vertex_ai.credentials_path',
            'LLMSHIELD_HF_TOKEN': 'huggingface.api_token',
            'LLMSHIELD_OLLAMA_URL': 'ollama.api_url',
        }
        
        for env_var, config_key in env_mappings.items():
            value = os.environ.get(env_var)
            if value:
                self.set(config_key, value)


# Global configuration instance
config_manager = ConfigManager()