"""Ollama integration for model downloading and management."""

import json
import os
import shutil
import subprocess
import tarfile
from pathlib import Path
from typing import Any, Dict, List, Optional

import requests

from llmshield.core.config import config_manager
from llmshield.core.logger import get_logger
from llmshield.core.exceptions import IntegrationError, OllamaError

logger = get_logger()


class OllamaIntegration:
    """Integration with Ollama for model operations."""
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """Initialize Ollama integration."""
        self.config = config or config_manager.config.ollama.dict()
        self.api_url = self.config.get('api_url', 'http://localhost:11434')
        self.timeout = self.config.get('timeout', 600)
        self.cache_dir = Path('~/.llmshield/models/ollama').expanduser()
        self.cache_dir.mkdir(parents=True, exist_ok=True)
    
    def _make_request(self, endpoint: str, method: str = 'GET', 
                     json_data: Optional[Dict] = None) -> Dict[str, Any]:
        """Make HTTP request to Ollama API."""
        url = f"{self.api_url}{endpoint}"
        
        try:
            if method == 'GET':
                response = requests.get(url, timeout=self.timeout)
            elif method == 'POST':
                response = requests.post(url, json=json_data, timeout=self.timeout)
            else:
                raise ValueError(f"Unsupported method: {method}")
            
            response.raise_for_status()
            return response.json() if response.content else {}
        
        except requests.exceptions.ConnectionError:
            raise OllamaError("Cannot connect to Ollama. Is Ollama running?")
        except requests.exceptions.Timeout:
            raise OllamaError(f"Request timed out after {self.timeout} seconds")
        except requests.exceptions.RequestException as e:
            raise OllamaError(f"Request failed: {e}")
    
    def check_connection(self) -> bool:
        """Check if Ollama is running and accessible."""
        try:
            self._make_request('/api/tags')
            return True
        except OllamaError:
            return False
    
    def list_models(self) -> List[Dict[str, Any]]:
        """List all models available in Ollama."""
        try:
            response = self._make_request('/api/tags')
            models = response.get('models', [])
            
            return [
                {
                    'name': model.get('name'),
                    'size': model.get('size'),
                    'digest': model.get('digest'),
                    'modified_at': model.get('modified_at'),
                }
                for model in models
            ]
        
        except Exception as e:
            logger.error(f"Error listing models: {e}")
            raise OllamaError(f"Failed to list models: {e}")
    
    def pull_model(self, model_name: str, output_dir: Optional[Path] = None) -> Path:
        """Pull a model using Ollama and extract it."""
        logger.info(f"Pulling model from Ollama: {model_name}")
        
        output_dir = output_dir or self.cache_dir / model_name.replace(':', '_')
        output_dir.mkdir(parents=True, exist_ok=True)
        
        try:
            # First, ensure the model is pulled in Ollama
            logger.progress(f"Pulling {model_name} with Ollama...")
            subprocess.run(
                ['ollama', 'pull', model_name],
                check=True,
                capture_output=True,
                text=True
            )
            
            # Get model info
            model_info = self.get_model_info(model_name)
            
            # Find Ollama's model storage location
            ollama_models_dir = Path.home() / '.ollama' / 'models'
            
            # Export the model layers
            if ollama_models_dir.exists():
                # Look for blob storage
                blobs_dir = ollama_models_dir / 'blobs'
                manifests_dir = ollama_models_dir / 'manifests'
                
                if blobs_dir.exists():
                    # Copy relevant blobs
                    copied_files = []
                    
                    # Find manifest
                    manifest_path = None
                    if manifests_dir.exists():
                        # Look for manifest file
                        for registry_dir in manifests_dir.iterdir():
                            if registry_dir.is_dir():
                                for namespace_dir in registry_dir.iterdir():
                                    if namespace_dir.is_dir():
                                        model_manifest = namespace_dir / model_name.replace(':', '/')
                                        if model_manifest.exists():
                                            manifest_path = model_manifest
                                            break
                    
                    if manifest_path and manifest_path.exists():
                        # Read manifest to find layers
                        with open(manifest_path, 'r') as f:
                            manifest = json.load(f)
                        
                        # Copy layers
                        for layer in manifest.get('layers', []):
                            digest = layer.get('digest', '').replace(':', '-')
                            if digest:
                                blob_path = blobs_dir / digest
                                if blob_path.exists():
                                    dest_path = output_dir / f"{digest}.blob"
                                    shutil.copy2(blob_path, dest_path)
                                    copied_files.append(dest_path)
                                    logger.debug(f"Copied blob: {digest}")
                    
                    # Also save model info
                    info_path = output_dir / 'model_info.json'
                    with open(info_path, 'w') as f:
                        json.dump(model_info, f, indent=2)
                    copied_files.append(info_path)
                    
                    if copied_files:
                        logger.success(f"Extracted {len(copied_files)} files to {output_dir}")
                        return output_dir
                    else:
                        logger.warning("No model files could be extracted from Ollama storage")
            
            # Fallback: Create a reference file
            reference_file = output_dir / 'ollama_model.json'
            with open(reference_file, 'w') as f:
                json.dump({
                    'model_name': model_name,
                    'model_info': model_info,
                    'note': 'Model stored in Ollama, reference file only'
                }, f, indent=2)
            
            logger.warning(f"Created reference file. Model data remains in Ollama: {reference_file}")
            return output_dir
        
        except subprocess.CalledProcessError as e:
            logger.error(f"Ollama command failed: {e.stderr}")
            raise OllamaError(f"Failed to pull model {model_name}: {e.stderr}")
        except Exception as e:
            logger.error(f"Error pulling model {model_name}: {e}")
            raise OllamaError(f"Failed to pull model {model_name}: {e}")
    
    def get_model_info(self, model_name: str) -> Dict[str, Any]:
        """Get information about a specific model."""
        try:
            # Use ollama show command
            result = subprocess.run(
                ['ollama', 'show', model_name, '--json'],
                check=True,
                capture_output=True,
                text=True
            )
            
            return json.loads(result.stdout)
        
        except subprocess.CalledProcessError as e:
            logger.error(f"Failed to get model info: {e.stderr}")
            raise OllamaError(f"Failed to get info for {model_name}: {e.stderr}")
        except json.JSONDecodeError as e:
            logger.error(f"Failed to parse model info: {e}")
            raise OllamaError(f"Invalid model info format: {e}")
        except Exception as e:
            logger.error(f"Error getting model info: {e}")
            raise OllamaError(f"Failed to get info for {model_name}: {e}")
    
    def delete_model(self, model_name: str):
        """Delete a model from Ollama."""
        try:
            subprocess.run(
                ['ollama', 'rm', model_name],
                check=True,
                capture_output=True,
                text=True
            )
            logger.success(f"Deleted model: {model_name}")
        
        except subprocess.CalledProcessError as e:
            logger.error(f"Failed to delete model: {e.stderr}")
            raise OllamaError(f"Failed to delete {model_name}: {e.stderr}")