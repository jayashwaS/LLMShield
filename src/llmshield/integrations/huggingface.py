"""HuggingFace Hub integration for model downloading."""

import json
import os
import shutil
from pathlib import Path
from typing import Any, Dict, List, Optional
from urllib.parse import urljoin

import requests
from huggingface_hub import hf_hub_download, list_repo_files, HfApi

from llmshield.core.config import config_manager
from llmshield.core.logger import get_logger
from llmshield.core.exceptions import IntegrationError, HuggingFaceError

logger = get_logger()


class HuggingFaceIntegration:
    """Integration with HuggingFace Hub for model operations."""
    
    BASE_URL = "https://huggingface.co"
    API_URL = "https://api.huggingface.co"
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """Initialize HuggingFace integration."""
        self.config = config or config_manager.config.huggingface.dict()
        self.api_token = self.config.get('api_token') or os.environ.get('HF_TOKEN')
        self.cache_dir = Path(self.config.get('cache_dir', '~/.llmshield/models/huggingface')).expanduser()
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        
        # Initialize HF API
        self.api = HfApi(token=self.api_token)
        
    def _get_headers(self) -> Dict[str, str]:
        """Get headers for API requests."""
        headers = {"User-Agent": "LLMShield/0.1.0"}
        if self.api_token:
            headers["Authorization"] = f"Bearer {self.api_token}"
        return headers
    
    def search_models(self, query: str, limit: int = 10) -> List[Dict[str, Any]]:
        """Search for models on HuggingFace Hub."""
        try:
            from huggingface_hub import list_models
            
            models = list(list_models(
                search=query,
                limit=limit,
                full=True
            ))
            
            return [
                {
                    'id': model.id,
                    'author': model.author,
                    'downloads': model.downloads,
                    'likes': model.likes,
                    'tags': model.tags,
                    'created_at': str(model.created_at) if model.created_at else None,
                }
                for model in models
            ]
        
        except Exception as e:
            logger.error(f"Error searching models: {e}")
            raise HuggingFaceError(f"Failed to search models: {e}")
    
    def list_model_files(self, model_id: str) -> List[str]:
        """List all files in a model repository."""
        try:
            files = list_repo_files(model_id, token=self.api_token)
            return files
        
        except Exception as e:
            logger.error(f"Error listing model files: {e}")
            raise HuggingFaceError(f"Failed to list files for {model_id}: {e}")
    
    def pull_model(self, model_id: str, output_dir: Optional[Path] = None) -> Path:
        """Pull a model from HuggingFace Hub."""
        logger.info(f"Pulling model: {model_id}")
        
        output_dir = output_dir or self.cache_dir / model_id.replace('/', '_')
        output_dir.mkdir(parents=True, exist_ok=True)
        
        try:
            # List all files in the repository
            files = self.list_model_files(model_id)
            logger.info(f"Found {len(files)} files in {model_id}")
            
            # Filter for model files
            model_extensions = {'.pt', '.pth', '.bin', '.safetensors', '.h5', '.pb', '.onnx'}
            model_files = [f for f in files if Path(f).suffix.lower() in model_extensions]
            
            if not model_files:
                logger.warning(f"No model files found in {model_id}")
                # Try to download common file names
                model_files = ['pytorch_model.bin', 'model.safetensors', 'tf_model.h5']
            
            downloaded_files = []
            
            # Download each model file
            for file_name in model_files:
                try:
                    logger.progress(f"Downloading {file_name}...")
                    
                    local_path = hf_hub_download(
                        repo_id=model_id,
                        filename=file_name,
                        cache_dir=str(self.cache_dir),
                        token=self.api_token,
                        local_dir=str(output_dir),
                        local_dir_use_symlinks=False
                    )
                    
                    downloaded_files.append(Path(local_path))
                    logger.success(f"Downloaded: {file_name}")
                    
                except Exception as e:
                    logger.debug(f"Could not download {file_name}: {e}")
                    continue
            
            # Also download config files
            config_files = ['config.json', 'model_card.md', 'README.md']
            for config_file in config_files:
                if config_file in files:
                    try:
                        hf_hub_download(
                            repo_id=model_id,
                            filename=config_file,
                            cache_dir=str(self.cache_dir),
                            token=self.api_token,
                            local_dir=str(output_dir),
                            local_dir_use_symlinks=False
                        )
                    except Exception:
                        pass
            
            if not downloaded_files:
                raise HuggingFaceError(f"No model files could be downloaded from {model_id}")
            
            logger.success(f"Successfully downloaded {len(downloaded_files)} model files to {output_dir}")
            return output_dir
        
        except Exception as e:
            logger.error(f"Error pulling model {model_id}: {e}")
            raise HuggingFaceError(f"Failed to pull model {model_id}: {e}")
    
    def get_model_info(self, model_id: str) -> Dict[str, Any]:
        """Get detailed information about a model."""
        try:
            from huggingface_hub import model_info
            
            info = model_info(model_id, token=self.api_token)
            
            return {
                'id': info.id,
                'author': info.author,
                'sha': info.sha,
                'created_at': str(info.created_at) if info.created_at else None,
                'last_modified': str(info.last_modified) if info.last_modified else None,
                'private': info.private,
                'downloads': info.downloads,
                'likes': info.likes,
                'tags': info.tags,
                'pipeline_tag': info.pipeline_tag,
                'library_name': info.library_name,
                'model_card': info.card_data.to_dict() if hasattr(info.card_data, 'to_dict') else None,
            }
        
        except Exception as e:
            logger.error(f"Error getting model info: {e}")
            raise HuggingFaceError(f"Failed to get info for {model_id}: {e}")
    
    def verify_model_safety(self, model_id: str) -> Dict[str, Any]:
        """Perform preliminary safety checks on a model before downloading."""
        safety_report = {
            'model_id': model_id,
            'checks_passed': True,
            'warnings': [],
            'info': {}
        }
        
        try:
            # Get model info
            info = self.get_model_info(model_id)
            safety_report['info'] = info
            
            # Check for suspicious patterns in model ID
            suspicious_patterns = ['eicar', 'malware', 'virus', 'backdoor', 'exploit']
            for pattern in suspicious_patterns:
                if pattern in model_id.lower():
                    safety_report['warnings'].append(f"Model ID contains suspicious pattern: {pattern}")
                    safety_report['checks_passed'] = False
            
            # Check model tags
            if info.get('tags'):
                for tag in info['tags']:
                    if any(pattern in tag.lower() for pattern in suspicious_patterns):
                        safety_report['warnings'].append(f"Suspicious tag found: {tag}")
                        safety_report['checks_passed'] = False
            
        except Exception as e:
            safety_report['warnings'].append(f"Could not verify model: {e}")
            safety_report['checks_passed'] = False
        
        return safety_report