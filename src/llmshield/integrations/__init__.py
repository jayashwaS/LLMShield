"""Integrations with external services."""

from .huggingface import HuggingFaceIntegration
from .ollama import OllamaIntegration

__all__ = [
    'HuggingFaceIntegration',
    'OllamaIntegration',
]