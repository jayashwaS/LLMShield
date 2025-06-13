"""Custom exceptions for LLMShield."""


class LLMShieldError(Exception):
    """Base exception for LLMShield."""
    pass


class ConfigurationError(LLMShieldError):
    """Raised when configuration is invalid or missing."""
    pass


class FileParsingError(LLMShieldError):
    """Raised when file parsing fails."""
    pass


class UnsupportedFormatError(FileParsingError):
    """Raised when file format is not supported."""
    pass


class CorruptedFileError(FileParsingError):
    """Raised when file is corrupted or malformed."""
    pass


class ScannerError(LLMShieldError):
    """Base exception for scanner-related errors."""
    pass


class VulnerabilityDetectionError(ScannerError):
    """Raised when vulnerability detection fails."""
    pass


class PayloadDetectionError(ScannerError):
    """Raised when payload detection fails."""
    pass


class IntegrationError(LLMShieldError):
    """Base exception for integration-related errors."""
    pass


class HuggingFaceError(IntegrationError):
    """Raised when HuggingFace operations fail."""
    pass


class OllamaError(IntegrationError):
    """Raised when Ollama operations fail."""
    pass


class VertexAIError(IntegrationError):
    """Raised when Vertex AI operations fail."""
    pass


class ReportGenerationError(LLMShieldError):
    """Raised when report generation fails."""
    pass


class AuthenticationError(LLMShieldError):
    """Raised when authentication fails."""
    pass


class RateLimitError(LLMShieldError):
    """Raised when rate limit is exceeded."""
    pass


class TimeoutError(LLMShieldError):
    """Raised when operation times out."""
    pass


class ValidationError(LLMShieldError):
    """Raised when validation fails."""
    pass